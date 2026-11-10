package client_test

import (
	"bytes"
	"compress/flate"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/seal"
)

// E2E-5 (§E.3.1, §7.1): a prune at the resource's current horizon, a
// tombstone that is no longer the head (a retention applied again after a
// restore), finds the tombstone's parent in the not_offered of a live
// revision above it, since the log no longer lists the horizon and the
// tombstone's own /rev is a 410: the snapshot is the parent's document,
// bound to it, the horizon staying the tombstone. A not_offered naming a
// last the tombstone isn't on is seal.ErrMismatch, and nothing is sent.
func TestV081PruneAtCurrentTombstoneHorizon(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	st := newE3Stub(t)
	g := st.rev(st.kr, "", []any{map[string]any{"op": "add", "path": "", "value": map[string]any{"n": 1.0}}})
	p := st.rev(st.kr, g["id"].(string), []any{map[string]any{"op": "replace", "path": "/n", "value": 2.0}})
	P := p["id"].(string)
	T := st.tombstone(P)["id"].(string)
	r := st.rev(st.kr, T, []any{map[string]any{"op": "replace", "path": "/n", "value": 3.0}})
	R := r["id"].(string)
	st.routes["/r/e/d"] = func(w http.ResponseWriter) {
		w.Header().Set("ETag", `"`+R+`"`)
		w.WriteHeader(302)
	}
	pruned := st.json(410, map[string]any{"error": "pruned", "code": "pruned", "horizon": T})
	st.routes["/r/e/d/rev/"+T] = st.json(410, map[string]any{"error": "gone", "code": "gone"})
	st.routes["/r/e/d/rev/"+T+"/log"] = pruned
	st.routes["/r/e/d/rev/"+T+"/log?since="+T] = st.json(200, []any{})
	st.routes["/r/e/d/rev/"+R] = st.notOffered(T, P)
	st.routes["/r/e/d/rev/"+R+"/log"] = pruned
	st.routes["/r/e/d/rev/"+R+"/log?since="+T] = st.json(200, []any{r})
	st.routes["/r/e/d/rev/"+P] = st.jose(st.snapshot(P, map[string]any{"n": 2.0}))
	x := st.view()
	if _, err := x.PruneE2E(ctx, "e", "d", T); err != nil {
		t.Fatal(err)
	}
	hd := must(seal.ParseHeader(st.pruned["snapshot"].(string)))
	if hd.PL["id"] != P || st.pruned["horizon"] != T || hd.Kid != "e#1" {
		t.Fatalf("prune at the current tombstone horizon: %s %v", hd.Raw, st.pruned["horizon"])
	}
	sameJSON(t, must(seal.OpenSnapshot(st.pruned["snapshot"].(string), st.kr, "e#1", "e", "d", P)), map[string]any{"n": 2.0})

	// A last the tombstone isn't on.
	st.pruned = nil
	st.routes["/r/e/d/rev/"+R] = st.notOffered(T, g["id"].(string))
	if _, err := x.PruneE2E(ctx, "e", "d", T); !errors.Is(err, seal.ErrMismatch) || st.pruned != nil {
		t.Fatalf("a not_offered naming another parent: %v, sent %v", err, st.pruned)
	}
}

// E2E-5 (§E.3.1): at a head tombstone's horizon the head's last is the
// tombstone's parent only where the tombstone's id is the one on it
// (ExpectedTombstone), as for a tombstone found in the log: a server
// naming another revision Q as last is seal.ErrMismatch, and no snapshot
// of Q's document is sealed under the horizon.
func TestV081PruneHeadTombstoneLastChecked(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	st := newE3Stub(t)
	g := st.rev(st.kr, "", []any{map[string]any{"op": "add", "path": "", "value": map[string]any{"n": 1.0}}})
	p := st.rev(st.kr, g["id"].(string), []any{map[string]any{"op": "replace", "path": "/n", "value": 2.0}})
	q := st.rev(st.kr, g["id"].(string), []any{map[string]any{"op": "replace", "path": "/n", "value": 9.0}})
	P, Q := p["id"].(string), q["id"].(string)
	T := st.tombstone(P)["id"].(string)
	st.routes["/r/e/d"] = st.json(410, map[string]any{"error": "gone", "code": "gone", "tombstone": T, "last": Q})
	st.routes["/r/e/d/rev/"+Q] = st.notOffered("", "")
	st.routes["/r/e/d/rev/"+Q+"/log"] = st.json(200, []any{g, q})
	if _, err := st.view().PruneE2E(ctx, "e", "d", T); !errors.Is(err, seal.ErrMismatch) || st.pruned != nil {
		t.Fatalf("a head last the tombstone isn't on: %v, sent %v", err, st.pruned)
	}
}

// KEYS-11 (§E.2.1 Message bound): a view's first sealing under a K_r
// counts the log first, so a fresh view, as every CLI run is, refuses
// past a bound the log already shows reached, without SealStatus being
// called.
func TestV081FreshViewCountsTheLog(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{KeyStore: keyStore(t)})
	c := s.Client(t, client.WithAuthor("alice"))
	_, priv, _ := seal.GenerateRecipient()
	must(c.CreateNamespace(ctx, "e", map[string]any{"encryption": map[string]any{"level": "e2e"}}))
	must(c.E2E(priv).InitKeyring(ctx, "e"))
	x := c.E2E(priv).WithoutValidation().WithSealBound(2, 1)
	head := must(x.CreateSealed(ctx, "e", "d", client.GenesisPatches(map[string]any{"n": 0}))).ID
	head = must(x.AppendSealed(ctx, "e", "d", head, ops(op("replace", "/n", 1)))).ID
	y := c.E2E(priv).WithoutValidation().WithSealBound(2, 1)
	if _, err := y.SealPatches(ctx, "e", "d", head, ops(op("replace", "/n", 2))); !errors.Is(err, client.ErrSealBound) {
		t.Fatalf("a fresh view sealed a third value under a K_r whose log shows the bound of 2 reached: %v", err)
	}
	// Below the bound, a fresh view seals.
	z := c.E2E(priv).WithoutValidation().WithSealBound(3, 1)
	must(z.SealPatches(ctx, "e", "d", head, ops(op("replace", "/n", 2))))
}

// KEYS-11: a fresh view's prune snapshot is counted against the log too:
// with two sealed ops logged and a bound of 2, it is refused, and nothing
// is sent.
func TestV081FreshViewPruneCountsTheLog(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	st := newE3Stub(t)
	g := st.rev(st.kr, "", []any{map[string]any{"op": "add", "path": "", "value": map[string]any{"n": 1.0}}})
	p := st.rev(st.kr, g["id"].(string), []any{map[string]any{"op": "replace", "path": "/n", "value": 2.0}})
	P := p["id"].(string)
	tomb := st.tombstone(P)
	T := tomb["id"].(string)
	st.routes["/r/e/d"] = st.json(410, map[string]any{"error": "gone", "code": "gone", "tombstone": T, "last": P})
	st.routes["/r/e/d/rev/"+P] = st.notOffered("", "")
	st.routes["/r/e/d/rev/"+P+"/log"] = st.json(200, []any{g, p})
	st.routes["/r/e/d/rev/"+T+"/log"] = st.json(200, []any{g, p, tomb})
	if _, err := st.view().WithSealBound(2, 1).PruneE2E(ctx, "e", "d", T); !errors.Is(err, client.ErrSealBound) || st.pruned != nil {
		t.Fatalf("a fresh view's prune snapshot past the bound: %v, sent %v", err, st.pruned)
	}
	if _, err := st.view().WithSealBound(3, 1).PruneE2E(ctx, "e", "d", T); err != nil {
		t.Fatal(err)
	}
}

// KEYS-11: a log a view can't read for another reason than the grant
// (§C.5) fails the first sealing rather than seal uncounted.
func TestV081SealFailsClosedOnUnreadableLog(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	st := newE3Stub(t)
	H := ids.Revision(nil, []byte("h")).String()
	st.routes["/r/e/d"] = func(w http.ResponseWriter) {
		w.Header().Set("ETag", `"`+H+`"`)
		w.WriteHeader(302)
	}
	st.routes["/r/e/d/rev/"+H+"/log"] = st.json(500, map[string]any{"error": "broken", "code": "internal"})
	if _, err := st.view().SealPatches(ctx, "e", "d", H, ops(op("add", "/a", 1))); err == nil {
		t.Fatal("sealed though the log couldn't be counted")
	}
}

// zipJWE seals plaintext as JWEs were before v0.65: raw DEFLATE under a
// protected header with zip "DEF" (RFC 7516 §5.1).
func zipJWE(t *testing.T, key []byte, kid string, pl seal.PL, plaintext []byte) string {
	t.Helper()
	var z bytes.Buffer
	w, _ := flate.NewWriter(&z, flate.BestCompression)
	w.Write(plaintext)
	w.Close()
	b64 := base64.RawURLEncoding
	protected := b64.EncodeToString(jsonv.Canonical(map[string]any{"alg": seal.AlgDir, "enc": seal.EncA256GCM, "kid": kid, "pl": map[string]any(pl), "zip": seal.ZipDeflate}))
	block := must(aes.NewCipher(key))
	gcm := must(cipher.NewGCM(block))
	iv := make([]byte, gcm.NonceSize())
	rand.Read(iv)
	out := gcm.Seal(nil, iv, z.Bytes(), []byte(protected))
	ct, tag := out[:len(out)-gcm.Overhead()], out[len(out)-gcm.Overhead():]
	return protected + ".." + b64.EncodeToString(iv) + "." + b64.EncodeToString(ct) + "." + b64.EncodeToString(tag)
}

// E2E-10 (§E.2.2: sealed payloads are never compressed): a patch set
// sealed with zip "DEF", as before v0.65, is flagged and folded as []
// whatever key its kid names, one the reader doesn't hold included, and
// never opened; a zip snapshot is seal.ErrMismatch. Neither asks /keys.
func TestV081ZipSealingsDontOpen(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	st := newE3Stub(t)
	g := st.rev(st.kr, "", []any{map[string]any{"op": "add", "path": "", "value": map[string]any{"n": 1.0}}})
	gid := g["id"].(string)
	ps := jsonv.FromGo([]any{map[string]any{"op": "sealed", "value": zipJWE(t, st.kr, "e#2", seal.PatchSetPL("e", "d", gid), []byte(`[{"op":"replace","path":"/n","value":2}]`))}})
	old := map[string]any{"id": must(client.ExpectedRevision(gid, ps)), "parent": gid, "kind": "rev", "patches": ps, "author": "user:w", "created": "2026-10-04T12:00:00.000Z"}
	head := old["id"].(string)
	st.routes["/r/e/d/rev/"+head] = st.notOffered("", "")
	st.routes["/r/e/d/rev/"+head+"/log"] = st.json(200, []any{g, old})
	x := st.view()
	d, err := x.DocE2E(ctx, "e", "d", head)
	if err != nil {
		t.Fatal(err)
	}
	sameJSON(t, d.Value, map[string]any{"n": 1.0})
	if len(d.Flagged) != 1 || d.Flagged[0].ID != head || d.ValidID != gid {
		t.Fatalf("a zip patch set: %+v", d)
	}
	st.routes["/r/e/d/rev/"+gid] = st.jose(zipJWE(t, st.kr, "e#1", seal.SnapshotPL("e", "d", gid), []byte(`{"n":1}`)))
	if _, err := x.DocE2E(ctx, "e", "d", gid); !errors.Is(err, seal.ErrMismatch) {
		t.Fatalf("a zip snapshot: %v", err)
	}
	if st.wasAsked("/ns/e/keys") {
		t.Fatal("asked /keys for a zip sealing")
	}
}
