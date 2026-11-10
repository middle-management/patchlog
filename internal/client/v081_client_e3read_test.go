package client_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/seal"
)

// e3Stub is an E3 server stub for namespace e, at epoch 1, as v0.81 serves
// /rev/{id} (§7.1): routes maps a request path, with "?since=…" for log
// ranges, to its answer. It records the paths asked and the last prune
// body.
type e3Stub struct {
	t      *testing.T
	ke, kr []byte
	mu     sync.Mutex
	routes map[string]func(w http.ResponseWriter)
	asked  []string
	pruned map[string]any
}

func newE3Stub(t *testing.T) *e3Stub {
	st := &e3Stub{t: t, ke: seal.NewKey(), routes: map[string]func(http.ResponseWriter){}}
	st.kr = must(seal.ResourceKey(st.ke, "e", "d"))
	nsID := ids.Revision(nil, []byte("ns")).String()
	st.routes["/ns/e"] = func(w http.ResponseWriter) {
		w.Header().Set("ETag", `"`+nsID+`"`)
		w.Header().Set("X-Config-Revision", nsID)
		w.WriteHeader(302)
	}
	st.routes["/ns/e/rev/"+nsID] = st.json(200, map[string]any{"encryption": map[string]any{"level": "e2e", "epoch": 1}})
	return st
}

func (st *e3Stub) json(status int, v any) func(http.ResponseWriter) {
	return func(w http.ResponseWriter) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		json.NewEncoder(w).Encode(v)
	}
}

func (st *e3Stub) jose(jwe string) func(http.ResponseWriter) {
	return func(w http.ResponseWriter) {
		w.Header().Set("Content-Type", seal.ContentType)
		io.WriteString(w, jwe)
	}
}

// notOffered is the v0.81 answer for a /rev/{id} the reader folds.
func (st *e3Stub) notOffered(horizon, last string) func(http.ResponseWriter) {
	b := map[string]any{"error": "the reader folds", "code": "not_offered"}
	if horizon != "" {
		b["horizon"] = horizon
	}
	if last != "" {
		b["last"] = last
	}
	return st.json(404, b)
}

// snapshot seals doc as the snapshot of id.
func (st *e3Stub) snapshot(id string, doc any) string {
	return must(seal.SealSnapshotPad(st.kr, "e#1", "e", "d", id, jsonv.FromGo(doc), true))
}

// rev is a log entry on parent whose patch set is patches sealed under key.
func (st *e3Stub) rev(key []byte, parent string, patches []any) map[string]any {
	ps := jsonv.MustParse(must(seal.SealPatchSetPad(key, "e#1", "e", "d", parent, jsonv.FromGo(patches), true)))
	id := must(client.ExpectedRevision(parent, ps))
	return map[string]any{"id": id, "parent": parent, "kind": "rev", "patches": ps, "author": "user:w", "created": "2026-10-04T12:00:00.000Z"}
}

func (st *e3Stub) tombstone(parent string) map[string]any {
	return map[string]any{"id": must(client.ExpectedTombstone(parent)), "parent": parent, "kind": "tombstone", "author": "user:w", "created": "2026-10-04T12:00:00.000Z"}
}

func (st *e3Stub) server() *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.URL.Path
		if s := r.URL.Query().Get("since"); s != "" {
			key += "?since=" + s
		}
		st.mu.Lock()
		st.asked = append(st.asked, r.Method+" "+key)
		h := st.routes[key]
		if r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/prune") {
			json.NewDecoder(r.Body).Decode(&st.pruned)
			h = st.json(200, map[string]any{"horizon": st.pruned["horizon"]})
		}
		st.mu.Unlock()
		if h == nil {
			st.json(404, map[string]any{"error": "not found", "code": "not_found"})(w)
			return
		}
		h(w)
	}))
	st.t.Cleanup(srv.Close)
	return srv
}

func (st *e3Stub) view() *client.E2E {
	c, err := client.New(st.server().URL)
	if err != nil {
		st.t.Fatal(err)
	}
	return c.E2EKeys(map[string][]byte{"e#1": st.ke})
}

func (st *e3Stub) wasAsked(path string) bool {
	st.mu.Lock()
	defer st.mu.Unlock()
	for _, a := range st.asked {
		if a == "GET "+path {
			return true
		}
	}
	return false
}

// E2E-9 = BYTES-6 (§7.1 End-to-end namespaces: "Readers fold the log up to
// id from the revision that last, or else horizon, names, or from genesis
// where neither is given"): a 404 not_offered naming the horizon H makes
// DocE2E fold from /rev/{H}'s snapshot over /rev/{id}/log?since=H; one
// naming no horizon folds from genesis, without since; a stored snapshot,
// 200 application/jose, is the document of id.
func TestV081DocE2EFoldsFromNotOffered(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	st := newE3Stub(t)
	g := st.rev(st.kr, "", []any{map[string]any{"op": "add", "path": "", "value": map[string]any{"n": 1.0, "title": "Derby"}}})
	h := st.rev(st.kr, g["id"].(string), []any{map[string]any{"op": "replace", "path": "/n", "value": 2.0}})
	H := h["id"].(string)
	a := st.rev(st.kr, H, []any{map[string]any{"op": "replace", "path": "/n", "value": 3.0}})
	b := st.rev(st.kr, a["id"].(string), []any{map[string]any{"op": "add", "path": "/x", "value": true}})
	head := b["id"].(string)
	st.routes["/r/e/d/rev/"+H] = st.jose(st.snapshot(H, map[string]any{"n": 2.0, "title": "Derby"}))
	st.routes["/r/e/d/rev/"+head] = st.notOffered(H, "")
	st.routes["/r/e/d/rev/"+head+"/log?since="+H] = st.json(200, []any{a, b})
	x := st.view()

	d, err := x.DocE2E(ctx, "e", "d", head)
	if err != nil {
		t.Fatal(err)
	}
	sameJSON(t, d.Value, map[string]any{"n": 3.0, "title": "Derby", "x": true})
	if len(d.Flagged) != 0 || d.ValidID != head || d.Plain || d.Kid() != "e#1" {
		t.Fatalf("fold from the horizon: %+v", d)
	}
	if st.wasAsked("/r/e/d/rev/" + head + "/log") {
		t.Fatal("folded from genesis though the horizon was named")
	}
	// The horizon itself: its stored snapshot is the document.
	d = must(x.DocE2E(ctx, "e", "d", H))
	sameJSON(t, d.Value, map[string]any{"n": 2.0, "title": "Derby"})

	// No horizon: from genesis, the range asked without since.
	st.routes["/r/e/d/rev/"+H] = st.notOffered("", "")
	st.routes["/r/e/d/rev/"+H+"/log"] = st.json(200, []any{g, h})
	d = must(x.DocE2E(ctx, "e", "d", H))
	sameJSON(t, d.Value, map[string]any{"n": 2.0, "title": "Derby"})
}

// E2E-9, E2E-5 (§7.1, §E.3.1: "A snapshot at a tombstone horizon is the
// last live document's, served at the tombstone's parent"): with
// {horizon: T, last: P} the reader starts from /rev/{P}, never asking the
// tombstone's URL for a snapshot, and folds the tombstone and the restore
// after it.
func TestV081DocE2EFoldsFromLast(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	st := newE3Stub(t)
	P := ids.Revision(nil, []byte("p")).String()
	T := st.tombstone(P)
	r := st.rev(st.kr, T["id"].(string), []any{map[string]any{"op": "add", "path": "/back", "value": true}})
	head := r["id"].(string)
	st.routes["/r/e/d/rev/"+P] = st.jose(st.snapshot(P, map[string]any{"n": 7.0}))
	st.routes["/r/e/d/rev/"+head] = st.notOffered(T["id"].(string), P)
	st.routes["/r/e/d/rev/"+head+"/log?since="+P] = st.json(200, []any{T, r})
	d, err := st.view().DocE2E(ctx, "e", "d", head)
	if err != nil {
		t.Fatal(err)
	}
	sameJSON(t, d.Value, map[string]any{"n": 7.0, "back": true})
	if st.wasAsked("/r/e/d/rev/"+T["id"].(string)) || st.wasAsked("/r/e/d/rev/"+head+"/log?since="+T["id"].(string)) {
		t.Fatal("started from the tombstone, not its parent")
	}
}

// E2E-9: the server never folds and never serves an e2e document in the
// clear, so any other 200 for a resource of an e2e namespace is refused
// (seal.ErrMismatch), as is a fold start that isn't a sealed snapshot. A
// plain 404 is an error, never a fold from genesis, and a not_offered
// naming something that isn't an id builds no URL.
func TestV081DocE2ERefusesOther200(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	st := newE3Stub(t)
	id := ids.Revision(nil, []byte("x")).String()
	H := ids.Revision(nil, []byte("h")).String()
	x := st.view()
	st.routes["/r/e/d/rev/"+id] = st.json(200, map[string]any{"title": "forged"})
	if d, err := x.DocE2E(ctx, "e", "d", id); !errors.Is(err, seal.ErrMismatch) {
		t.Fatalf("a 200 application/json document: %+v %v", d, err)
	}
	// A snapshot bound to another revision.
	st.routes["/r/e/d/rev/"+id] = st.jose(st.snapshot(H, map[string]any{"title": "other"}))
	if _, err := x.DocE2E(ctx, "e", "d", id); !errors.Is(err, seal.ErrMismatch) {
		t.Fatalf("a snapshot of another revision: %v", err)
	}
	// The fold start isn't a snapshot.
	a := st.rev(st.kr, H, []any{map[string]any{"op": "add", "path": "/a", "value": 1.0}})
	aid := a["id"].(string)
	st.routes["/r/e/d/rev/"+aid] = st.notOffered(H, "")
	st.routes["/r/e/d/rev/"+H] = st.json(200, map[string]any{"title": "forged"})
	st.routes["/r/e/d/rev/"+aid+"/log?since="+H] = st.json(200, []any{a})
	if _, err := x.DocE2E(ctx, "e", "d", aid); !errors.Is(err, seal.ErrMismatch) {
		t.Fatalf("a fold start served in the clear: %v", err)
	}
	// A plain 404.
	st.routes["/r/e/d/rev/"+id] = st.json(404, map[string]any{"error": "not found", "code": "not_found"})
	if _, err := x.DocE2E(ctx, "e", "d", id); !client.IsNotFound(err) || st.wasAsked("/r/e/d/rev/"+id+"/log") {
		t.Fatalf("a plain 404: %v", err)
	}
	// Not an id.
	st.routes["/r/e/d/rev/"+id] = st.notOffered("../../x", "")
	if _, err := x.DocE2E(ctx, "e", "d", id); err == nil || errors.Is(err, seal.ErrMismatch) {
		t.Fatalf("a not_offered naming no id: %v", err)
	}
	// A log entry served sealed, as before a raise, isn't folded.
	st.routes["/r/e/d/rev/"+id] = st.notOffered("", "")
	st.routes["/r/e/d/rev/"+id+"/log"] = st.json(200, []any{st.snapshot(id, map[string]any{})})
	if _, err := x.DocE2E(ctx, "e", "d", id); !errors.Is(err, seal.ErrMismatch) {
		t.Fatalf("a sealed log entry: %v", err)
	}
}

// E2E-10 (§E.2.1: K_e seals nothing; §E.3.2): a patch set sealed under K_e
// itself, as before v0.65, doesn't open: the fold flags it and folds it as
// [], going on from its parent's document.
func TestV081KeSealedPatchSetFlagged(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	st := newE3Stub(t)
	g := st.rev(st.kr, "", []any{map[string]any{"op": "add", "path": "", "value": map[string]any{"n": 1.0}}})
	old := st.rev(st.ke, g["id"].(string), []any{map[string]any{"op": "replace", "path": "/n", "value": 2.0}})
	head := old["id"].(string)
	st.routes["/r/e/d/rev/"+head] = st.notOffered("", "")
	st.routes["/r/e/d/rev/"+head+"/log"] = st.json(200, []any{g, old})
	d, err := st.view().DocE2E(ctx, "e", "d", head)
	if err != nil {
		t.Fatal(err)
	}
	sameJSON(t, d.Value, map[string]any{"n": 1.0})
	if len(d.Flagged) != 1 || d.Flagged[0].ID != head || d.ValidID != g["id"] {
		t.Fatalf("a K_e patch set: %+v", d)
	}
}

// E2E-5 (§E.3.1: a snapshot's pl names "that revision, or the tombstone's
// parent where it is a tombstone"): PruneE2E at a head tombstone's horizon
// folds the last live document and sends a snapshot bound to the
// tombstone's parent, h.Last, under this namespace's kid, the horizon
// staying the tombstone.
func TestV081PruneE2ETombstoneSnapshotBindsParent(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	st := newE3Stub(t)
	g := st.rev(st.kr, "", []any{map[string]any{"op": "add", "path": "", "value": map[string]any{"n": 1.0}}})
	p := st.rev(st.kr, g["id"].(string), []any{map[string]any{"op": "replace", "path": "/n", "value": 2.0}})
	P := p["id"].(string)
	T := st.tombstone(P)["id"].(string)
	st.routes["/r/e/d"] = st.json(410, map[string]any{"error": "gone", "code": "gone", "tombstone": T, "last": P})
	st.routes["/r/e/d/rev/"+P] = st.notOffered("", "")
	st.routes["/r/e/d/rev/"+P+"/log"] = st.json(200, []any{g, p})
	x := st.view()
	if _, err := x.PruneE2E(ctx, "e", "d", T); err != nil {
		t.Fatal(err)
	}
	if st.pruned["horizon"] != T {
		t.Fatalf("prune body %v", st.pruned)
	}
	jwe, _ := st.pruned["snapshot"].(string)
	hd, err := seal.ParseHeader(jwe)
	if err != nil {
		t.Fatal(err)
	}
	if hd.Kid != "e#1" || hd.PL["id"] != P || hd.PL["ns"] != "e" || hd.PL["name"] != "d" || len(hd.PL) != 3 {
		t.Fatalf("snapshot header %s, want pl.id the tombstone's parent %s", hd.Raw, P)
	}
	doc := must(seal.OpenSnapshot(jwe, st.kr, "e#1", "e", "d", P))
	sameJSON(t, doc, map[string]any{"n": 2.0})

	// A tombstone further down the chain, found in the log.
	r := st.rev(st.kr, T, []any{map[string]any{"op": "add", "path": "/r", "value": true}})
	st.routes["/r/e/d"] = func(w http.ResponseWriter) {
		w.Header().Set("ETag", `"`+r["id"].(string)+`"`)
		w.WriteHeader(302)
	}
	st.routes["/r/e/d/rev/"+T+"/log"] = st.json(200, []any{g, p, st.tombstone(P)})
	if _, err := x.PruneE2E(ctx, "e", "d", T); err != nil {
		t.Fatal(err)
	}
	hd = must(seal.ParseHeader(st.pruned["snapshot"].(string)))
	if hd.PL["id"] != P || st.pruned["horizon"] != T {
		t.Fatalf("mid-chain tombstone: %s %v", hd.Raw, st.pruned["horizon"])
	}
}
