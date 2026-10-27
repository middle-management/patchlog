package core

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"strings"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/grant"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/keystore"
	"github.com/middle-management/patchlog/internal/pgtest"
	"github.com/middle-management/patchlog/internal/seal"
)

// P36 LEVELS-KEYS-BRANCHES: keys and branches after a raise to e2e
// (Addendum E Levels, §E.2.3, §G.5.2).

// p36Branch creates branch name of base at at ("" for the base's head).
func p36Branch(e *Engine, base, name, at string) (*WriteResult, error) {
	return e.CreateBranch(context.Background(), p29Req(base), BranchRequest{Name: name, At: at, IfNoneMatch: true})
}

// v0.73 Addendum E Levels, Branches of a raised base (ENC-44, CONFORMANCE
// ENC-10, Levels scenario 4): a branch of a base raised to e2e can't be
// created with an at before the raise (422 invalid with errors at
// /base/at, a branch field), since the epoch key in force at an earlier at
// also opens what the base sealed after it. The raise lies before the
// entry that made the namespace e2e, so at may be that entry or a later
// one.
func TestV073P36BranchAtBeforeRaise(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	e := p29Engine(t)
	cfg := mkNS(t, e, "n", map[string]any{})
	w, err := e.WriteResource(ctx, p29Req("n"), Item{Resource: "d", IfNoneMatch: true, Steps: []Step{{Patches: []any{p29Add("", map[string]any{"v": 1.0})}}}})
	if err != nil {
		t.Fatal(err)
	}
	before := w.NSID
	rw, err := e.WriteConfig(ctx, p29Req("n"), ConfigChange{IfMatch: cfg, Patches: []any{p29Add("/encryption", map[string]any{"level": "e2e"})}})
	if err != nil {
		t.Fatal(err)
	}
	refused := func(what string, err error) {
		t.Helper()
		st, body := p29Status(t, err)
		errs, _ := body["errors"].([]any)
		if st != 422 || body["code"] != "invalid" || len(errs) != 1 || errs[0].(map[string]any)["pointer"] != "/base/at" {
			t.Fatalf("%s: %d %v, want 422 invalid at /base/at", what, st, body)
		}
	}
	_, err = p36Branch(e, "n", "early", before)
	refused("a branch at an entry before the raise", err)
	if _, err := p36Branch(e, "n", "atraise", rw.NSID); err != nil {
		t.Fatalf("a branch at the raising entry: %v", err)
	}
	if _, err := p36Branch(e, "n", "head", ""); err != nil {
		t.Fatalf("a branch at the head: %v", err)
	}
	// A namespace e2e from its creation has no raise: any at of its chain.
	mkNS(t, e, "c", map[string]any{"encryption": map[string]any{"level": "e2e"}})
	var first string
	if err := e.read(ctx, func(t *tx) error {
		n := t.nsByName("c")
		var seq int64
		t.must(t.QueryRow(`SELECT MIN(seq) FROM ns_log WHERE ns = ?`, n.id).Scan(&seq))
		first = t.nsLogID(seq).String()
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := p36Branch(e, "c", "cb", first); err != nil {
		t.Fatalf("a branch of a namespace e2e from its creation: %v", err)
	}
}

// p36Env is an engine with a key store and authentication, whose clock
// the test moves, and the signing keys its namespaces list.
type p36Env struct {
	*Engine
	now  *time.Time
	keys p17Keys
	op   ed25519.PrivateKey
}

var p36T0 = time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

func p36NewEnv(t *testing.T) *p36Env {
	t.Helper()
	ks, err := keystore.New(keystore.Generate())
	if err != nil {
		t.Fatal(err)
	}
	opPub, opPriv := grant.GenerateKey()
	ops, err := grant.ParseKeys(jsonv.FromGo([]any{map[string]any{"kid": "operator", "alg": "ed25519", "pub": opPub, "can": []any{"*"}}}))
	if err != nil {
		t.Fatal(err)
	}
	now := p36T0
	env := &p36Env{now: &now, op: opPriv}
	env.keys.add("admin", map[string]any{"can": []any{"*"}})
	e, err := Open(Options{Path: pgtest.DB(t), BlobDir: t.TempDir(), OperatorKeys: ops, RetentionInterval: -1, BlobSweepInterval: -1,
		Remote: RemoteOptions{FollowInterval: -1}, Limits: p17Fast(), Purger: discardPurger{}, KeyStore: ks,
		Now: func() time.Time { return *env.now }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close() })
	env.Engine = e
	return env
}

func (e *p36Env) advance(d time.Duration) { *e.now = e.now.Add(d) }

// mint mints a grant of the admin key for sub on nss, with extra members
// in its root block; exp defaults to the clock plus a day.
func (e *p36Env) mint(t *testing.T, sub string, nss []string, can []string, extra map[string]any) Credentials {
	t.Helper()
	root := map[string]any{"kid": "admin", "sub": sub, "ns": anyStrings(nss), "can": anyStrings(can), "exp": e.now.Add(24 * time.Hour).Format(time.RFC3339)}
	for k, v := range extra {
		root[k] = v
	}
	return e.keys.mint(t, root)
}

// star is a grant chained to the admin * key, with every verb.
func (e *p36Env) star(t *testing.T, nss ...string) Request {
	return Request{NS: nss[0], Cred: e.mint(t, "user:admin", nss, grant.Verbs, nil)}
}

// create creates ns with an operator grant.
func (e *p36Env) create(t *testing.T, ns string, doc map[string]any) {
	t.Helper()
	doc["keys"] = e.keys.entries
	g, err := grant.Mint(map[string]any{"kid": "operator", "sub": "user:op", "ns": []any{ns}, "can": []any{"config"}, "exp": e.now.Add(time.Hour).Format(time.RFC3339)}, e.op)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.WriteConfig(context.Background(), Request{NS: ns, Cred: Credentials{Bearer: g.Encode()}}, ConfigChange{IfNoneMatch: true, Patches: []any{p29Add("", doc)}}); err != nil {
		t.Fatalf("creating %s: %v", ns, err)
	}
}

// config writes patches to ns's document under a * grant.
func (e *p36Env) config(t *testing.T, ns string, patches ...any) *WriteResult {
	t.Helper()
	ctx := context.Background()
	req := e.star(t, ns)
	h, err := e.NamespaceHead(ctx, ns, req.Cred)
	if err != nil {
		t.Fatal(err)
	}
	w, err := e.WriteConfig(ctx, req, ConfigChange{IfMatch: h.Config, Patches: patches})
	if err != nil {
		t.Fatalf("config of %s %v: %v", ns, patches, err)
	}
	return w
}

// keyKids is the kids ("kid name" for a K_r) of /keys for cred, in
// order, each key unwrapped with priv into got by that label.
func p36Keys(t *testing.T, e *p36Env, ns string, cred Credentials, kr KeysRequest, priv *ecdh.PrivateKey) (string, map[string][]byte) {
	t.Helper()
	ans, err := e.Keys(context.Background(), ns, cred, kr)
	if err != nil {
		t.Fatalf("/keys of %s: %v", ns, err)
	}
	var kids []string
	got := map[string][]byte{}
	for _, k := range ans.Keys {
		w, err := seal.ParseWrappedKey(jsonv.FromGo(k))
		if err != nil {
			t.Fatalf("/keys entry %v: %v", k, err)
		}
		label := w.Kid
		if w.Resource != "" {
			label += " " + w.Resource
		}
		kids = append(kids, label)
		if w.From == "" {
			if got[label], err = seal.UnwrapKey(priv, w); err != nil {
				t.Fatalf("unwrapping %s: %v", label, err)
			}
		}
	}
	return strings.Join(kids, ","), got
}

// v0.73 Addendum E Levels, After a raise and Branches of a raised base
// (ENC-42, CONFORMANCE ENC-9, ENC-10, Levels scenarios 5 and 24): after a
// raise from sealed, /keys at E3 gives the keys of the epochs before the
// raise as at E2: K_e to a grant that reads the namespace unrestricted,
// K_r of the names a grant's rules fix and it may read, for the epochs of
// its §E.2.3 window (from the one in force at its latest nbf; none
// without nbf, whose window is the current epoch alone), the request's
// epochs selecting among them; what E2 would refuse with 403 is left out.
// A branch's /keys gives the base's pre-raise keys, kid and K_r naming the
// base, for the base epochs §E.2.3 selects, which the request's epochs
// don't narrow.
func TestV073P36PreRaiseKeys(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	e := p36NewEnv(t)
	p29RaiseFromSealed(t, e.Engine)
	e.create(t, "s", map[string]any{"read": "grant", "encryption": map[string]any{"level": "sealed"}})
	e.advance(time.Hour)
	e.config(t, "s", p29Add("/encryption/epoch", 2.0)) // epoch 2 from t0+1h
	e.advance(time.Hour)
	e.config(t, "s", map[string]any{"op": "replace", "path": "/encryption", "value": map[string]any{"level": "e2e", "epoch": 3.0}}) // e2e epoch 3 from t0+2h
	e.advance(10 * time.Minute)
	jwk, priv, err := seal.GenerateRecipient()
	if err != nil {
		t.Fatal(err)
	}
	at := func(d time.Duration) string { return p36T0.Add(d).Format(time.RFC3339) }
	reader := func(ns string, extra map[string]any) Credentials {
		m := map[string]any{"enc": jwk}
		for k, v := range extra {
			m[k] = v
		}
		return e.mint(t, "user:r", []string{ns}, []string{"read"}, m)
	}
	enumAB := []any{map[string]any{"op": "test", "path": "/resource", "schema": map[string]any{"enum": []any{"a", "b"}}}}
	notB := []any{map[string]any{"not": map[string]any{"op": "test", "path": "/resource", "value": "b"}}}
	for name, c := range map[string]struct {
		cred Credentials
		kr   KeysRequest
		want string
	}{
		"no nbf: the current epoch alone":       {reader("s", nil), KeysRequest{}, ""},
		"nbf before the first epoch":            {reader("s", map[string]any{"nbf": at(-time.Hour)}), KeysRequest{}, "s#1,s#2"},
		"nbf in epoch 2":                        {reader("s", map[string]any{"nbf": at(90 * time.Minute)}), KeysRequest{}, "s#2"},
		"nbf after the raise":                   {reader("s", map[string]any{"nbf": at(125 * time.Minute)}), KeysRequest{}, ""},
		"epochs select":                         {reader("s", map[string]any{"nbf": at(-time.Hour)}), KeysRequest{Epochs: []int{2, 3}}, "s#2"},
		"fixed names: K_r":                      {reader("s", map[string]any{"nbf": at(-time.Hour), "rules": enumAB}), KeysRequest{}, "s#1 a,s#1 b,s#2 a,s#2 b"},
		"a name not fixed is left out, not 403": {reader("s", map[string]any{"nbf": at(-time.Hour), "rules": enumAB}), KeysRequest{Resources: []string{"a", "c"}}, "s#1 a,s#2 a"},
		"an unreadable name is left out":        {reader("s", map[string]any{"nbf": at(-time.Hour), "rules": append(enumAB, notB...)}), KeysRequest{}, "s#1 a,s#2 a"},
		"rules that refer without fixing: none": {reader("s", map[string]any{"nbf": at(-time.Hour), "rules": notB}), KeysRequest{}, ""},
		"unrestricted: K_e, resources ignored":  {reader("s", map[string]any{"nbf": at(-time.Hour)}), KeysRequest{Resources: []string{"zzz"}}, "s#1,s#2"},
	} {
		got, _ := p36Keys(t, e, "s", c.cred, c.kr, priv)
		if got != c.want {
			t.Errorf("%s: %q, want %q", name, got, c.want)
		}
	}
	// The keys are the origin's epoch keys, K_r derived with the namespace.
	var k1, k2 []byte
	if err := e.read(ctx, func(t *tx) error {
		n := t.nsByName("s")
		k1, k2 = t.epochKey(n.id, 1), t.epochKey(n.id, 2)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	_, got := p36Keys(t, e, "s", reader("s", map[string]any{"nbf": at(-time.Hour)}), KeysRequest{}, priv)
	if !bytes.Equal(got["s#1"], k1) || !bytes.Equal(got["s#2"], k2) {
		t.Fatalf("pre-raise K_e don't match the epoch keys: %v", got)
	}
	_, got = p36Keys(t, e, "s", reader("s", map[string]any{"nbf": at(-time.Hour), "rules": enumAB}), KeysRequest{}, priv)
	if kr, _ := seal.ResourceKey(k1, "s", "a"); !bytes.Equal(got["s#1 a"], kr) {
		t.Fatal("pre-raise K_r isn't derived with the namespace")
	}

	// A branch at the head: the base's pre-raise keys, named for the base.
	if _, err := e.CreateBranch(ctx, e.star(t, "s", "z"), BranchRequest{Name: "z", IfNoneMatch: true}); err != nil {
		t.Fatal(err)
	}
	e.advance(10 * time.Minute)
	for name, c := range map[string]struct {
		cred Credentials
		kr   KeysRequest
		want string
	}{
		"no nbf: base at its epoch at at":     {reader("z", nil), KeysRequest{}, ""},
		"nbf before the base's first epoch":   {reader("z", map[string]any{"nbf": at(-time.Hour)}), KeysRequest{}, "s#1,s#2"},
		"nbf in epoch 2":                      {reader("z", map[string]any{"nbf": at(90 * time.Minute)}), KeysRequest{}, "s#2"},
		"epochs don't select the base's":      {reader("z", map[string]any{"nbf": at(-time.Hour)}), KeysRequest{Epochs: []int{}}, "s#1,s#2"},
		"fixed names: K_r named for the base": {reader("z", map[string]any{"nbf": at(-time.Hour), "rules": enumAB}), KeysRequest{Resources: []string{"a"}}, "s#1 a,s#2 a"},
	} {
		got, _ := p36Keys(t, e, "z", c.cred, c.kr, priv)
		if got != c.want {
			t.Errorf("branch, %s: %q, want %q", name, got, c.want)
		}
	}
	_, got = p36Keys(t, e, "z", reader("z", map[string]any{"nbf": at(-time.Hour), "rules": enumAB}), KeysRequest{}, priv)
	if kr, _ := seal.ResourceKey(k2, "s", "b"); !bytes.Equal(got["s#2 b"], kr) {
		t.Fatal("a branch's pre-raise K_r isn't derived with the base's namespace")
	}
}

// v0.73 §8.6, §E.3.1, Addendum E Levels, After a raise (ENC-51, ENC-22;
// CONFORMANCE Levels scenarios 23 and 37): after a raise from sealed, an
// E3 prune whose horizon's document is from before the raise keeps that
// document, which /rev/{H} goes on serving as before the raise, and its
// stored sealing, which fixed the epoch it is served under; the documents
// and sealings of what it prunes below go. In a branch reading that
// content through, a prune's snapshot is sealed under the epoch the base
// serves the revision under, so its kid names the base, never the
// branch's own later epoch.
func TestV073P36PreRaiseHorizon(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ks, err := keystore.New(keystore.Generate())
	if err != nil {
		t.Fatal(err)
	}
	now := &p29Clock{t: p36T0}
	e, err := Open(Options{Path: pgtest.DB(t), BlobDir: t.TempDir(), AuthDisabled: true, RetentionInterval: -1, BlobSweepInterval: -1,
		Remote: RemoteOptions{FollowInterval: -1}, Purger: discardPurger{}, KeyStore: ks, Archiver: p29Archiver{}, Now: now.Now})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close() })
	p29RaiseFromSealed(t, e)
	cfg := mkNS(t, e, "s", map[string]any{"encryption": map[string]any{"level": "sealed"}})
	ids := []string{""}
	for i := 1; i <= 3; i++ {
		patches := []any{map[string]any{"op": "replace", "path": "/n", "value": float64(i)}, map[string]any{"op": "replace", "path": "/$nonce", "value": seal.NewNonce()}}
		if i == 1 {
			patches = []any{p29Add("", map[string]any{"n": 1.0}), p29Add("/$nonce", seal.NewNonce())}
		}
		w, err := e.WriteResource(ctx, p29Req("s"), Item{Resource: "d", IfMatch: ids[i-1], IfNoneMatch: i == 1, Steps: []Step{{Patches: patches}}})
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, w.Items[0].IDs[0])
	}
	w1, w2 := ids[1], ids[2]
	// Read while sealed: each document gets its stored sealing (§E.2.2).
	for _, id := range ids[1:] {
		if _, err := e.ResourceRev(ctx, "s", "d", id, who.Cred); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := e.WriteConfig(ctx, p29Req("s"), ConfigChange{IfMatch: cfg, Patches: []any{map[string]any{"op": "replace", "path": "/encryption", "value": map[string]any{"level": "e2e", "epoch": 2.0}}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := p36Branch(e, "s", "z", ""); err != nil {
		t.Fatal(err)
	}
	now.Advance(10 * time.Minute) // past what a prune protects
	key := seal.NewKey()          // the server checks the header only
	snap := func(kid, ns string) string {
		t.Helper()
		kns, _, _ := seal.ParseKid(kid)
		kr, err := seal.ResourceKey(key, kns, "d")
		if err != nil {
			t.Fatal(err)
		}
		jwe, err := seal.SealSnapshot(kr, kid, ns, "d", w2, jsonv.FromGo(map[string]any{"n": 2.0}))
		if err != nil {
			t.Fatal(err)
		}
		return jwe
	}

	// The branch's snapshot of the base's pre-raise content names the base.
	for _, kid := range []string{"z#2", "s#2"} {
		if st, body := p29Status(t, second(e.Prune(ctx, p29Req("z"), "d", PruneRequest{Horizon: w2, Snapshot: snap(kid, "z")}))); st != 422 || body["code"] != "invalid" {
			t.Fatalf("branch snapshot of the base's pre-raise content under %s: %d %v, want 422 invalid", kid, st, body)
		}
	}
	if _, err := e.Prune(ctx, p29Req("z"), "d", PruneRequest{Horizon: w2, Snapshot: snap("s#1", "z")}); err != nil {
		t.Fatalf("branch snapshot under the base's epoch it is served under: %v", err)
	}

	// The base's prune at w2 keeps w2's document and stored sealing.
	if _, err := e.Prune(ctx, p29Req("s"), "d", PruneRequest{Horizon: w2, Snapshot: snap("s#1", "s")}); err != nil {
		t.Fatalf("prune at a pre-raise horizon: %v", err)
	}
	var doc []byte
	sealedOf := map[string]int{}
	if err := e.read(ctx, func(t *tx) error {
		n := t.nsByName("s")
		var err error
		row := t.findInAncestry(t.resolve(n, "d", nil).head, mustID(w2))
		if doc, err = t.docBytesAt(row); err != nil {
			return err
		}
		for _, id := range []string{w1, w2} {
			r := t.findInAncestry(t.resolve(n, "d", nil).head, mustID(id))
			var c int
			t.must(t.QueryRow(`SELECT COUNT(*) FROM sealed WHERE ns = ? AND rev_seq = ? AND kind = 'doc'`, n.id, r.seq).Scan(&c))
			sealedOf[id] = c
		}
		return nil
	}); err != nil {
		t.Fatalf("the horizon's document after the prune: %v", err)
	}
	if v, _ := jsonv.MustParse(doc).(map[string]any); v["n"] != 2.0 {
		t.Fatalf("the horizon's document %s", doc)
	}
	if sealedOf[w2] != 1 || sealedOf[w1] != 0 {
		t.Fatalf("stored sealings after the prune: %v, want the horizon's kept and the pruned one's gone", sealedOf)
	}
}
