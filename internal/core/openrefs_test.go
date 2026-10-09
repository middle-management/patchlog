package core

import (
	"context"
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/grant"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/pgtest"
	"github.com/middle-management/patchlog/internal/schema"
)

// refsEnv is an engine with authentication on and one key, k, in every
// namespace it makes.
type refsEnv struct {
	t     *testing.T
	e     *Engine
	op    Credentials
	priv  ed25519.PrivateKey
	keys  []any
	admin Credentials
}

func newRefsEnv(t *testing.T) *refsEnv {
	t.Helper()
	opPub, opPriv := grant.GenerateKey()
	ops, err := grant.ParseKeys(jsonv.FromGo([]any{map[string]any{"kid": "operator", "alg": "ed25519", "pub": opPub, "can": []any{"*"}}}))
	if err != nil {
		t.Fatal(err)
	}
	lim := DefaultLimits()
	fast := Rate{1e9, 1e9}
	lim.RatePerResource, lim.RatePerPrincipal, lim.RatePerNamespace = fast, fast, fast
	e, err := Open(Options{Path: pgtest.DB(t), BlobDir: t.TempDir(), OperatorKeys: ops, RetentionInterval: -1, Remote: RemoteOptions{FollowInterval: -1},
		Limits: lim, TailInterval: authTailEvery, Purger: discardPurger{}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close() })
	pub, priv := grant.GenerateKey()
	r := &refsEnv{t: t, e: e, priv: priv, keys: []any{map[string]any{"kid": "k", "alg": "ed25519", "pub": pub, "can": []any{"*"}}}}
	r.op = r.mint(opPriv, map[string]any{"kid": "operator", "sub": "op:root", "ns": []any{"*"}, "can": []any{"config"}})
	r.admin = r.mint(priv, map[string]any{"kid": "k", "sub": "user:root", "ns": []any{"schemas", "pub", "pub2"}, "can": []any{"read", "create", "append", "config"}})
	return r
}

func (r *refsEnv) mint(priv ed25519.PrivateKey, root map[string]any) Credentials {
	r.t.Helper()
	root["exp"] = time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	g, err := grant.Mint(root, priv)
	if err != nil {
		r.t.Fatal(err)
	}
	return Credentials{Bearer: g.Encode()}
}

// config writes ns's document whole, creating ns if ifMatch is "", and
// returns its configuration id.
func (r *refsEnv) config(ns, ifMatch string, doc map[string]any) string {
	r.t.Helper()
	doc["keys"] = r.keys
	op, cred := "replace", r.admin
	if ifMatch == "" {
		op, cred = "add", r.op
	}
	res, err := r.e.WriteConfig(context.Background(), Request{NS: ns, Cred: cred},
		ConfigChange{IfMatch: ifMatch, IfNoneMatch: ifMatch == "", Patches: []any{map[string]any{"op": op, "path": "", "value": doc}}})
	if err != nil {
		r.t.Fatal(err)
	}
	return res.ConfigID
}

// put writes doc to ns/name, creating it if ifMatch is "", and returns the
// revision id.
func (r *refsEnv) put(ns, name, ifMatch string, doc map[string]any) string {
	r.t.Helper()
	op := "replace"
	if ifMatch == "" {
		op = "add"
	}
	it := Item{Resource: name, IfMatch: ifMatch, IfNoneMatch: ifMatch == "", Steps: []Step{{Patches: []any{map[string]any{"op": op, "path": "", "value": doc}}}}}
	res, err := r.e.WriteResource(context.Background(), Request{NS: ns, Cred: r.admin}, it)
	if err != nil {
		r.t.Fatal(err)
	}
	return res.Items[0].IDs[0]
}

// read reads revision id of schemas/name and returns its status.
func (r *refsEnv) read(name, id string, cred Credentials) int {
	r.t.Helper()
	res, err := r.e.ResourceRev(context.Background(), "schemas", name, id, cred)
	if err != nil {
		return status(err)
	}
	return res.Status
}

// Whether a referrer in a public namespace opens a schema revision under
// schemaReads (§6.1) is the same for every request, and is kept by path:
// an anonymous read doesn't read the referrers' namespaces again until a
// write to one of them, or a configuration change, may have changed the
// answer.
func TestOpenReferrersMemo(t *testing.T) {
	t.Parallel()
	r := newRefsEnv(t)
	e := r.e
	r.config("schemas", "", map[string]any{"read": "grant", "schemaReads": map[string]any{"for": []any{"pub*"}}})
	pubCfg := r.config("pub", "", map[string]any{"read": "public"})
	s := r.put("schemas", "s", "", map[string]any{"$schema": schema.Dialect2020, "title": "s"})
	u := r.put("schemas", "u", "", map[string]any{"$schema": schema.Dialect2020, "title": "u"})
	sPath, uPath := "/r/schemas/s/rev/"+s, "/r/schemas/u/rev/"+u
	gen := e.rc.nsGen("pub").Load()
	r.put("pub", "doc", "", map[string]any{"$schema": sPath})
	tailed(t, e, "pub", gen)

	anon := Credentials{}
	if c := r.read("s", s, anon); c != 200 {
		t.Fatalf("pinned by a public referrer: %d", c)
	}
	if c := r.read("u", u, anon); c != 401 {
		t.Fatalf("pinned by nobody: %d", c)
	}
	kept := func(path string) (openRefsEntry, bool) { return e.rc.refsFor(e.rc.load("schemas"), path) }
	if m, ok := kept(sPath); !ok || !m.ok {
		t.Fatalf("the open answer isn't kept: %+v %v", m, ok)
	}
	if m, ok := kept(uPath); !ok || m.ok {
		t.Fatalf("the closed answer isn't kept: %+v %v", m, ok)
	}
	// Mark u's answer open: what follows shows when it is served.
	mark := func() {
		e.rc.refs.mu.Lock()
		m := e.rc.refs.m[uPath]
		m.ok = true
		e.rc.refs.m[uPath] = m
		e.rc.refs.mu.Unlock()
		if c := r.read("u", u, anon); c != 200 {
			t.Fatalf("the kept answer isn't served: %d", c)
		}
	}
	mark()
	// Any write to pub decides anew, a referrer or not.
	r.put("pub", "other", "", map[string]any{"v": 1.0})
	if c := r.read("u", u, anon); c != 401 {
		t.Fatalf("after a write to pub: %d", c)
	}
	// So does a configuration change anywhere.
	mark()
	pubCfg = r.config("pub", pubCfg, map[string]any{"read": "public", "x-title": "pub"})
	if c := r.read("u", u, anon); c != 401 {
		t.Fatalf("after a configuration change: %d", c)
	}

	// A namespace made since that schemaReads lists counts.
	r.config("pub2", "", map[string]any{"read": "public"})
	d := r.put("pub2", "doc", "", map[string]any{"$schema": uPath})
	if c := r.read("u", u, anon); c != 200 {
		t.Fatalf("pinned in a new namespace: %d", c)
	}
	r.put("pub2", "doc", d, map[string]any{})
	if c := r.read("u", u, anon); c != 401 {
		t.Fatalf("no longer pinned: %d", c)
	}
	// Once pub isn't public, its referrer opens s to its readers only.
	r.config("pub", pubCfg, map[string]any{"read": "grant"})
	if c := r.read("s", s, anon); c != 401 {
		t.Fatalf("pub private: %d", c)
	}
	reader := r.mint(r.priv, map[string]any{"kid": "k", "sub": "user:r", "ns": []any{"pub"}, "can": []any{"read"}})
	if c := r.read("s", s, reader); c != 200 {
		t.Fatalf("pub private, a reader of pub: %d", c)
	}
}
