package core

import (
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
