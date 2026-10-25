package server

import (
	"crypto/ed25519"
	"testing"
	"time"
)

// Spec v0.73, package P25: step 6 of §6.2 for a remote branch's creation.

// GB-1 (GR-25): a remote branch's creation under the operator grant that
// creates it skips only the namespace rules (§6.4.3). Step 6 still runs
// that grant's own rules against the config envelope of the genesis
// (§6.2 step 6, §C.2 item 4): a block rule reading /doc that refuses is
// 403, and neither the branch nor the schema namespace it would mirror
// into is created. The checks of the genesis that need the base come
// first (step 4, §G.3), so a creation failing one of them and the rule is
// 422.
func TestV073P25RemoteCreationGrantRules(t *testing.T) {
	t.Parallel()
	var bPriv ed25519.PrivateKey
	a := newEnv(t, withOrigin(originA))
	f := populateA(t, a)
	b := newEnv(t, withOrigin(originB), withAuth(&bPriv), withRemote(&route{url: a.srv.URL}))
	b.opPriv = bPriv
	notPublic := map[string]any{"op": "test", "path": "/doc/read", "value": "grant"}
	opGrant := func() string {
		return mint(t, bPriv, map[string]any{"kid": "operator", "sub": "op:root", "ns": []any{"rel"}, "can": []any{"config"},
			"rules": []any{notPublic}, "exp": b.clock.Now().Add(time.Hour).Format(time.RFC3339)})
	}
	create := func(genesis []any) *resp {
		return b.do(req{method: "PATCH", path: "/ns/rel", ifNoneMatch: "*", body: genesis, bearer: opGrant()})
	}

	// A's main is public, so §G.5 allows a public branch of it; the
	// grant's rule doesn't.
	expectCode(t, create(remoteGenesis("main", f.at, nil)), 403, "forbidden")
	expect(t, b.get("/ns/rel/principal", b.operatorGrant("rel")), 404)
	expect(t, b.get("/ns/schemas/principal", b.operatorGrant("schemas")), 404)

	// A base.chain that doesn't name the bases A follows is refused once
	// the base is verified, before the rule.
	expectCode(t, create(remoteGenesisChain([]string{"main", "other"}, f.at, nil)), 422, "invalid")
	expect(t, b.get("/ns/rel/principal", b.operatorGrant("rel")), 404)

	// The rule allows a private branch.
	expect(t, create(remoteGenesis("main", f.at, map[string]any{"read": "grant"})), 201)
	expect(t, b.get("/ns/schemas/principal", b.operatorGrant("schemas")), 200)
}
