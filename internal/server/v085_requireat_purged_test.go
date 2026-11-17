package server

import (
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/ids"
)

// Grant scope 77 (§C.4 requireAt, v0.85): "The grant fails the scope
// (403), answered as any other scope failure, where requireAt names a
// purged namespace ... or, at the origin, one that doesn't exist." A key
// of n with requireAt: "cat-old" signs a grant whose at is cat-old's
// head: it reads while cat-old lives, and once cat-old is purged it is
// 403 with at the purge-ns entry, the log's last and its head for good,
// and with the at it read under, with the body a requireAt naming a
// namespace that doesn't exist gets, which names neither.
func TestV085RequireAtPurgedNamespaceOrigin(t *testing.T) {
	t.Parallel()
	e := newAuthEnv(t)
	k, old, nope := newKey("k"), newKey("old"), newKey("nope")
	scoped := func(kp keyPair, at string) map[string]any {
		en := kp.entry("read", "append")
		en["requireAt"], en["maxTtl"] = at, "PT15M"
		return en
	}
	e.mkNS("cat-old", map[string]any{"read": "grant", "keys": []any{k.entry("*")}})
	e.mkNS("n", map[string]any{"read": "grant", "keys": []any{k.entry("*"), scoped(old, "cat-old"), scoped(nope, "nope")}})
	admin := e.grant(k, "user:root", []string{"n", "cat-old"}, allVerbs)
	e.create("n", "x", map[string]any{"n": 0.0}, admin)
	exp := func() string { return e.clock.Now().Add(10 * time.Minute).Format(time.RFC3339) }
	at := func(kp keyPair, ns, id string) string {
		return e.grant(kp, "user:li", []string{"n"}, []string{"read", "append"}, map[string]any{"at": map[string]any{"ns": ns, "id": id}, "exp": exp()})
	}
	before := e.nsHead("cat-old", admin)
	live := at(old, "cat-old", before)
	expect(t, e.get("/ns/n/log", live), 302)
	purge := e.purgeNSAs("cat-old", admin)
	missing := e.get("/ns/n/log", at(nope, "nope", ids.Of([]byte("in no chain")).String()))
	expect(t, missing, 403)
	for name, g := range map[string]string{
		"at the purge-ns entry":      at(old, "cat-old", purge),
		"the grant that read before": live,
		"at the head before":         at(old, "cat-old", before),
	} {
		r := e.get("/ns/n/log", g)
		if r.Code != 403 || r.String() != missing.String() {
			t.Errorf("%s: %d %s, want the 403 of a requireAt naming no namespace, %s", name, r.Code, r.Body, missing.Body)
		}
		if r := e.get("/r/n/x", g); r.Code != 404 {
			t.Errorf("%s, a resource: %d %s, want 404", name, r.Code, r.Body)
		}
	}
}
