package server

import (
	"strings"
	"testing"
	"time"
)

// Access scenario 83 (§C.4 requireAt, §8.5; v0.86): "where requireAt
// names a purged namespace other than the one the grant is checked in".
// A key of private, unsealed matches with requireAt: true, and one with
// requireAt: "matches", its own name: once matches is purged, a grant
// either signs, at in matches's chain, still verifies, so the log range
// is served as before and a resource read gets the purged namespace's
// 410, never the scope's 403. Before v0.86 the key naming matches by
// name was 403. The same key checked in a branch names another
// namespace there, and stays 403.
func TestV086RequireAtOwnNamespacePurged(t *testing.T) {
	t.Parallel()
	e := newAuthEnv(t)
	k, self, named := newKey("k"), newKey("self"), newKey("named")
	scoped := func(kp keyPair, at any) map[string]any {
		en := kp.entry("read", "append")
		en["requireAt"], en["maxTtl"] = at, "PT15M"
		return en
	}
	e.mkNS("matches", map[string]any{"read": "grant", "keys": []any{k.entry("*"), scoped(self, true), scoped(named, "matches")}})
	admin := e.grant(k, "user:root", []string{"matches", "matches-b"}, allVerbs)
	e.create("matches", "derby", map[string]any{"n": 0.0}, admin)
	expect(t, e.branch("matches", map[string]any{"name": "matches-b"}, admin), 201)
	exp := func() string { return e.clock.Now().Add(10 * time.Minute).Format(time.RFC3339) }
	grantAt := func(kp keyPair, ns, id string) string {
		return e.grant(kp, "user:li", []string{ns}, []string{"read", "append"}, map[string]any{"at": map[string]any{"ns": "matches", "id": id}, "exp": exp()})
	}
	before := e.nsHead("matches", admin)
	keys := map[string]keyPair{"requireAt: true": self, `requireAt: "matches"`: named}
	live := map[string]string{}
	for name, kp := range keys {
		live[name] = grantAt(kp, "matches", before)
		expect(t, e.get("/r/matches/derby", live[name]), 302)
		expect(t, e.get("/ns/matches/rev/"+before+"/log", live[name]), 200)
	}
	e.purgeNSAs("matches-b", admin)
	purge := e.purgeNSAs("matches", admin)
	for name, kp := range keys {
		for an, g := range map[string]string{"at the purge-ns entry": grantAt(kp, "matches", purge), "the grant that read before": live[name]} {
			// The log range, served as before (§8.5: the log is kept).
			if r := e.get("/ns/matches/rev/"+before+"/log", g); r.Code != 200 {
				t.Errorf("%s, %s: log range %d %s, want 200 as before the purge", name, an, r.Code, r.Body)
			}
			if r := e.get("/ns/matches/rev/"+purge+"/log", g); r.Code != 200 {
				t.Errorf("%s, %s: log range to the purge-ns entry %d %s, want 200", name, an, r.Code, r.Body)
			}
			// A resource: the purged namespace's 410.
			if r := e.get("/r/matches/derby", g); r.Code != 410 || r.Str("code") != "purged" {
				t.Errorf("%s, %s: resource %d %s, want 410 purged, never the scope's 403", name, an, r.Code, r.Body)
			}
			// The log's pointer, kept like the log (§8.5).
			if r := e.get("/ns/matches/log", g); r.Code != 302 {
				t.Errorf("%s, %s: log pointer %d %s, want 302 as before the purge", name, an, r.Code, r.Body)
			}
		}
	}
	// In the branch, which takes the base's keys (§C.4), "matches" is a
	// namespace other than the one the grant is checked in: the scope's
	// 403, as for any purged namespace a requireAt names.
	if r := e.get("/ns/matches-b/log", grantAt(named, "matches-b", purge)); r.Code != 403 {
		t.Errorf(`requireAt: "matches" checked in its purged branch: %d %s, want the scope's 403`, r.Code, r.Body)
	}
}

// Access scenario 84 (§C.4 requireAt; v0.86): a grant a requireAt:
// "cat-season" key signs without at, or with neither nbf nor a key
// maxTtl, is 403 naming no namespace; its body may differ from the
// others', while the bodies for an at outside the chain and for a
// namespace that doesn't exist are identical.
func TestV086RequireAtRefusalsNameNoNamespace(t *testing.T) {
	t.Parallel()
	e := newAuthEnv(t)
	k, timed, untimed, nope := newKey("k"), newKey("timed"), newKey("untimed"), newKey("nope")
	scoped := func(kp keyPair, at, maxTTL string) map[string]any {
		en := kp.entry("read")
		en["requireAt"] = at
		if maxTTL != "" {
			en["maxTtl"] = maxTTL
		}
		return en
	}
	e.mkNS("cat-season", map[string]any{"read": "grant", "keys": []any{k.entry("*")}})
	e.mkNS("matches", map[string]any{"read": "grant", "keys": []any{k.entry("*"),
		scoped(timed, "cat-season", "PT15M"), scoped(untimed, "cat-season", ""), scoped(nope, "cat-gone", "PT15M")}})
	admin := e.grant(k, "user:root", []string{"matches", "cat-season"}, allVerbs)
	head := e.nsHead("cat-season", admin)
	exp := e.clock.Now().Add(10 * time.Minute).Format(time.RFC3339)
	at := func(ns, id string) map[string]any {
		return map[string]any{"at": map[string]any{"ns": ns, "id": id}, "exp": exp}
	}
	inNoChain := hashID(t, "", []byte("in no chain"))
	expect(t, e.get("/ns/matches/log", e.grant(timed, "user:li", []string{"matches"}, []string{"read"}, at("cat-season", head))), 302)
	shape := map[string]*resp{
		"without at":                   e.get("/ns/matches/log", e.grant(timed, "user:li", []string{"matches"}, []string{"read"}, map[string]any{"exp": exp})),
		"neither nbf nor a key maxTtl": e.get("/ns/matches/log", e.grant(untimed, "user:li", []string{"matches"}, []string{"read"}, at("cat-season", head))),
	}
	chain := map[string]*resp{
		"an at outside the chain":      e.get("/ns/matches/log", e.grant(timed, "user:li", []string{"matches"}, []string{"read"}, at("cat-season", inNoChain))),
		"a namespace that isn't there": e.get("/ns/matches/log", e.grant(nope, "user:li", []string{"matches"}, []string{"read"}, at("cat-gone", inNoChain))),
	}
	for name, r := range shape {
		if r.Code != 403 || strings.Contains(r.String(), "cat-season") {
			t.Errorf("%s: %d %s, want 403 naming no namespace", name, r.Code, r.Body)
		}
	}
	for name, r := range chain {
		if r.Code != 403 || strings.Contains(r.String(), "cat-") || r.String() != chain["an at outside the chain"].String() {
			t.Errorf("%s: %d %s, want the one 403 body, %s", name, r.Code, r.Body, chain["an at outside the chain"].Body)
		}
	}
}
