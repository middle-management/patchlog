package server

import (
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
