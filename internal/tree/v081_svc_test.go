package tree_test

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/tree"
)

// §C.2 item 5, §B.11.5 (v0.78): a grant with a key-scope or block rule on
// /now is refused every read, so it doesn't read the catalog unrestricted
// (problems 403) and reads no listing, nor is it exchanged for an edge
// grant.
func TestV081SvcReadNowTree(t *testing.T) {
	t.Parallel()
	clock := map[string]any{"rules": []any{map[string]any{"op": "test", "path": "/now", "exists": true}}}
	q := newP24World(t, "grant", "grant").start(withEdgeGrants)
	cl := q.grant("user:cl", []string{"cat", "matches"}, clock)
	amy := q.grant("user:amy", []string{"cat", "matches"})
	if r := q.do("GET", q.x.atURL("/cat/problems", amy), amy, ""); r.status != 200 {
		t.Fatalf("problems, a namespace-wide reader: %d %v", r.status, r.body)
	}
	for _, path := range []string{"/cat/problems", "/cat/g/all/problems", "/cat/children?of=root"} {
		if r := q.do("GET", path, cl, ""); r.status != 403 || r.header.Get("Cache-Control") != "no-store" {
			t.Errorf("%s with a block rule on /now: %d %q %v", path, r.status, r.header.Get("Cache-Control"), r.body)
		}
	}
	req := must(http.NewRequest("POST", q.x.http.URL+"/edge-grants", nil))
	req.Header.Set("Authorization", "Bearer "+cl)
	r := must(noRedirect.Do(req))
	r.Body.Close()
	if r.StatusCode != 403 || len(r.Cookies()) != 0 {
		t.Errorf("exchange with a block rule on /now: %d %v", r.StatusCode, r.Cookies())
	}
}

// §B.11.5, §B.11.9 gs (v0.78): no gs leaves a group out, so an edge
// grant whose subject set was stored holding "partial", under an earlier
// draft, is 403, no-store, until the reader exchanges again, without a
// Profiler too: served as it is it would show what a group it left out
// hides.
func TestV081SvcStoredPartialRefused(t *testing.T) {
	t.Parallel()
	q := newP24World(t, "grant", "grant").start(withEdgeGrants)
	bob := q.scoped("user:bob", "root", "season", "matches.derby")
	prefix, ck := q.exchange(bob)
	r := q.do("GET", prefix+"/children?of=root", "", "", ck)
	if r.status != 302 {
		t.Fatalf("cookie's head pointer: %d %v", r.status, r.body)
	}
	loc := r.header.Get("Location")
	if r = q.do("GET", loc, "", "", ck); r.status != 200 {
		t.Fatalf("cookie at its at: %d %v", r.status, r.body)
	}
	gs := strings.TrimPrefix(prefix, "/cat/g/")
	subs := []string{"partial", "scope:matches.derby", "scope:root", "scope:season"}
	if err := q.x.s.RecordSubjects(context.Background(), gs, subs, q.s.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{prefix + "/children?of=root", loc} {
		if r = q.do("GET", path, "", "", ck); r.status != 403 || r.header.Get("Cache-Control") != "no-store" {
			t.Errorf("a stored partial set at %s: %d %q %v", path, r.status, r.header.Get("Cache-Control"), r.body)
		}
	}
	// Exchanged again, the set is the grant's own and reads.
	prefix2, ck2 := q.exchange(bob)
	if prefix2 != prefix {
		t.Fatalf("exchanged again for %s", prefix2)
	}
	if r = q.do("GET", loc, "", "", ck2); r.status != 200 {
		t.Errorf("exchanged again: %d %v", r.status, r.body)
	}
}

// §E.2.6, v0.78: a namespace is e2e only from its creation, so the born
// epoch of an e2e namespace's revision comes from its own sealed op, never
// from a kid the origin serves with the entry, which only revisions
// sealed before a raise carried.
func TestV081SvcSnapshotBornEpochIgnoresKid(t *testing.T) {
	t.Parallel()
	if e := tree.SnapshotBornEpoch("e3", client.LogEntry{ID: "a", Kid: "e3#2"}); e != 0 {
		t.Errorf("a served kid without a patch set: %d", e)
	}
	plain := client.LogEntry{ID: "a", Kid: "e3#2", HasPatches: true, Patches: []any{map[string]any{"op": "add", "path": "", "value": map[string]any{}}}}
	if e := tree.SnapshotBornEpoch("e3", plain); e != tree.BornPending {
		t.Errorf("a served kid with a patch set that isn't the namespace's sealed op: %d", e)
	}
}
