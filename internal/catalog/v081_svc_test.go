package catalog_test

import (
	"testing"

	"github.com/middle-management/patchlog/internal/grantcheck"
)

// TestV081SvcAllGroups (§B.11.5 Listing URLs carry the subject set,
// v0.78; CONFORMANCE Tree-derived access 78 and 69): a listing's subjects
// are every group of the caller, plus its sub only where the catalog has
// direct entries for it. zed and fred differ only in interns, which
// nothing names, and have different subject sets; once reader tests
// interns negatively, zed's old cookie, whose set holds interns, sees what
// reader no longer grants it hidden at once, while fred reads on.
func TestV081SvcAllGroups(t *testing.T) {
	t.Parallel()
	w := setup(t)
	w.startEdge()
	zed := w.caller("user:zed", "fan-club", "interns")
	fred := w.caller("user:fred", "fan-club")
	gz, gf := w.gsFor(zed), w.gsFor(fred)
	if gz != grantcheck.SubjectSetID([]string{"group:fan-club", "group:interns"}) {
		t.Errorf("zed's subject set %s", gz)
	}
	if gf != grantcheck.SubjectSetID([]string{"group:fan-club"}) || gz == gf {
		t.Errorf("fred's subject set %s (zed's %s)", gf, gz)
	}
	_, cks := w.exchange(zed, nil, "")
	ck := cks[0]
	r := w.withCookie("/cat/g/"+gz+"/children?of=season", ck, nil)
	if r.status != 302 {
		t.Fatalf("zed's cookie, head pointer: %d %v", r.status, r.body)
	}
	if r = w.withCookie(r.header.Get("Location"), ck, nil); r.status != 200 || childNames(r.body) != "matches.derby,matches.shared" {
		t.Fatalf("zed's cookie on season: %d %v", r.status, r.body)
	}

	w.patchMatches(map[string]any{"op": "add", "path": "/roles/reader/rules", "value": []any{notInterns}})
	r = w.withCookie("/cat/g/"+gz+"/children?of=season", ck, nil)
	if r.status != 302 {
		t.Fatalf("zed's cookie, head pointer once reader excludes interns: %d %v", r.status, r.body)
	}
	if r = w.withCookie(r.header.Get("Location"), ck, nil); r.status != 404 {
		t.Errorf("zed's old cookie on season once reader excludes interns: %d %v", r.status, r.body)
	}
	if !w.listsFolder(fred, "season") || w.listsFolder(zed, "season") {
		t.Errorf("season: fred %v, zed %v", w.listsFolder(fred, "season"), w.listsFolder(zed, "season"))
	}
}
