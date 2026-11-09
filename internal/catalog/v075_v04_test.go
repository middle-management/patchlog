package catalog_test

import (
	"testing"

	"github.com/middle-management/patchlog/internal/edge"
	"github.com/middle-management/patchlog/internal/grantcheck"
)

// startEdge starts the seeded world's service with edge grants of its own
// (§B.11.5).
func (w *world) startEdge() {
	w.t.Helper()
	w.seed()
	w.edgeGrants = edge.NewCookies("catalog-cat", edgeKey)
	w.start()
	w.caughtUp()
}

// gsFor is the subject set token's listings are keyed by: the gs of the
// prefix POST /edge-grants gives it, which must be that of its listings'
// redirect.
func (w *world) gsFor(token string) string {
	w.t.Helper()
	r, cks := w.exchange(token, nil, "")
	if r.status != 200 || len(cks) != 1 {
		w.t.Fatalf("exchange: %d %v", r.status, r.body)
	}
	gs := gsOf(prefixes(r) + "/")
	if _, loc := w.follow("/cat/children?of=season", token); gsOf(loc) != gs {
		w.t.Fatalf("the listing's subject set %s isn't the exchange's %s", loc, gs)
	}
	return gs
}

// notInterns is a rule that tests /principal/groups negatively (§B.11.5).
var notInterns = map[string]any{"not": map[string]any{"op": "test", "path": "/principal/groups",
	"schema": map[string]any{"contains": map[string]any{"const": "interns"}}}}

// TestDecidingSubjectsV075 (MUST-4, SVC-1, scenario 69): a listing's
// subjects are the caller's deciding subjects: its groups that the
// catalog's $access, or a role or key rule of a content namespace it
// trusts, names, plus "partial" if that leaves one out (§B.11.5). Where a
// rule tests /principal/groups otherwise than positively by value, every
// group is kept, and there is no "partial".
func TestDecidingSubjectsV075(t *testing.T) {
	t.Parallel()
	w := setup(t)
	w.startEdge()
	// The seed's $access names fan-club, and no rule names a group: zed's
	// interns decides nothing, so it is left out, and "partial" says so.
	zed := w.caller("user:zed", "fan-club", "interns")
	partial := grantcheck.SubjectSetID([]string{"group:fan-club", "partial"})
	if gs := w.gsFor(zed); gs != partial {
		t.Errorf("zed's subject set %s, want %s (group:fan-club, partial)", gs, partial)
	}
	// What it sees is fan-club's alone, which interns can't change.
	if r, _ := w.follow("/cat/children?of=season", zed); r.status != 200 || childNames(r.body) != "matches.derby,matches.shared" {
		t.Errorf("zed on season: %d %v", r.status, r.body)
	}
	// A caller with only named groups has no "partial".
	if gs, want := w.gsFor(w.caller("user:fred", "fan-club")), grantcheck.SubjectSetID([]string{"group:fan-club"}); gs != want {
		t.Errorf("fred's subject set %s, want %s", gs, want)
	}
	// A role rule of matches tests the groups negatively: every group
	// decides, even in a role that grants no read.
	w.patchMatches(map[string]any{"op": "add", "path": "/roles/gate", "value": map[string]any{"can": toAny("delete"), "rules": []any{notInterns}}})
	if gs, want := w.gsFor(zed), grantcheck.SubjectSetID([]string{"group:fan-club", "group:interns"}); gs != want {
		t.Errorf("zed's subject set with a negative group test %s, want %s", gs, want)
	}
}

// TestDecidingSubjectsNamedV075 (MUST-4, scenario 69): a group a role rule
// names by a positive test, or a folder's $access names, decides, and a
// partial subject set's cookie sees nothing more through a group named
// after its exchange (§B.11.5).
func TestDecidingSubjectsNamedV075(t *testing.T) {
	t.Parallel()
	w := setup(t)
	w.startEdge()
	zed := w.caller("user:zed", "fan-club", "interns")
	_, cks := w.exchange(zed, nil, "")
	old := cks[0]

	// rumours' $access now names interns: zed's new subject set keeps it.
	w.patch("cat", "rumours", map[string]any{"op": "add", "path": "/$access/group:interns", "value": toAny("reader")})
	w.caughtUp()
	if gs, want := w.gsFor(zed), grantcheck.SubjectSetID([]string{"group:fan-club", "group:interns"}); gs != want {
		t.Errorf("zed's subject set once $access names interns %s, want %s", gs, want)
	}
	if !w.listsFolder(zed, "rumours") {
		t.Error("zed's grant doesn't see rumours through interns")
	}
	// The old cookie, without interns, sees nothing through it.
	r := w.withCookie("/cat/g/"+gsOf(old.Path+"/")+"/children?of=season", old, nil)
	if r.status != 302 {
		t.Fatalf("old cookie's head pointer: %d %v", r.status, r.body)
	}
	if r = w.withCookie(r.header.Get("Location"), old, nil); r.status != 200 || childNames(r.body) != "matches.derby,matches.shared" {
		t.Errorf("old cookie on season: %d %v", r.status, r.body)
	}

	// A role rule naming a group by a positive test makes it decide.
	ann := w.caller("user:ann", "fan-club", "stewards")
	if gs, want := w.gsFor(ann), grantcheck.SubjectSetID([]string{"group:fan-club", "partial"}); gs != want {
		t.Errorf("ann's subject set %s, want %s", gs, want)
	}
	w.patchMatches(map[string]any{"op": "add", "path": "/roles/steward", "value": map[string]any{"can": toAny("read"),
		"rules": []any{map[string]any{"op": "test", "path": "/principal/groups", "schema": map[string]any{"contains": map[string]any{"const": "stewards"}}}}}})
	if gs, want := w.gsFor(ann), grantcheck.SubjectSetID([]string{"group:fan-club", "group:stewards"}); gs != want {
		t.Errorf("ann's subject set once a rule names stewards %s, want %s", gs, want)
	}
}

// TestPositionalGroupRuleV075 (MUST-4, scenario 79): a role rule testing
// /principal/groups/0 tests a position, so every group of the caller is
// kept, and there is no "partial" (§B.11.5).
func TestPositionalGroupRuleV075(t *testing.T) {
	t.Parallel()
	w := setup(t)
	w.startEdge()
	li := w.caller("user:zed", "interns", "fan-club")
	w.patchMatches(map[string]any{"op": "add", "path": "/roles/fans", "value": map[string]any{"can": toAny("read"),
		"rules": []any{map[string]any{"op": "test", "path": "/principal/groups/0", "value": "fan-club"}}}})
	if gs, want := w.gsFor(li), grantcheck.SubjectSetID([]string{"group:fan-club", "group:interns"}); gs != want {
		t.Errorf("subject set with a positional rule %s, want %s", gs, want)
	}
}
