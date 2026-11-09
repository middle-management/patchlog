package catalog_test

import (
	"strings"
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

// atOf is the at of a listing URL /cat/g/{gs}/at/{at}/….
func atOf(loc string) string {
	_, rest, _ := strings.Cut(loc, "/at/")
	at, _, _ := strings.Cut(rest, "/")
	return at
}

// TestPartialRefusedWhereGroupsKeptV075 (MUST-5, SVC-2, scenario 78): a
// subject set that left out a group is 403 at an at where every group is
// kept, its head pointer included, until the reader exchanges again; at
// the at it was keyed at it still reads, and the new exchange's set holds
// every group, so it is denied what the new rule denies (§B.11.5).
func TestPartialRefusedWhereGroupsKeptV075(t *testing.T) {
	t.Parallel()
	w := setup(t)
	w.startEdge()
	li := w.caller("user:zed", "fan-club", "contractors")
	r, cks := w.exchange(li, nil, "")
	if r.status != 200 || len(cks) != 1 {
		t.Fatalf("exchange: %d %v", r.status, r.body)
	}
	ck := cks[0]
	old := gsOf(ck.Path + "/")
	if old != grantcheck.SubjectSetID([]string{"group:fan-club", "partial"}) {
		t.Fatalf("li's subject set %s doesn't leave out contractors", old)
	}
	r = w.withCookie("/cat/g/"+old+"/children?of=season", ck, nil)
	if r.status != 302 {
		t.Fatalf("head pointer: %d %v", r.status, r.body)
	}
	at1 := r.header.Get("Location")
	if r = w.withCookie(at1, ck, nil); r.status != 200 || childNames(r.body) != "matches.derby,matches.shared" {
		t.Fatalf("li's cookie on season: %d %v", r.status, r.body)
	}

	// reader now tests the groups negatively: every group is kept.
	w.patchMatches(map[string]any{"op": "add", "path": "/roles/reader/rules", "value": []any{notContractors}})
	r = w.withCookie("/cat/g/"+old+"/children?of=season", ck, nil)
	if r.status != 403 || r.header.Get("Cache-Control") != "no-store" {
		t.Errorf("old cookie's head pointer once groups are kept: %d %q %v", r.status, r.header.Get("Cache-Control"), r.body)
	}
	// At the current at too.
	fresh := w.caller("user:fred", "fan-club")
	_, loc := w.follow("/cat/children?of=season", fresh)
	cur := atOf(loc)
	if cur == atOf(at1) {
		t.Fatal("the at didn't move")
	}
	r = w.withCookie("/cat/g/"+old+"/at/"+cur+"/children?of=season", ck, nil)
	if r.status != 403 || r.header.Get("Cache-Control") != "no-store" {
		t.Errorf("old cookie at the new at: %d %q %v", r.status, r.header.Get("Cache-Control"), r.body)
	}
	// The at it was keyed at still reads, from its kept listing.
	if r = w.withCookie(at1, ck, nil); r.status != 200 {
		t.Errorf("old cookie at its at: %d %v", r.status, r.body)
	}
	// Exchanged again, li's set keeps contractors, and reader denies her
	// season.
	if gs, want := w.gsFor(li), grantcheck.SubjectSetID([]string{"group:contractors", "group:fan-club"}); gs != want {
		t.Errorf("li's new subject set %s, want %s", gs, want)
	}
	if w.listsFolder(li, "season") {
		t.Error("li sees season, which reader now denies contractors")
	}
	// fred's grant has no group left out: he reads on.
	if !w.listsFolder(fresh, "season") {
		t.Error("fred lost season")
	}
}

// notContractors is a rule that tests /principal/groups negatively
// (§B.11.5).
var notContractors = map[string]any{"not": map[string]any{"op": "test", "path": "/principal/groups",
	"schema": map[string]any{"contains": map[string]any{"const": "contractors"}}}}

// TestGrantReadsAtItsOwnGSV075 (MUST-6, SVC-3): a grant in Authorization
// reads at its own gs as of the URL's at: a listing kept at an older at
// under the gs the grant had there is still its own once a direct entry
// for its sub puts its sub in its gs at later ones (§B.11.5).
func TestGrantReadsAtItsOwnGSV075(t *testing.T) {
	t.Parallel()
	w := setup(t)
	w.seed()
	w.start()
	w.caughtUp()
	zed := w.caller("user:zed", "fan-club")
	r, loc1 := w.follow("/cat/children?of=season", zed)
	if r.status != 200 || gsOf(loc1) != grantcheck.SubjectSetID([]string{"group:fan-club"}) {
		t.Fatalf("zed at at1: %d %s %v", r.status, loc1, r.body)
	}
	// derbies gets a direct entry for zed: his sub decides from now on.
	w.patch("cat", "derbies", map[string]any{"op": "add", "path": "/$access/user:zed", "value": toAny("reader")})
	w.caughtUp()
	_, loc2 := w.follow("/cat/children?of=season", zed)
	if gsOf(loc2) != grantcheck.SubjectSetID([]string{"group:fan-club", "user:zed"}) || atOf(loc2) == atOf(loc1) {
		t.Fatalf("zed at at2: %s", loc2)
	}
	// At at1, his gs is still the one he had there.
	if r = w.do("GET", loc1, zed, nil); r.status != 200 || childNames(r.body) != "matches.derby,matches.shared" {
		t.Errorf("zed's grant at its gs of at1: %d %v", r.status, r.body)
	}
	// And not at2's there, nor at1's at at2.
	if r = w.do("GET", strings.Replace(loc1, gsOf(loc1), gsOf(loc2), 1), zed, nil); r.status != 403 {
		t.Errorf("zed's grant at at2's gs at at1: %d %v", r.status, r.body)
	}
	if r = w.do("GET", strings.Replace(loc2, gsOf(loc2), gsOf(loc1), 1), zed, nil); r.status != 403 {
		t.Errorf("zed's grant at at1's gs at at2: %d %v", r.status, r.body)
	}
}
