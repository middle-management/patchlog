package catalog_test

import (
	"context"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/catvis"
	"github.com/middle-management/patchlog/internal/edge"
	"github.com/middle-management/patchlog/internal/grant"
	"github.com/middle-management/patchlog/internal/grantcheck"
	"github.com/middle-management/patchlog/internal/tree"
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

// TestVisibilityIsCatvisV075 (VIS-4): the service's listings show what
// catvis's node test, which the origin's filtered reads use (§B.11.9),
// shows a subject set over a graph built from the same documents, with
// the catalog's key as the content namespace's only kid (§B.11.5): one
// implementation, so they can't drift.
func TestVisibilityIsCatvisV075(t *testing.T) {
	t.Parallel()
	w := setup(t)
	w.seed()
	w.start()
	w.caughtUp()
	// A role whose rule tests the groups positively, and one reading the
	// resource: the folder and item rules of the node test.
	w.patchMatches(map[string]any{"op": "add", "path": "/roles/steward", "value": map[string]any{"can": toAny("read"),
		"rules": []any{map[string]any{"op": "test", "path": "/principal/groups", "schema": map[string]any{"contains": map[string]any{"const": "stewards"}}}}}},
		map[string]any{"op": "add", "path": "/roles/derbyonly", "value": map[string]any{"can": toAny("read"),
			"rules": []any{map[string]any{"op": "test", "path": "/resource", "value": "derby"}}}})
	w.patch("cat", "derbies", map[string]any{"op": "add", "path": "/$access/group:stewards", "value": toAny("steward")})
	w.patch("cat", "rumours", map[string]any{"op": "add", "path": "/$access/group:fan-club", "value": toAny("derbyonly")})
	w.caughtUp()

	ctx := context.Background()
	nsDoc := func(ns string) map[string]any {
		return must(w.ops.NSDoc(ctx, ns, must(w.ops.NSHead(ctx, ns)).ID)).Value
	}
	folders := []string{"root", "season", "rumours", "derbies"}
	docs := map[string]any{}
	for _, name := range append(slices.Clone(folders), "matches.derby", "matches.shared", "matches.rumour1", "matches.other") {
		docs[name] = must(w.ops.Doc(ctx, "cat", name, must(w.ops.Head(ctx, "cat", name)).ID)).Value
	}
	g := tree.BuildGraph("cat", nsDoc("cat"), docs)
	cfg := must(grantcheck.ParseConfig("matches", "", nsDoc("matches")))
	c := catvis.NewCatalog(g, map[string]*catvis.Content{"matches": {NS: "matches", Cfg: cfg, Kids: []string{"catalog-01"}}})

	shown := 0
	for _, who := range []struct {
		sub    string
		groups []string
	}{
		{"user:fred", []string{"fan-club"}}, {"user:li", nil}, {"user:guest", nil}, {"user:eve", []string{"editors-in-chief"}},
		{"user:sam", []string{"stewards", "interns"}}, {"user:md", []string{"match-desk", "translators"}}, {"user:x", []string{"ops", "fan-club"}},
	} {
		token := w.caller(who.sub, who.groups...)
		v := c.View(catvis.ListingSubjects(c.Profile(), grant.Principal{ID: who.sub, Groups: who.groups}))
		for _, f := range folders {
			want := "404"
			if v.Node(g.Node(f)) {
				var kids []string
				for _, name := range g.Names() {
					n := g.Node(name)
					if v.Node(n) && slices.ContainsFunc(n.Parents, func(p tree.Parent) bool { return p.Name == f }) {
						kids = append(kids, name)
					}
				}
				want = strings.Join(kids, ",")
			}
			r, _ := w.follow("/cat/children?of="+f, token)
			got := strconv.Itoa(r.status)
			if r.status == 200 {
				got = childNames(r.body)
			}
			if got != want {
				t.Errorf("%s %v, children of %s: service %q, catvis %q", who.sub, who.groups, f, got, want)
			}
			if want != "404" && want != "" {
				shown++
			}
		}
	}
	if shown < 6 {
		t.Errorf("only %d listings show anything", shown)
	}
}

// TestGrantReadsAtItsOwnGSSealedV075 (MUST-6, SVC-3): in a sealed catalog,
// a listing served from the sealed store and kept again is recorded again
// with its at's profile, so a grant still reads it at its own gs as of
// that at once the at moves on, after its first record has expired and
// after a restart, where no record outlasts the service (§B.11.5).
func TestGrantReadsAtItsOwnGSSealedV075(t *testing.T) {
	for _, restart := range []bool{false, true} {
		t.Run("restart="+strconv.FormatBool(restart), func(t *testing.T) {
			t.Parallel()
			w := setupWith(t, true)
			w.seed()
			w.start()
			w.caughtUp()
			zed := w.caller("user:zed", "fan-club")
			r, loc1 := w.follow("/cat/children?of=season", zed)
			if r.status != 200 || gsOf(loc1) != grantcheck.SubjectSetID([]string{"group:fan-club"}) {
				t.Fatalf("zed at at1: %d %s %v", r.status, loc1, r.body)
			}
			if restart {
				w.stop()
				w.start()
				w.caughtUp()
			} else {
				// The kept listing and its at's record expire; the
				// sealed one stays stored at the current at.
				w.s.Clock.Advance(61 * time.Second)
			}
			zed = w.caller("user:zed", "fan-club")
			// at1 is still current: its listing comes from the sealed
			// store, and is kept again.
			if r, loc := w.follow("/cat/children?of=season", zed); r.status != 200 || loc != loc1 {
				t.Fatalf("zed at at1 again: %d %s %v", r.status, loc, r.body)
			}
			// derbies gets a direct entry for zed: his sub decides from
			// now on.
			w.patch("cat", "derbies", map[string]any{"op": "add", "path": "/$access/user:zed", "value": toAny("reader")})
			w.caughtUp()
			_, loc2 := w.follow("/cat/children?of=season", zed)
			if gsOf(loc2) != grantcheck.SubjectSetID([]string{"group:fan-club", "user:zed"}) || atOf(loc2) == atOf(loc1) {
				t.Fatalf("zed at at2: %s", loc2)
			}
			if r = w.do("GET", loc1, zed, nil); r.status != 200 || childNames(r.body) != "matches.derby,matches.shared" {
				t.Errorf("zed's grant at its gs of at1, kept again: %d %v", r.status, r.body)
			}
			if r = w.do("GET", strings.Replace(loc1, gsOf(loc1), gsOf(loc2), 1), zed, nil); r.status != 403 {
				t.Errorf("zed's grant at at2's gs at at1: %d %v", r.status, r.body)
			}
		})
	}
}
