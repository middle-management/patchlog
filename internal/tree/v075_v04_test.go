package tree_test

import (
	"context"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/middle-management/patchlog/internal/grant"
	"github.com/middle-management/patchlog/internal/grantcheck"
	"github.com/middle-management/patchlog/internal/tree"
)

// profView is scopeView with a profile per checkpoint (tree.Profiler), as
// the catalog's subject sets have, through the sub (§B.11.5): until the
// catalog has a node "gate", a subject set holds "partial", a subject
// standing for one that changes with the checkpoint.
type profView struct {
	scopeView
	svc *atomic.Pointer[tree.Service]
}

// profOf is profView's profile of g.
type profOf struct{ strict bool }

func (p profOf) Subjects(v *grant.Verified) []string {
	subs, _, _ := scopeView{}.Resolve(context.Background(), v)
	if !p.strict {
		subs = append(subs, "partial")
		slices.Sort(subs)
	}
	return subs
}

func (profView) Profile(g *tree.Graph) tree.Profile { return profOf{strict: g.Node("gate") != nil} }

func (pv profView) Resolve(_ context.Context, v *grant.Verified) ([]string, tree.Visibility, error) {
	var subs []string
	pv.svc.Load().View(func(g *tree.Graph, _ map[string]string) { subs = pv.Profile(g).Subjects(v) })
	return subs, pv.ForSubjects(subs), nil
}

// gsOfTree and atOfTree are the gs and at of a listing URL
// /cat/g/{gs}/at/{at}/….
func gsOfTree(loc string) string { return segAfter(loc, "/g/") }
func atOfTree(loc string) string { return segAfter(loc, "/at/") }

func segAfter(loc, sep string) string {
	_, rest, _ := strings.Cut(loc, sep)
	seg, _, _ := strings.Cut(rest, "/")
	return seg
}

// gateView is profView with a profile whose listing subjects hold
// "has:{name}" for each of the nodes gate1 and gate2 the catalog has, as
// a direct entry or a newly named group changes a grant's gs at later
// ats, and which admits every subject set (§B.11.5).
type gateView struct{ profView }

// gateProf is gateView's profile: the gates the catalog has.
type gateProf []string

func (p gateProf) Subjects(v *grant.Verified) []string {
	subs, _, _ := scopeView{}.Resolve(context.Background(), v)
	for _, n := range p {
		subs = append(subs, "has:"+n)
	}
	slices.Sort(subs)
	return subs
}

func (gateView) Profile(g *tree.Graph) tree.Profile {
	var p gateProf
	for _, n := range []string{"gate1", "gate2"} {
		if g.Node(n) != nil {
			p = append(p, n)
		}
	}
	return p
}

func (gv gateView) Resolve(_ context.Context, v *grant.Verified) ([]string, tree.Visibility, error) {
	var subs []string
	gv.svc.Load().View(func(g *tree.Graph, _ map[string]string) { subs = gv.Profile(g).Subjects(v) })
	return subs, gv.ForSubjects(subs), nil
}

// TestRedirectNamesGSWhereListedV075 (MUST-6, §B.11.5): when the
// checkpoint moves between keying a grant (keyAt) and computing its
// listing, the redirect to the at the listing is at names the grant's gs
// there, not the one it had at the at before, and is answered: a head
// pointer's, and a current at's that is no longer current.
func TestRedirectNamesGSWhereListedV075(t *testing.T) {
	t.Parallel()
	p := newP24World(t, "grant", "grant")
	var ptr atomic.Pointer[tree.Service]
	p.start(func(o *tree.Options) { o.RoleView = gateView{profView{svc: &ptr}} })
	ptr.Store(p.x.s)
	bob := p.scoped("user:bob", "root", "season", "matches.derby")
	scopes := []string{"scope:matches.derby", "scope:root", "scope:season"}
	// moveOnce makes the next listing start only once the catalog has the
	// node gate, and the service has caught up with it.
	moveOnce := func(gate string) {
		var once sync.Once
		p.x.s.BeforeListing(func() {
			once.Do(func() {
				must(p.w.CreateDoc(context.Background(), "cat", gate, map[string]any{"title": gate, "parents": parents("root@c0")}))
				p.x.caughtUp("cat")
			})
		})
	}
	at0 := p.x.s.At()

	// A head pointer: keyed as of at0, listed at at1.
	moveOnce("gate1")
	r := p.do("GET", "/cat/children?of=root", bob, "")
	loc := r.header.Get("Location")
	gs1 := grantcheck.SubjectSetID(append([]string{"has:gate1"}, scopes...))
	if r.status != 302 || gsOfTree(loc) != gs1 || atOfTree(loc) == at0 {
		t.Fatalf("head pointer: %d %s, want gs %s at a new at", r.status, loc, gs1)
	}
	if r = p.do("GET", loc, bob, ""); r.status != 200 {
		t.Errorf("following the head pointer: %d %v", r.status, r.body)
	}

	// The current at: keyed as of at1, listed at at2.
	at1 := atOfTree(loc)
	moveOnce("gate2")
	r = p.do("GET", "/cat/g/"+gs1+"/at/"+at1+"/children?of=season", bob, "")
	loc = r.header.Get("Location")
	gs2 := grantcheck.SubjectSetID(append([]string{"has:gate1", "has:gate2"}, scopes...))
	if r.status != 302 || gsOfTree(loc) != gs2 || atOfTree(loc) == at1 {
		t.Fatalf("at1 once at2 is current: %d %s, want gs %s at a new at", r.status, loc, gs2)
	}
	if r = p.do("GET", loc, bob, ""); r.status != 200 {
		t.Errorf("following the redirect: %d %v", r.status, r.body)
	}
	p.x.s.BeforeListing(nil)
}
