package catvis_test

import (
	"reflect"
	"slices"
	"testing"

	"github.com/middle-management/patchlog/internal/catvis"
	"github.com/middle-management/patchlog/internal/grant"
	"github.com/middle-management/patchlog/internal/grantcheck"
)

// §B.11.5 Listing URLs carry the subject set, §B.11.9 gs (v0.78): a
// subject set holds every group: entry of the caller's, deduplicated,
// never "partial", so li and bo, who differ only in group:interns, which
// nothing in the catalog names, have different listing and filtered gs
// (CONFORMANCE Tree-derived access 78). The sub is added only where the
// catalog has direct entries for that user or its own key a sub scope.
func TestV081SvcSubjects(t *testing.T) {
	t.Parallel()
	docs := map[string]any{
		"root":          map[string]any{"parents": []any{}, "$access": acc("group:editors", "reader", "user:al", "reader")},
		"matches.derby": map[string]any{"parents": parents("root")},
	}
	c := seedCatalog(t, matchesDoc(t, `{"reader":{"can":["read"]}}`, ""), docs)
	p := c.Profile()
	if !p.KeepAll || !p.Users["user:al"] || p.SubScoped {
		t.Fatalf("profile %+v", p)
	}
	li := grant.Principal{ID: "user:li", Groups: []string{"editors", "interns", "editors"}}
	bo := grant.Principal{ID: "user:bo", Groups: []string{"editors"}}
	al := grant.Principal{ID: "user:al", Groups: []string{"editors"}}
	for _, x := range []struct {
		pr   grant.Principal
		want []string
	}{
		{li, []string{"group:editors", "group:interns"}},
		{bo, []string{"group:editors"}},
		{al, []string{"group:editors", "user:al"}},
	} {
		subs, dropped := p.Deciding(x.pr)
		if !reflect.DeepEqual(subs, x.want) || dropped {
			t.Errorf("%s: Deciding %v %v", x.pr.ID, subs, dropped)
		}
		if got := catvis.ListingSubjects(p, x.pr); !reflect.DeepEqual(got, x.want) || slices.Contains(got, catvis.Partial) {
			t.Errorf("%s: ListingSubjects %v", x.pr.ID, got)
		}
	}
	if grantcheck.SubjectSetID(catvis.ListingSubjects(p, li)) == grantcheck.SubjectSetID(catvis.ListingSubjects(p, bo)) {
		t.Error("li and bo share a listing gs")
	}
	filtered := func(pr grant.Principal) []string {
		subs, _ := p.Deciding(pr)
		return catvis.FilteredSubjects([][]string{subs}, pr.Groups, "D")
	}
	if got := filtered(li); !reflect.DeepEqual(got, []string{"group:editors", "group:interns", "scope:D"}) {
		t.Errorf("li filtered %v", got)
	}
	if grantcheck.SubjectSetID(filtered(li)) == grantcheck.SubjectSetID(filtered(bo)) {
		t.Error("li and bo share a filtered gs")
	}
	// The sub comes from the deciding lists, which hold it where §B.11.5
	// adds it; their groups and any "partial" in them never count.
	got := catvis.FilteredSubjects([][]string{{"group:other", catvis.Partial, "user:al"}}, []string{"editors"}, "D")
	if !reflect.DeepEqual(got, []string{"group:editors", "scope:D", "user:al"}) {
		t.Errorf("FilteredSubjects %v", got)
	}

	// TDA 69: with reader narrowed by a negative test of interns, li's
	// set, which holds interns, sees nothing, at once.
	neg := `{"reader":{"can":["read"],"rules":[{"not":{"op":"test","path":"/principal/groups","schema":{"contains":{"const":"interns"}}}}]}}`
	cn := seedCatalog(t, matchesDoc(t, neg, ""), docs)
	if v := cn.View(catvis.ListingSubjects(cn.Profile(), li)); v.Node(cn.G.Node("matches.derby")) || v.Node(cn.G.Node("root")) {
		t.Error("li sees through a role that excludes interns")
	}
	if v := cn.View(catvis.ListingSubjects(cn.Profile(), bo)); !v.Node(cn.G.Node("matches.derby")) {
		t.Error("bo doesn't see derby")
	}

	// A sub scope adds the sub only on the catalog's own key, not
	// another key of the content namespace.
	if p := seedCatalog(t, v076V03Matches(t, `[],"sub":"user:.*"`), docs).Profile(); p.SubScoped {
		t.Errorf("another key's sub scope: %+v", p)
	}
	ps := seedCatalog(t, matchesDoc(t, `{"reader":{"can":["read"]}}`, `,"sub":"user:.*"`), docs).Profile()
	if subs, _ := ps.Deciding(bo); !ps.SubScoped || !reflect.DeepEqual(subs, []string{"group:editors", "user:bo"}) {
		t.Errorf("the catalog key's sub scope: %+v %v", ps, subs)
	}
}
