package catvis_test

import (
	"reflect"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/catvis"
	"github.com/middle-management/patchlog/internal/grantcheck"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/tree"
)

func parse(s string) map[string]any { return jsonv.MustParse([]byte(s)).(map[string]any) }

func parents(names ...string) []any {
	out := []any{}
	for _, n := range names {
		out = append(out, map[string]any{"href": "/r/cat/" + n})
	}
	return out
}

func acc(kv ...string) map[string]any {
	m := map[string]any{}
	for i := 0; i < len(kv); i += 2 {
		if kv[i+1] == "false" {
			m[kv[i]] = false
			continue
		}
		var rs []any
		for _, r := range strings.Split(kv[i+1], ",") {
			rs = append(rs, r)
		}
		m[kv[i]] = rs
	}
	return m
}

// seedDocs are the catalog service tests' seed (internal/catalog):
//
//	root
//	├── season   $access: match-desk desk, translators translator, fan-club reader, user:li reader
//	│   ├── matches.derby
//	│   ├── matches.shared      (also under derbies)
//	│   └── rumours  $access: inherit false, editors-in-chief desk
//	│       └── matches.rumour1
//	└── derbies  $access: match-desk desk, fan-club desk
//	    ├── matches.shared
//	    └── matches.other       $access (placement): user:guest reader
func seedDocs() map[string]any {
	return map[string]any{
		"root":   map[string]any{"title": "Root", "parents": []any{}},
		"season": map[string]any{"parents": parents("root"), "$access": acc("group:match-desk", "desk", "group:translators", "translator", "group:fan-club", "reader", "user:li", "reader")},
		"rumours": map[string]any{"parents": parents("season"),
			"$access": acc("inherit", "false", "group:editors-in-chief", "desk")},
		"derbies":         map[string]any{"parents": parents("root"), "$access": acc("group:match-desk", "desk", "group:fan-club", "desk")},
		"matches.derby":   map[string]any{"parents": parents("season")},
		"matches.shared":  map[string]any{"parents": parents("season", "derbies")},
		"matches.rumour1": map[string]any{"parents": parents("rumours")},
		"matches.other":   map[string]any{"parents": parents("derbies"), "$access": acc("user:guest", "reader")},
	}
}

var catConfig = map[string]any{"read": "grant", "catalog": map[string]any{"trust": []any{"matches"}, "mode": "dag"}}

// matchesDoc is matches's document, with the catalog's key catalog-01
// (as in internal/catalog's tests) and extra appended to its keys.
func matchesDoc(t *testing.T, roles string, keyExtra string) *grantcheck.Config {
	t.Helper()
	if roles == "" {
		roles = `{"desk":{"can":["read","create","append","restore"]},
			"translator":{"can":["read","append"],"rules":[{"op":"writes","within":["/i18n"]}]},
			"reader":{"can":["read"]},"deleter":{"can":["delete"]}}`
	}
	doc := parse(`{"read":"grant","roles":` + roles + `,
		"keys":[{"kid":"catalog-01","alg":"Ed25519","pub":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
			"can":["read","create","append","restore"],"maxTtl":"PT15M","readScope":"resource","requireAt":"cat",
			"groups":{"deny":["ops"]},"roles":{"allow":["desk","translator","reader"]}` + keyExtra + `}],
		"catalogs":{"cat":{"place":["group:match-desk"]}}}`)
	cfg, err := grantcheck.ParseConfig("matches", "", doc)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func seedCatalog(t *testing.T, cfg *grantcheck.Config, docs map[string]any, kids ...string) *catvis.Catalog {
	t.Helper()
	if len(kids) == 0 {
		kids = []string{"catalog-01"}
	}
	g := tree.BuildGraph("cat", catConfig, docs)
	return catvis.NewCatalog(g, map[string]*catvis.Content{"matches": {NS: "matches", Cfg: cfg, Kids: kids}})
}

func visibleNodes(c *catvis.Catalog, subjects ...string) []string {
	v := c.View(subjects)
	var out []string
	for _, name := range c.G.Names() {
		if v.Node(c.G.Node(name)) {
			out = append(out, name)
		}
	}
	return out
}

// §B.11.5 item and folder visibility, as the catalog service's tests
// judge the seed (internal/catalog, v074 and earlier), with the catalog's
// key as the one kid.
func TestV075ItemAndFolderVisibility(t *testing.T) {
	t.Parallel()
	c := seedCatalog(t, matchesDoc(t, "", ""), seedDocs())
	for _, tc := range []struct {
		subjects []string
		want     []string
	}{
		// fan-club: reader at season, desk at derbies; rumours stops the walk.
		{[]string{"group:fan-club"}, []string{"derbies", "matches.derby", "matches.other", "matches.shared", "season"}},
		{[]string{"group:editors-in-chief"}, []string{"matches.rumour1", "rumours"}},
		// translator lists read, and its writes rule passes a read.
		{[]string{"group:translators"}, []string{"matches.derby", "matches.shared", "season"}},
		{[]string{"user:guest"}, []string{"matches.other"}},
		{[]string{"user:li"}, []string{"matches.derby", "matches.shared", "season"}},
		// ops is denied by the key's groups scope.
		{[]string{"group:ops"}, nil},
		// partial and scope: subjects are ignored.
		{[]string{"partial", "scope:x", "user:guest"}, []string{"matches.other"}},
		{nil, nil},
	} {
		if got := visibleNodes(c, tc.subjects...); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%v: visible %v, want %v", tc.subjects, got, tc.want)
		}
	}
	v := c.View([]string{"group:fan-club"})
	if !v.Placement("matches", "derby") || v.Placement("matches", "rumour1") || v.Placement("matches", "never") {
		t.Error("Placement")
	}
}

// §B.11.5: a role whose rule refers to /resource counts for items only,
// with /resource the item's name; a rule on /now or /principal/sub makes
// it not count; a key rule on anything but /principal/groups and roles
// stops folders counting through the key.
func TestV075RoleRules(t *testing.T) {
	t.Parallel()
	byName := `{"reader":{"can":["read"],"rules":[{"op":"test","path":"/resource","value":"derby"}]}}`
	c := seedCatalog(t, matchesDoc(t, byName, ""), seedDocs())
	if got := visibleNodes(c, "user:li"); !reflect.DeepEqual(got, []string{"matches.derby"}) {
		t.Errorf("by name: %v", got)
	}
	for _, r := range []string{`{"op":"test","path":"/now","exists":true}`, `{"op":"test","path":"/principal/id","value":"user:li"}`} {
		c := seedCatalog(t, matchesDoc(t, `{"reader":{"can":["read"],"rules":[`+r+`]}}`, ""), seedDocs())
		if got := visibleNodes(c, "user:li"); got != nil {
			t.Errorf("rule %s: %v", r, got)
		}
	}
	c = seedCatalog(t, matchesDoc(t, "", `,"rules":[{"op":"test","path":"/resource","schema":{"type":"string"}}]`), seedDocs())
	if got := visibleNodes(c, "user:li"); !reflect.DeepEqual(got, []string{"matches.derby", "matches.shared"}) {
		t.Errorf("key rule on /resource: %v", got)
	}
	// A sub scope: li matches, a set without a user: subject doesn't.
	c = seedCatalog(t, matchesDoc(t, "", `,"sub":"user:l.*"`), seedDocs())
	if got := visibleNodes(c, "user:li"); len(got) != 3 {
		t.Errorf("sub scope, li: %v", got)
	}
	if got := visibleNodes(c, "group:fan-club"); got != nil {
		t.Errorf("sub scope, no user: %v", got)
	}
}

// §B.11.9 Where: a role counts through any key of the content namespace
// whose requireAt names the catalog.
func TestV075KidSet(t *testing.T) {
	t.Parallel()
	doc := parse(`{"roles":{"reader":{"can":["read"]}},"keys":[
		{"kid":"k1","alg":"Ed25519","pub":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo","can":["read"],"requireAt":"cat","groups":{"deny":["fan-club"]}},
		{"kid":"k2","alg":"Ed25519","pub":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo","can":["read"],"requireAt":"cat"}]}`)
	cfg, err := grantcheck.ParseConfig("matches", "", doc)
	if err != nil {
		t.Fatal(err)
	}
	if got := visibleNodes(seedCatalog(t, cfg, seedDocs(), "k1"), "group:fan-club"); got != nil {
		t.Errorf("k1 alone: %v", got)
	}
	if got := visibleNodes(seedCatalog(t, cfg, seedDocs(), "k1", "k2"), "group:fan-club"); len(got) != 3 {
		t.Errorf("k1 and k2: %v", got)
	}
	// No kid: nothing counts.
	if got := visibleNodes(seedCatalog(t, cfg, seedDocs(), "k3"), "group:fan-club"); got != nil {
		t.Errorf("unknown kid: %v", got)
	}
}

// §B.11.4, §B.11.5 Organising, §B.11.9 Deleted resources: AsIfLive
// judges a dangling placement as if its item were live, from roles
// computed from the graph, and a node detached from the graph (a deleted
// node's last live document) from its own parents. Cyclic nodes stay
// hidden.
func TestV075AsIfLive(t *testing.T) {
	t.Parallel()
	docs := seedDocs()
	docs["loop-a"] = map[string]any{"parents": parents("loop-b"), "$access": acc("group:fan-club", "reader")}
	docs["loop-b"] = map[string]any{"parents": parents("loop-a")}
	docs["matches.inloop"] = map[string]any{"parents": parents("loop-a")}
	c := seedCatalog(t, matchesDoc(t, "", ""), docs)
	v := c.View([]string{"group:fan-club"})
	gone := tree.ParseNode("cat", "matches.gone", "", map[string]any{"parents": parents("season")})
	if v.Node(gone) || !v.AsIfLive(gone) {
		t.Errorf("detached placement: Node %v AsIfLive %v", v.Node(gone), v.AsIfLive(gone))
	}
	hidden := tree.ParseNode("cat", "matches.gone", "", map[string]any{"parents": parents("rumours")})
	if v.AsIfLive(hidden) {
		t.Error("detached placement under rumours")
	}
	folder := tree.ParseNode("cat", "oldfolder", "", map[string]any{"parents": parents("season")})
	if !v.AsIfLive(folder) {
		t.Error("detached folder under season")
	}
	if v.AsIfLive(c.G.Node("loop-a")) || v.Placement("matches", "inloop") {
		t.Error("cyclic node visible")
	}
	if got := catvis.EffectiveOf(c.G, gone); !reflect.DeepEqual(got["group:fan-club"], []string{"reader"}) {
		t.Errorf("EffectiveOf: %v", got)
	}
	if got, want := catvis.EffectiveOf(c.G, c.G.Node("matches.derby")), catvis.Effective(c.G, "matches.derby", nil); !reflect.DeepEqual(got, want) {
		t.Errorf("EffectiveOf of a graph node: %v, want %v", got, want)
	}
	// An untrusted namespace's placement is never visible.
	if v.AsIfLive(tree.ParseNode("cat", "other.x", "", map[string]any{"parents": parents("season")})) {
		t.Error("untrusted namespace")
	}
}

// §B.11.9 gs: FilteredSubjects.
func TestV075FilteredSubjects(t *testing.T) {
	t.Parallel()
	// Every group counts, never "partial" (v0.78; TestV081SvcSubjects).
	if got := catvis.FilteredSubjects([][]string{{"group:editors"}}, []string{"editors", "interns"}, "D"); !reflect.DeepEqual(got, []string{"group:editors", "group:interns", "scope:D"}) {
		t.Errorf("every group: %v", got)
	}
	got := catvis.FilteredSubjects([][]string{{"group:editors"}, {"group:interns", "user:li"}}, []string{"editors", "interns"}, "D")
	if !reflect.DeepEqual(got, []string{"group:editors", "group:interns", "scope:D", "user:li"}) {
		t.Errorf("joint: %v", got)
	}
}

// §B.11.9 Where: TrustedCatalogs.
func TestV075TrustedCatalogs(t *testing.T) {
	t.Parallel()
	ns := parse(`{"catalogs":{"cat-season":{},"cat-other":{},"cat-nokey":{},"cat-gone":{}},"keys":[
		{"kid":"catalog-01","requireAt":"cat-season"},{"kid":"catalog-02","requireAt":"cat-season"},
		{"kid":"other","requireAt":"cat-other"},{"kid":"gone","requireAt":"cat-gone"},{"kid":"plain","requireAt":true}]}`)
	docs := map[string]map[string]any{
		"cat-season": parse(`{"catalog":{"trust":["matches"]}}`),
		"cat-other":  parse(`{"catalog":{"trust":["elsewhere"]}}`),
		"cat-nokey":  parse(`{"catalog":{"trust":["matches"]}}`),
	}
	got := catvis.TrustedCatalogs("matches", ns, func(cat string) map[string]any { return docs[cat] })
	want := []catvis.Trust{{Catalog: "cat-season", Kids: []string{"catalog-01", "catalog-02"}}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("TrustedCatalogs %+v", got)
	}
}

// §B.11.9 Deleted resources: a tombstoned node is judged by its last live
// document, its own $access included, so the users only that $access
// names keep deciding (Profile.Users) and Deleted returns the node.
func TestV075ProfileOfDeletedNodes(t *testing.T) {
	t.Parallel()
	docs := map[string]any{
		"root":          map[string]any{"parents": []any{}, "$access": acc("group:editors", "reader")},
		"matches.derby": map[string]any{"parents": parents("root")},
	}
	g := tree.BuildGraph("cat", catConfig, docs)
	audit := tree.ParseNode("cat", "audit", "", map[string]any{"parents": parents("root"),
		"$access": acc("group:auditors", "reader", "user:bo", "reader")})
	// A node of the graph passed as deleted is ignored.
	derby := tree.ParseNode("cat", "matches.derby", "", map[string]any{"parents": parents("root"), "$access": acc("group:x", "reader")})
	contents := map[string]*catvis.Content{"matches": {NS: "matches", Cfg: matchesDoc(t, `{"reader":{"can":["read"]}}`, ""), Kids: []string{"catalog-01"}}}
	c := catvis.NewCatalogDeleted(g, contents, []*tree.Node{audit, derby})
	p := c.Profile()
	if !p.Users["user:bo"] {
		t.Fatalf("profile %+v", p)
	}
	if c.Deleted("audit") != audit || c.Deleted("matches.derby") != nil || c.Deleted("root") != nil {
		t.Fatal("Deleted")
	}
	if !c.View([]string{"group:auditors"}).AsIfLive(c.Deleted("audit")) {
		t.Error("the deleted node, as if live, to auditors")
	}
	// Without it, the user decides nothing.
	if p := catvis.NewCatalog(g, contents).Profile(); p.Users["user:bo"] {
		t.Errorf("profile without deleted nodes %+v", p)
	}
}
