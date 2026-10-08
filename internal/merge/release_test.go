package merge_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/catalog"
	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/follow"
	"github.com/middle-management/patchlog/internal/grant"
	"github.com/middle-management/patchlog/internal/janitor"
	"github.com/middle-management/patchlog/internal/merge"
	"github.com/middle-management/patchlog/internal/release"
	"github.com/middle-management/patchlog/internal/tree"
)

// Releases across namespaces (§F.9), end to end: schemas, matches and the
// catalog cat-season, each with a release branch, and a releases
// namespace holding release documents and the merge's stored plans.

const dialect = "https://json-schema.org/draft/2020-12/schema"

func sAny(xs ...string) []any {
	out := make([]any, len(xs))
	for i, x := range xs {
		out[i] = x
	}
	return out
}

func parentsOf(ps ...string) []any {
	out := []any{}
	for _, p := range ps {
		out = append(out, map[string]any{"href": "/r/cat-season/" + p})
	}
	return out
}

type relWorld struct {
	t      *testing.T
	s      *clienttest.Server
	ops    *client.Client // "*" key everywhere
	anna   *client.Client // the editor who merges (idp key, catalog-admins)
	idp    clienttest.Key
	opsKey clienttest.Key
	catKey clienttest.Key
	// mergeKey is the catalog service's merge key (§F.8), used for
	// nothing else.
	mergeKey clienttest.Key
	svc      *catalog.Service
	svcURL   string
	// T0 is the base revision of /r/schemas/match.
	T0 string
}

// every namespace a test grant names: the bases, the releases namespace,
// and the branches the tests create.
var relNS = []string{"schemas", "matches", "cat-season", "releases",
	"schemas-r7", "matches-r7", "cat-season-r7", "schemas-x", "cat-season-r8",
	"schemas-r7-b", "matches-r7-b", "cat-season-r7-b"}

func matchSchema(extra ...string) map[string]any {
	props := map[string]any{"home": map[string]any{"type": "string"}, "away": map[string]any{"type": "string"}}
	for _, e := range extra {
		props[e] = map[string]any{"type": "string"}
	}
	return map[string]any{"$schema": dialect, "type": "object", "properties": props, "required": sAny("home", "away")}
}

func newRelWorld(t *testing.T) *relWorld {
	s := clienttest.New(t, clienttest.Options{Auth: true, LongPoll: 100 * time.Millisecond})
	w := &relWorld{t: t, s: s, idp: clienttest.NewKey("idp"), opsKey: clienttest.NewKey("ops"), catKey: clienttest.NewKey("catalog-01"),
		mergeKey: clienttest.NewKey("catalog-merge")}
	authors := func(kid string) map[string]any {
		return map[string]any{"authors": []any{map[string]any{"sub": "user:anna", "kid": kid}}}
	}
	cleanup := map[string]any{"merged": "PT0S", "superseded": "PT0S", "abandoned": "PT0S"}
	mk := func(ns string, doc map[string]any) {
		doc["read"] = "grant"
		keys := []any{w.opsKey.Entry("*"), w.idp.Entry("read", "create", "append", "delete", "restore", "config", "branch", "purge-ns", "purge")}
		if ns == "cat-season" {
			ce := w.catKey.Entry("read", "create", "append", "delete", "restore")
			ce["maxTtl"] = "PT15M"
			ce["requireAt"] = true
			me := w.mergeKey.Entry("create", "append", "delete", "restore")
			me["maxTtl"] = "PT10M"
			me["requireAt"] = true
			keys = append(keys, ce, me)
		}
		doc["keys"] = keys
		must(s.Client(t, client.WithBearer(s.OperatorGrant(t, ns))).CreateNamespace(ctx, ns, doc))
	}
	mk("schemas", map[string]any{"merge": authors("idp"), "cleanup": cleanup})
	mk("matches", map[string]any{"merge": authors("idp"), "cleanup": cleanup,
		"roles":    map[string]any{"desk": map[string]any{"can": sAny("read", "create", "append")}, "reader": map[string]any{"can": sAny("read")}},
		"catalogs": map[string]any{"cat-season": map[string]any{"place": sAny("group:match-desk")}}})
	// The catalog's merge batches: the merge service under the merge key,
	// or a catalog admin for $access changes (§F.8, §F.9).
	catAuthors := map[string]any{"authors": []any{map[string]any{"sub": "svc:merge", "kid": "catalog-merge"}, map[string]any{"sub": "user:anna", "kid": "idp"}}}
	mk("cat-season", map[string]any{"merge": catAuthors, "cleanup": cleanup,
		"catalog": map[string]any{"trust": sAny("matches"), "mode": "dag"},
		"roles":   map[string]any{"desk": map[string]any{"move": true, "place": true}, "reader": map[string]any{}}})
	mk("releases", map[string]any{})
	all := []string{"read", "create", "append", "delete", "restore", "config", "branch", "purge-ns", "purge"}
	long := map[string]any{"exp": s.Now().Add(24 * time.Hour).Format(time.RFC3339)}
	w.ops = s.Client(t, client.WithBearer(w.opsKey.Grant(t, s.Now(), "user:ops", relNS, all, long)))
	w.anna = s.Client(t, client.WithBearer(w.idp.Grant(t, s.Now(), "user:anna", relNS, all,
		map[string]any{"groups": sAny("match-desk", "catalog-admins"), "exp": s.Now().Add(24 * time.Hour).Format(time.RFC3339)})))

	// The bases.
	w.T0 = must(w.ops.CreateDoc(ctx, "schemas", "match", matchSchema())).ID
	m := "/r/schemas/match/rev/" + w.T0
	must(w.ops.CreateDoc(ctx, "matches", "derby", map[string]any{"$schema": m, "home": "A", "away": "B"}))
	must(w.ops.CreateDoc(ctx, "matches", "cup", map[string]any{"$schema": m, "home": "C", "away": "D"}))
	must(w.ops.CreateDoc(ctx, "cat-season", "root", map[string]any{"title": "Root",
		"$access": map[string]any{"group:fans": sAny("reader"), "group:match-desk": sAny("desk")}}))
	must(w.ops.CreateDoc(ctx, "cat-season", "season", map[string]any{"title": "Season", "parents": parentsOf("root"),
		"$access": map[string]any{"group:match-desk": sAny("desk")}}))
	must(w.ops.CreateDoc(ctx, "cat-season", "vault", map[string]any{"title": "Vault", "parents": parentsOf("root"),
		"$access": map[string]any{"inherit": false, "group:match-desk": sAny("desk")}}))
	must(w.ops.CreateDoc(ctx, "cat-season", "embargo", map[string]any{"title": "Embargo", "parents": parentsOf("root"),
		"$access": map[string]any{"inherit": false, "group:editors": sAny("reader"), "group:match-desk": sAny("desk")}}))
	must(w.ops.CreateDoc(ctx, "cat-season", "matches.derby", map[string]any{"parents": parentsOf("season")}))
	must(w.ops.CreateDoc(ctx, "cat-season", "matches.cup", map[string]any{"parents": parentsOf("season")}))
	return w
}

// startCatalog runs the catalog service of cat-season (§B.11, §F.8).
func (w *relWorld) startCatalog() {
	t := w.t
	svcClient := w.s.Client(t, client.WithBearer(w.opsKey.Grant(t, w.s.Now(), "svc:catalog", []string{"cat-season", "matches"}, []string{"read"},
		map[string]any{"exp": w.s.Now().Add(24 * time.Hour).Format(time.RFC3339)})))
	svc, err := catalog.Open(ctx, catalog.Options{
		Tree: tree.Options{Client: svcClient, Catalog: "cat-season", DB: filepath.Join(t.TempDir(), "cat.db"), Now: w.s.Now, CheckerTTL: time.Millisecond,
			Logf:          func(string, ...any) {},
			FollowOptions: []follow.Option{follow.WithBackoff(time.Millisecond, 20*time.Millisecond)}},
		Key: w.catKey.Priv, Kid: "catalog-01",
		MergeKey: w.mergeKey.Priv, MergeKid: "catalog-merge", MergeService: "svc:merge",
	})
	if err != nil {
		t.Fatal(err)
	}
	w.svc = svc
	hs := httptest.NewServer(svc.Handler())
	w.svcURL = hs.URL
	cctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { svc.Run(cctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done; hs.Close(); svc.Close() })
}

func (w *relWorld) granter() merge.MergeGranter {
	return &merge.HTTPGranter{URLs: map[string]string{"cat-season": w.svcURL}, Bearer: w.mergeBearer(), Approver: w.annaBearer()}
}

// mergeBearer is the merge service's identity grant for the catalog.
func (w *relWorld) mergeBearer() string {
	return w.opsKey.Grant(w.t, w.s.Now(), "svc:merge", []string{"cat-season"}, []string{"read"},
		map[string]any{"exp": w.s.Now().Add(24 * time.Hour).Format(time.RFC3339)})
}

// annaAll is anna's grant with every verb: a catalog admin's, under which
// the merge service submits $access changes (§F.8).
func (w *relWorld) annaAll() string {
	return w.idp.Grant(w.t, w.s.Now(), "user:anna", relNS, []string{"read", "create", "append", "delete", "restore", "config", "branch", "purge-ns", "purge"},
		map[string]any{"groups": sAny("match-desk", "catalog-admins"), "exp": w.s.Now().Add(24 * time.Hour).Format(time.RFC3339)})
}

func (w *relWorld) annaBearer() string {
	return w.idp.Grant(w.t, w.s.Now(), "user:anna", relNS, []string{"read"},
		map[string]any{"groups": sAny("match-desk", "catalog-admins"), "exp": w.s.Now().Add(24 * time.Hour).Format(time.RFC3339)})
}

func (w *relWorld) branch(base, name string, patches ...map[string]any) {
	w.t.Helper()
	br := client.BranchRequest{Name: name}
	if len(patches) > 0 {
		br.Patches = ops(patches...)
	}
	must(w.anna.CreateBranch(ctx, base, br))
}

func (w *relWorld) doc(ns, name string) map[string]any {
	w.t.Helper()
	h, d, err := w.anna.Load(ctx, ns, name)
	if err != nil {
		w.t.Fatalf("%s/%s: %v", ns, name, err)
	}
	if h.State != client.Live {
		return nil
	}
	m, _ := d.Value.(map[string]any)
	return m
}

func (w *relWorld) live(ns, name string) bool {
	h, err := w.anna.Head(ctx, ns, name)
	return err == nil && h.State == client.Live
}

func (w *relWorld) appendTo(ns, name string, patches ...map[string]any) string {
	w.t.Helper()
	h := must(w.anna.Head(ctx, ns, name))
	return must(w.anna.Append(ctx, ns, name, h.ID, ops(patches...))).ID
}

func (w *relWorld) frozen(ns string) bool {
	h := must(w.anna.NSHead(ctx, ns))
	d := must(w.anna.NSDoc(ctx, ns, h.ID))
	f, _ := d.Value["frozen"].(bool)
	return f
}

// release7 builds release-7:
//
//   - schemas-r7 drafts /r/schemas/match T1 (adds venue), drafts.for the
//     other branches;
//   - matches-r7 creates final ($schema T1) and moves derby to T1;
//   - cat-season-r7 places matches.final in season (widens), moves
//     matches.cup into vault (narrows), and creates the folder locked
//     (inherit: false, desk for match-desk) and moves matches.derby into
//     it (narrows; the folder is created without desk, step 4 adds it).
func (w *relWorld) release7() (t1 string) {
	w.branch("schemas", "schemas-r7", op("add", "/drafts", map[string]any{"for": sAny("matches-r7", "cat-season-r7")}))
	w.branch("matches", "matches-r7")
	w.branch("cat-season", "cat-season-r7")
	t1 = w.appendTo("schemas-r7", "match", op("add", "/properties/venue", map[string]any{"type": "string"}))
	draft := "/r/schemas/match/rev/" + t1
	must(w.anna.CreateDoc(ctx, "matches-r7", "final", map[string]any{"$schema": draft, "home": "A", "away": "C", "venue": "Wembley"}))
	w.appendTo("matches-r7", "derby", op("replace", "/$schema", draft), op("add", "/venue", "Anfield"))
	must(w.anna.CreateDoc(ctx, "cat-season-r7", "matches.final", map[string]any{"parents": parentsOf("season")}))
	w.appendTo("cat-season-r7", "matches.cup", op("replace", "/parents", parentsOf("vault")))
	must(w.anna.CreateDoc(ctx, "cat-season-r7", "locked", map[string]any{"title": "Locked", "parents": parentsOf("root"),
		"$access": map[string]any{"inherit": false, "group:match-desk": sAny("desk")}}))
	w.appendTo("cat-season-r7", "matches.derby", op("replace", "/parents", parentsOf("locked")))
	w.writeRelease("release-7", map[string]string{"schemas": "schemas-r7", "matches": "matches-r7", "cat-season": "cat-season-r7"})
	return t1
}

func (w *relWorld) writeRelease(name string, branches map[string]string) {
	w.t.Helper()
	d := &release.Doc{Name: name, Branches: map[string]release.Branch{}, Owners: []string{"user:anna"}}
	for k, b := range branches {
		h := must(w.anna.NSHead(ctx, b))
		nd := must(w.anna.NSDoc(ctx, b, h.ID))
		bref, _ := nd.Value["base"].(map[string]any)
		at, _ := bref["at"].(string)
		d.Branches[k] = release.Branch{NS: b, At: at}
	}
	ref := release.Ref{NS: "releases", Name: name}
	parent := ""
	if h := must(w.anna.Head(ctx, "releases", name)); h.State == client.Live {
		parent = h.ID
	}
	must(release.Write(ctx, w.anna, ref, parent, d))
}

func (w *relWorld) opts(rel string) merge.ReleaseOptions {
	return merge.ReleaseOptions{Release: "/r/releases/" + rel, Granter: w.granter(), Who: "user:anna", Now: w.s.Now, BehindWait: 30 * time.Second,
		AdminGrant: w.annaAll(), Via: "svc:merge"}
}

func stepsOf(rp *merge.ReleasePlan) []string {
	var out []string
	for _, st := range rp.Steps {
		out = append(out, strings.Join(append([]string{string(rune('0' + st.Step)), st.Key}, st.Resources...), " "))
	}
	return out
}

func conflictKinds(rp *merge.ReleasePlan) map[string][]string {
	out := map[string][]string{}
	for _, c := range rp.Conflicts {
		out[c.Kind] = append(out[c.Kind], c.Key+"/"+c.Resource)
	}
	return out
}

func parentNames(doc map[string]any) []string {
	var out []string
	ps, _ := doc["parents"].([]any)
	for _, p := range ps {
		m, _ := p.(map[string]any)
		h, _ := m["href"].(string)
		out = append(out, strings.TrimPrefix(h, "/r/cat-season/"))
	}
	sort.Strings(out)
	return out
}

// §F.9 Merging: plan, approve (freezes), merge in the four steps with the
// states in between, a stop after step 2 and a resume, one release per
// catalog base at a time, merged recorded after step 4.
func TestReleaseMerge(t *testing.T) { t.Parallel(); testReleaseMerge(t) }

func testReleaseMerge(t *testing.T) {
	w := newRelWorld(t)
	w.startCatalog()
	t1 := w.release7()

	rp, err := merge.PlanRelease(ctx, w.anna, w.opts("release-7"))
	noErr(t, err)
	if !rp.Clean() {
		t.Fatalf("conflicts: %+v", rp.Conflicts)
	}
	want := []string{
		"1 schemas match",
		"2 cat-season locked matches.cup matches.derby",
		"3 matches derby final",
		"4 cat-season matches.final",
	}
	if got := stepsOf(rp); strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("steps\n got %q\nwant %q", got, want)
	}
	// v0.34: the folder a narrowing move needs is created in step 2 with
	// its own $access, in one piece.
	if _, ok := rp.Halves["cat-season"]["locked"]; ok {
		t.Fatalf("locked halves: %+v", rp.Halves)
	}
	if rp.Digest == "" || rp.Steps[0].Digest == "" {
		t.Fatalf("no plan digest: %+v", rp)
	}
	noErr(t, merge.SaveReleasePlan(ctx, w.anna, w.opts("release-7"), rp))

	// A second release on the same catalog base, approved too.
	w.branch("cat-season", "cat-season-r8")
	w.appendTo("cat-season-r8", "season", op("replace", "/title", "Season 2026"))
	w.writeRelease("release-8", map[string]string{"cat-season": "cat-season-r8"})
	rp8 := must(merge.PlanRelease(ctx, w.anna, w.opts("release-8")))
	noErr(t, merge.SaveReleasePlan(ctx, w.anna, w.opts("release-8"), rp8))

	// Applying before approval is refused.
	if _, err := merge.ApplyRelease(ctx, w.anna, w.opts("release-7")); err == nil {
		t.Fatal("applied an unapproved plan")
	}
	// Approval freezes every listed branch (§8.4).
	rp = must(merge.ApproveRelease(ctx, w.anna, w.opts("release-7")))
	for _, b := range []string{"schemas-r7", "matches-r7", "cat-season-r7"} {
		if !w.frozen(b) {
			t.Fatalf("%s not frozen after approval", b)
		}
	}
	if _, err := w.anna.CreateDoc(ctx, "matches-r7", "late", map[string]any{"home": "x", "away": "y"}); !client.IsFrozen(err) {
		t.Fatalf("write to a frozen branch: %v", err)
	}
	must(merge.ApproveRelease(ctx, w.anna, w.opts("release-8")))

	// Merge, stopping after step 2 (a crash).
	crash := errors.New("crash")
	o := w.opts("release-7")
	o.AfterStep = func(st *merge.ReleaseStep) error {
		if st.Step == 2 {
			return crash
		}
		return nil
	}
	if _, err := merge.ApplyRelease(ctx, w.anna, o); !errors.Is(err, crash) {
		t.Fatalf("apply: %v", err)
	}
	// After step 1 the schema revision is in the base with its id.
	if h := must(w.anna.Head(ctx, "schemas", "match")); h.ID != t1 {
		t.Fatalf("schemas/match is %s, want the draft's id %s (fast-forward)", h.ID, t1)
	}
	// After step 2: the narrowing moves are in, locked exists with its own
	// $access, nothing new is placed or created.
	if got := parentNames(w.doc("cat-season", "matches.cup")); strings.Join(got, ",") != "vault" {
		t.Fatalf("matches.cup parents %v", got)
	}
	if got := parentNames(w.doc("cat-season", "matches.derby")); strings.Join(got, ",") != "locked" {
		t.Fatalf("matches.derby parents %v", got)
	}
	lk := w.doc("cat-season", "locked")
	if acc, _ := lk["$access"].(map[string]any); acc["group:match-desk"] == nil || acc["inherit"] != false {
		t.Fatalf("locked after step 2: %v", lk)
	}
	if w.live("matches", "final") || w.live("cat-season", "matches.final") {
		t.Fatal("step 3 or 4 ran before the stop")
	}

	// One release per catalog base: release-8 waits for release-7.
	if holder := must(merge.LockHolder(ctx, w.anna, w.opts("release-8"), "cat-season")); holder != "/r/releases/release-7" {
		t.Fatalf("lock holder %q", holder)
	}
	if _, err := merge.ApplyRelease(ctx, w.anna, w.opts("release-8")); !errors.Is(err, merge.ErrLocked) {
		t.Fatalf("release-8 while release-7 merges: %v", err)
	}

	// Resume; after step 3 the new documents exist, unplaced.
	o.AfterStep = func(st *merge.ReleaseStep) error {
		if st.Step == 3 {
			if !w.live("matches", "final") {
				t.Error("after step 3: matches/final missing")
			}
			if w.live("cat-season", "matches.final") {
				t.Error("after step 3: matches.final placed already")
			}
			if d := w.doc("matches", "derby"); d["$schema"] != "/r/schemas/match/rev/"+t1 {
				t.Errorf("after step 3: derby %v", d)
			}
		}
		return nil
	}
	rp, err = merge.ApplyRelease(ctx, w.anna, o)
	noErr(t, err)
	if rp.State != merge.ReleaseDone {
		t.Fatalf("state %s", rp.State)
	}
	if got := parentNames(w.doc("cat-season", "matches.final")); strings.Join(got, ",") != "season" {
		t.Fatalf("matches.final parents %v", got)
	}
	// Every branch records merged, at the target's ns_id after the last
	// batch into it; the janitor verifies the claims (catalog batches are
	// the merge service's under the merge key, or anna's, an admin's, for
	// $access, §F.8).
	j := janitor.New(w.anna, janitor.Options{DryRun: true, Now: func() time.Time { return w.s.Now().Add(time.Hour) }})
	for base, br := range map[string]string{"schemas": "schemas-r7", "matches": "matches-r7", "cat-season": "cat-season-r7"} {
		h := must(w.anna.NSHead(ctx, br))
		d := must(w.anna.NSDoc(ctx, br, h.ID))
		if _, ok := d.Value["merged"]; !ok {
			t.Fatalf("%s doesn't record merged", br)
		}
		dec := must(j.Check(ctx, base, br))
		if dec.Claim != "merged" || dec.Action != janitor.ActionWouldPurge {
			t.Fatalf("janitor on %s: %+v", br, dec)
		}
	}
	if holder := must(merge.LockHolder(ctx, w.anna, w.opts("release-8"), "cat-season")); holder != "" {
		t.Fatalf("lock still held by %q", holder)
	}
	// Done is done; release-8 may go now.
	if rp, err := merge.ApplyRelease(ctx, w.anna, w.opts("release-7")); err != nil || rp.State != merge.ReleaseDone {
		t.Fatalf("apply again: %v", err)
	}
	if _, err := merge.ApplyRelease(ctx, w.anna, w.opts("release-8")); err != nil {
		t.Fatalf("release-8: %v", err)
	}
	if d := w.doc("cat-season", "season"); d["title"] != "Season 2026" {
		t.Fatalf("release-8 not merged: %v", d)
	}
}

// §F.9: unfreezing a branch invalidates the approved plan; so does a new
// revision of the release document.
func TestReleaseUnfreezeInvalidates(t *testing.T) {
	t.Parallel()
	w := newRelWorld(t)
	w.startCatalog()
	w.release7()
	o := w.opts("release-7")
	noErr(t, merge.SaveReleasePlan(ctx, w.anna, o, must(merge.PlanRelease(ctx, w.anna, o))))
	must(merge.ApproveRelease(ctx, w.anna, o))
	h := must(w.anna.NSHead(ctx, "matches-r7"))
	must(w.anna.PatchConfig(ctx, "matches-r7", h.Config, ops(op("replace", "/frozen", false))))
	if _, err := merge.ApplyRelease(ctx, w.anna, o); !errors.Is(err, merge.ErrInvalidPlan) {
		t.Fatalf("apply after an unfreeze: %v", err)
	}
	if w.live("schemas", "match") && must(w.anna.Head(ctx, "schemas", "match")).ID != w.T0 {
		t.Fatal("something was merged")
	}
	// Planning again sees the other branches frozen by this approval, and
	// matches-r7 not frozen: clean.
	stored := must(merge.LoadReleasePlan(ctx, w.anna, o))
	o.AcceptFrozen = stored.FrozenBy()
	rp := must(merge.PlanRelease(ctx, w.anna, o))
	if !rp.Clean() {
		t.Fatalf("replan: %+v", rp.Conflicts)
	}
	// A new release document revision invalidates an approval too.
	merge.AdoptHead(rp, stored)
	noErr(t, merge.SaveReleasePlan(ctx, w.anna, o, rp))
	must(merge.ApproveRelease(ctx, w.anna, o))
	w.appendTo("releases", "release-7", op("add", "/owners/-", "user:bo"))
	if _, err := merge.ApplyRelease(ctx, w.anna, o); !errors.Is(err, merge.ErrInvalidPlan) {
		t.Fatalf("apply after the release changed: %v", err)
	}
}

// §F.9: the conflicts reported before anything is submitted.
func TestReleaseConflicts(t *testing.T) {
	t.Parallel()
	w := newRelWorld(t)
	w.startCatalog()
	t1 := w.release7()

	// A placement in the base already names an item step 3 creates.
	must(w.ops.CreateDoc(ctx, "cat-season", "matches.newbie", map[string]any{"parents": parentsOf("season")}))
	h := must(w.anna.NSHead(ctx, "matches-r7"))
	_ = h
	must(w.anna.CreateDoc(ctx, "matches-r7", "newbie", map[string]any{"$schema": "/r/schemas/match/rev/" + w.T0, "home": "N", "away": "B"}))
	// A node that narrows for some subjects and widens for others: into
	// embargo, fans lose reader and editors gain it.
	w.appendTo("cat-season-r7", "matches.cup", op("replace", "/parents", parentsOf("embargo")))
	// A pin to a revision of another listed branch that the merge replays:
	// the base changes cup too, so cup replays.
	cupRev := w.appendTo("matches-r7", "cup", op("add", "/note", "branch"))
	w.appendTo("matches", "cup", op("add", "/score", "1-0"))
	must(w.anna.CreateDoc(ctx, "matches-r7", "report", map[string]any{"about": "/r/matches/cup/rev/" + cupRev}))
	// A draft in a branch the release doesn't list.
	w.branch("schemas", "schemas-x", op("add", "/drafts", map[string]any{"for": sAny("matches-r7")}))
	sx := must(w.anna.CreateDoc(ctx, "schemas-x", "other", matchSchema("x"))).ID
	must(w.anna.CreateDoc(ctx, "matches-r7", "odd", map[string]any{"$schema": "/r/schemas/other/rev/" + sx, "home": "a", "away": "b"}))
	// The base changes the schema the release drafts.
	w.appendTo("schemas", "match", op("add", "/properties/coach", map[string]any{"type": "string"}))

	o := w.opts("release-7")
	rp := must(merge.PlanRelease(ctx, w.anna, o))
	got := conflictKinds(rp)
	for kind, where := range map[string]string{
		merge.RCSchemaChanged:  "schemas/match",
		merge.RCNarrowAndWiden: "cat-season/matches.cup",
		merge.RCPlacedItem:     "matches/newbie",
		merge.RCDanglingPin:    "matches/report",
		merge.RCForeignDraft:   "matches/odd",
	} {
		found := false
		for _, x := range got[kind] {
			if x == where {
				found = true
			}
		}
		if !found {
			t.Errorf("missing %s conflict at %s; got %v", kind, where, got)
		}
	}
	// Nothing can be approved like this.
	noErr(t, merge.SaveReleasePlan(ctx, w.anna, o, rp))
	if _, err := merge.ApproveRelease(ctx, w.anna, o); !errors.Is(err, merge.ErrConflicts) {
		t.Fatalf("approve: %v", err)
	}
	if w.frozen("matches-r7") {
		t.Fatal("a refused approval froze a branch")
	}

	// Resolutions: a split for matches.cup (into vault in step 2, on to
	// embargo in step 4), the placement accepted.
	o.Splits = map[string]map[string]any{"cat-season": {"matches.cup": map[string]any{"parents": parentsOf("vault")}}}
	o.Accept = []string{"matches.newbie"}
	rp = must(merge.PlanRelease(ctx, w.anna, o))
	got = conflictKinds(rp)
	if len(got[merge.RCNarrowAndWiden]) > 0 || len(got[merge.RCPlacedItem]) > 0 {
		t.Fatalf("still: %v", got)
	}
	if h := rp.Halves["cat-season"]["matches.cup"]; h.Reason != "split" {
		t.Fatalf("halves %+v", rp.Halves)
	}
	// A split that doesn't narrow first is refused.
	o.Splits = map[string]map[string]any{"cat-season": {"matches.cup": map[string]any{"parents": parentsOf("embargo")}}}
	rp = must(merge.PlanRelease(ctx, w.anna, o))
	if len(conflictKinds(rp)[merge.RCBadSplit]) == 0 {
		t.Fatalf("bad split accepted: %v", conflictKinds(rp))
	}
	_ = t1
}

// §F.9 Rebasing: the schema base changed, so the release is rebased; the
// schema successor's drafts.for names the other successors, documents
// referencing the replayed draft are squashed onto its new revision, and
// the release document lists the successors. Then the janitor cleans up
// the old generation: the draft branch last, retrying on in_use (§F.6).
func TestReleaseRebaseAndJanitor(t *testing.T) { t.Parallel(); testReleaseRebaseAndJanitor(t) }

func testReleaseRebaseAndJanitor(t *testing.T) {
	w := newRelWorld(t)
	w.startCatalog()
	t1 := w.release7()
	w.appendTo("schemas", "match", op("add", "/properties/coach", map[string]any{"type": "string"}))
	o := w.opts("release-7")
	if rp := must(merge.PlanRelease(ctx, w.anna, o)); len(conflictKinds(rp)[merge.RCSchemaChanged]) == 0 {
		t.Fatalf("no schema conflict: %+v", rp.Conflicts)
	}

	res, err := merge.RebaseRelease(ctx, w.anna, merge.RebaseReleaseOptions{Release: "/r/releases/release-7", Suffix: "-b"})
	noErr(t, err)
	if res.Order[0] != "schemas-r7" {
		t.Fatalf("order %v", res.Order)
	}
	h := must(w.anna.NSHead(ctx, "schemas-r7-b"))
	sd := must(w.anna.NSDoc(ctx, "schemas-r7-b", h.ID))
	dr, _ := sd.Value["drafts"].(map[string]any)
	if got := strings.Join(strList(dr["for"]), ","); got != "cat-season-r7-b,matches-r7-b" {
		t.Fatalf("drafts.for %q", got)
	}
	t1b := must(w.anna.Head(ctx, "schemas-r7-b", "match")).ID
	if t1b == t1 {
		t.Fatal("the draft kept its id though the base changed")
	}
	if res.Drafts["/r/schemas/match/rev/"+t1] != "/r/schemas/match/rev/"+t1b {
		t.Fatalf("drafts %v", res.Drafts)
	}
	if sq := strings.Join(res.Squashed["matches"], ","); sq != "derby,final" {
		t.Fatalf("squashed %q", sq)
	}
	for _, n := range []string{"final", "derby"} {
		if d := w.doc("matches-r7-b", n); d["$schema"] != "/r/schemas/match/rev/"+t1b || d["venue"] == nil {
			t.Fatalf("%s in the successor: %v", n, d)
		}
	}
	rel := must(release.Load(ctx, w.anna, "/r/releases/release-7"))
	if rel.Doc.Branches["matches"].NS != "matches-r7-b" || rel.Doc.Branches["schemas"].NS != "schemas-r7-b" || rel.Doc.Branches["cat-season"].NS != "cat-season-r7-b" {
		t.Fatalf("release document %+v", rel.Doc.Branches)
	}
	if !w.frozen("schemas-r7") || !w.frozen("matches-r7") {
		t.Fatal("old branches not switched")
	}
	// The rebased release plans clean.
	if rp := must(merge.PlanRelease(ctx, w.anna, o)); !rp.Clean() {
		t.Fatalf("after the rebase: %+v", rp.Conflicts)
	}

	// Cleanup of the old generation. schemas-r7 holds the only copy of t1,
	// which matches-r7's documents reference: purging it first is in_use,
	// a decision to retry, not an error.
	later := func() time.Time { return w.s.Now().Add(time.Hour) }
	j := janitor.New(w.anna, janitor.Options{Now: later})
	d, err := j.Check(ctx, "schemas", "schemas-r7")
	noErr(t, err)
	if d.Action != janitor.ActionRetry || d.Claim != "superseded" {
		t.Fatalf("schemas-r7 first: %+v", d)
	}
	// A sweep over both bases, with the release named, purges matches-r7
	// before schemas-r7, and both go.
	j = janitor.New(w.anna, janitor.Options{Now: later, Bases: []string{"schemas", "matches", "cat-season"}, Releases: []string{"/r/releases/release-7"}})
	ds, err := j.Sweep(ctx)
	noErr(t, err)
	order := map[string]int{}
	for i, d := range ds {
		if d.Action == janitor.ActionPurged {
			order[d.NS] = i + 1
		}
	}
	if order["matches-r7"] == 0 || order["schemas-r7"] == 0 || order["cat-season-r7"] == 0 || order["matches-r7"] > order["schemas-r7"] {
		t.Fatalf("purges %v in %+v", order, ds)
	}
	for _, d := range ds {
		if strings.HasSuffix(d.NS, "-b") && d.Action == janitor.ActionPurged {
			t.Fatalf("purged a live successor: %+v", d)
		}
	}
}

func strList(v any) []string {
	arr, _ := v.([]any)
	var out []string
	for _, x := range arr {
		s, _ := x.(string)
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// §B.5 Previews of a release: a tree service follows the release's
// branches in place of their bases, resolves placements to the release's
// branch of the content namespace, and shows a viewer only branches it
// can read.
func TestReleasePreview(t *testing.T) {
	t.Parallel()
	w := newRelWorld(t)
	w.release7()
	rel := must(release.Load(ctx, w.anna, "/r/releases/release-7"))
	svcClient := w.s.Client(t, client.WithBearer(w.opsKey.Grant(t, w.s.Now(), "svc:preview", relNS, []string{"read"},
		map[string]any{"exp": w.s.Now().Add(24 * time.Hour).Format(time.RFC3339)})))
	if _, err := tree.Open(ctx, tree.Options{Client: svcClient, Catalog: "cat-season", DB: filepath.Join(t.TempDir(), "x.db"), Branches: rel.Doc.Aliases(),
		RoleView: nopRoleView{}}); err == nil {
		t.Fatal("a preview opened as a catalog service")
	}
	svc, err := tree.Open(ctx, tree.Options{Client: svcClient, Catalog: "cat-season", DB: filepath.Join(t.TempDir(), "p.db"), Branches: rel.Doc.Aliases(),
		Now: w.s.Now, CheckerTTL: time.Millisecond, Logf: func(string, ...any) {},
		FollowOptions: []follow.Option{follow.WithBackoff(time.Millisecond, 20*time.Millisecond)}})
	if err != nil {
		t.Fatal(err)
	}
	hs := httptest.NewServer(svc.Handler())
	cctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { svc.Run(cctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done; hs.Close(); svc.Close() })
	hcp := must(w.anna.NSHead(ctx, "cat-season-r7")).ID
	hmp := must(w.anna.NSHead(ctx, "matches-r7")).ID
	deadline := time.Now().Add(30 * time.Second)
	for svc.Checkpoint("cat-season") != hcp || svc.Checkpoint("matches") != hmp {
		if time.Now().After(deadline) {
			t.Fatal("the preview didn't follow the branches")
		}
		time.Sleep(10 * time.Millisecond)
	}

	full := w.opsKey.Grant(t, w.s.Now(), "user:viewer", []string{"cat-season-r7", "matches-r7"}, []string{"read"})
	catOnly := w.opsKey.Grant(t, w.s.Now(), "user:viewer2", []string{"cat-season-r7"}, []string{"read"})
	base := w.opsKey.Grant(t, w.s.Now(), "user:viewer3", []string{"cat-season", "matches"}, []string{"read"})

	get := func(grant, path string) (int, map[string]any) {
		code, body := getJSON(t, hs.URL+path, grant)
		return code, body
	}
	code, body := get(full, "/cat-season/children?of=season")
	if code != 200 {
		t.Fatalf("children: %d %v", code, body)
	}
	items := map[string]map[string]any{}
	for _, x := range body["children"].([]any) {
		m := x.(map[string]any)
		items[m["name"].(string)] = m
	}
	fin := items["matches.final"]
	if fin == nil || fin["head"] == nil || fin["branch"] != "matches-r7" || !strings.Contains(fin["url"].(string), "/r/matches-r7/final/rev/") || fin["item"] != "/r/matches/final" {
		t.Fatalf("matches.final in the preview: %v (children %v)", fin, items)
	}
	if items["matches.cup"] != nil || items["matches.derby"] != nil {
		t.Fatalf("moved nodes still under season: %v", items)
	}
	// A viewer who can't read matches-r7 sees the structure, no items.
	code, body = get(catOnly, "/cat-season/children?of=season")
	if code != 200 {
		t.Fatalf("children (catalog only): %d %v", code, body)
	}
	for _, x := range body["children"].([]any) {
		if m := x.(map[string]any); m["head"] != nil || m["url"] != nil {
			t.Fatalf("an unreadable branch's item is shown: %v", m)
		}
	}
	// A grant for the bases doesn't read the preview.
	if code, _ := get(base, "/cat-season/children?of=season"); code != 403 {
		t.Fatalf("base grant on the preview: %d", code)
	}
	// /_status names the branches.
	code, st := get("", "/_status")
	if code != 200 {
		t.Fatalf("status %d", code)
	}
	var nss []string
	for _, x := range st["namespaces"].([]any) {
		m := x.(map[string]any)
		nss = append(nss, m["ns"].(string))
	}
	sort.Strings(nss)
	if strings.Join(nss, ",") != "cat-season-r7,matches-r7" {
		t.Fatalf("status namespaces %v", nss)
	}
}

type nopRoleView struct{}

func (nopRoleView) Resolve(context.Context, *grant.Verified) ([]string, tree.Visibility, error) {
	return nil, nil, nil
}

func getJSON(t *testing.T, url, bearer string) (int, map[string]any) {
	t.Helper()
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		t.Fatal(err)
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}
