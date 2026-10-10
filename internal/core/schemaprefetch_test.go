package core

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/pgtest"
	"github.com/middle-management/patchlog/internal/schema"
)

// Step 5 reads the schema revisions a write's documents pin by $schema
// ahead, a few statements per namespace (prefetchSchemas), and resolves
// each path from what it read; these tests pin that the answers are
// loadSchemaIn's, path by path.

// schemaEnv is an engine with authentication off and a clock tests move,
// running no background loop (onStatement is set after Open).
type schemaEnv struct {
	t   *testing.T
	e   *Engine
	now atomic.Int64 // unix ms
}

func newSchemaEnv(t *testing.T) *schemaEnv {
	t.Helper()
	s := &schemaEnv{t: t}
	s.now.Store(time.Now().UnixMilli())
	lim := DefaultLimits()
	fast := Rate{1e9, 1e9}
	lim.RatePerResource, lim.RatePerPrincipal, lim.RatePerNamespace = fast, fast, fast
	e, err := Open(Options{Path: pgtest.DB(t), BlobDir: t.TempDir(), AuthDisabled: true, Limits: lim, Purger: discardPurger{},
		Now:               func() time.Time { return time.UnixMilli(s.now.Load()) },
		RetentionInterval: -1, BlobSweepInterval: -1, RepurgeInterval: -1, Remote: RemoteOptions{FollowInterval: -1}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close() })
	s.e = e
	return s
}

func (s *schemaEnv) req(ns string) Request { return Request{NS: ns, Cred: Credentials{Author: "a"}} }

func (s *schemaEnv) mkNS(ns string) {
	s.t.Helper()
	if _, err := s.e.WriteConfig(context.Background(), s.req(ns), ConfigChange{IfNoneMatch: true,
		Patches: []any{map[string]any{"op": "add", "path": "", "value": map[string]any{"read": "public"}}}}); err != nil {
		s.t.Fatal(err)
	}
}

// createItem creates name with doc.
func createItem(name string, doc any) Item {
	return Item{Resource: name, IfNoneMatch: true, Steps: []Step{{Patches: []any{map[string]any{"op": "add", "path": "", "value": doc}}}}}
}

func (s *schemaEnv) batch(ns string, items []Item, dryRun bool) (*WriteResult, error) {
	return s.e.Batch(context.Background(), s.req(ns), items, nil, nil, dryRun)
}

func (s *schemaEnv) mustBatch(ns string, items []Item) *WriteResult {
	s.t.Helper()
	res, err := s.batch(ns, items, false)
	if err != nil {
		s.t.Fatalf("batch to %s: %v", ns, err)
	}
	return res
}

// put writes doc to ns/name as a single write: a create with ifMatch "",
// else a replace. It returns the revision's id.
func (s *schemaEnv) put(ns, name, ifMatch string, doc any) string {
	s.t.Helper()
	it := createItem(name, doc)
	if ifMatch != "" {
		it = Item{Resource: name, IfMatch: ifMatch, Steps: []Step{{Patches: []any{map[string]any{"op": "replace", "path": "", "value": doc}}}}}
	}
	res, err := s.e.WriteResource(context.Background(), s.req(ns), it)
	if err != nil {
		s.t.Fatalf("write %s/%s: %v", ns, name, err)
	}
	return res.Items[0].IDs[0]
}

// kSchema is a schema whose documents must have k equal to v.
func kSchema(v int) map[string]any {
	return map[string]any{"$schema": schema.Dialect2020, "type": "object", "required": []any{"k"},
		"properties": map[string]any{"k": map[string]any{"const": float64(v)}}}
}

func typedDoc(path string, k int) map[string]any {
	return map[string]any{"$schema": path, "k": float64(k)}
}

// itemFails returns the failures of a batch error by item index: code and,
// for schema_unavailable, ref.
func itemFails(t *testing.T, err error) map[int]string {
	t.Helper()
	var ae *Error
	if !errors.As(err, &ae) || ae.Body["code"] != "batch" {
		t.Fatalf("want a batch error, got %v", err)
	}
	out := map[int]string{}
	for _, x := range ae.Body["items"].([]any) {
		m := x.(map[string]any)
		s := fmt.Sprint(m["code"])
		if ref, ok := m["ref"]; ok {
			s += " " + fmt.Sprint(ref)
		}
		out[m["index"].(int)] = s
	}
	return out
}

// A batch of many documents typed by many schemas of two namespaces
// validates each against its own schema: a revision that is its
// resource's head, an older one, one of a tombstoned resource, one whose
// $ref closure reaches another namespace's, and one written by an earlier
// item of the batch; unknown revisions, resources and namespaces, a later
// item's revision and a branch's paths are refused, item by item.
func TestSchemaBatchManyTyped(t *testing.T) {
	t.Parallel()
	s := newSchemaEnv(t)
	for _, ns := range []string{"s", "u", "d"} {
		s.mkNS(ns)
	}
	const n = 40
	var items []Item
	for i := 0; i < n; i++ {
		items = append(items, createItem(fmt.Sprintf("s%02d", i), kSchema(i)))
	}
	res := s.mustBatch("s", items)
	path := func(ns string, i int, id string) string { return fmt.Sprintf("/r/%s/s%02d/rev/%s", ns, i, id) }
	var paths []string
	for i, it := range res.Items {
		paths = append(paths, path("s", i, it.IDs[0]))
	}
	// s00's first revision is no longer its head; s01 is tombstoned.
	old := paths[0]
	head0 := s.put("s", "s00", res.Items[0].IDs[0], kSchema(100))
	if _, err := s.e.WriteResource(context.Background(), s.req("s"), Item{Resource: "s01", IfMatch: res.Items[1].IDs[0], Steps: []Step{{Delete: true}}}); err != nil {
		t.Fatal(err)
	}
	u := s.put("u", "s07", "", kSchema(7))
	// A schema of u whose $ref closure reaches s05.
	viaRef := "/r/u/ref/rev/" + s.put("u", "ref", "", map[string]any{"$schema": schema.Dialect2020, "$ref": paths[5]})
	if _, err := s.e.CreateBranch(context.Background(), s.req("s"), BranchRequest{Name: "sb", IfNoneMatch: true}); err != nil {
		t.Fatal(err)
	}

	// Valid: three documents per schema of s, by head path but s00's
	// first revision and s01's tombstoned one, and one typed by u's.
	items = nil
	for j := 0; j < 3*n; j++ {
		i := j % n
		items = append(items, createItem(fmt.Sprintf("v%03d", j), typedDoc(paths[i], i)))
	}
	items = append(items, createItem("vu", typedDoc("/r/u/s07/rev/"+u, 7)))
	items = append(items, createItem("vh", typedDoc("/r/s/s00/rev/"+head0, 100)))
	items = append(items, createItem("vr0", typedDoc(viaRef, 5)), createItem("vr1", typedDoc(viaRef, 5)))
	res = s.mustBatch("d", items)
	if len(res.Items) != len(items) {
		t.Fatalf("%d items written, want %d", len(res.Items), len(items))
	}

	// Each item fails or not by its own document and schema.
	unknownRev := "/r/s/s05/rev/1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	unknownRes := "/r/s/nope/rev/" + res.Items[0].IDs[0]
	unknownNS := "/r/nons/s05/rev/" + res.Items[0].IDs[0]
	branch := "/r/sb/s05/rev/" + res.Items[0].IDs[0]
	items = []Item{
		createItem("w0", typedDoc(paths[3], 3)),
		createItem("w1", typedDoc(paths[3], 4)), // invalid
		createItem("w2", typedDoc(old, 100)),    // s00's first revision wants 0
		createItem("w3", typedDoc(unknownRev, 5)),
		createItem("w4", typedDoc(unknownRes, 5)),
		createItem("w5", typedDoc(unknownNS, 5)),
		createItem("w6", typedDoc(branch, 5)),
		createItem("w7", typedDoc(paths[9], 9)),
		createItem("w8", typedDoc(viaRef, 6)), // s05 wants 5
		createItem("w9", typedDoc(viaRef, 5)),
	}
	_, err := s.batch("d", items, false)
	got := itemFails(t, err)
	want := map[int]string{
		1: "invalid", 2: "invalid",
		3: "schema_unavailable " + unknownRev, 4: "schema_unavailable " + unknownRes, 5: "schema_unavailable " + unknownNS,
		6: "schema_ref", 8: "invalid",
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("failures %v, want %v", got, want)
	}

	// A schema written by an earlier item of the same batch is found
	// there, one written by a later item isn't.
	createID := func(doc any) string {
		return ids.Revision(nil, jsonv.Canonical(createItem("", doc).Steps[0].Patches)).String()
	}
	fresh, later := createID(kSchema(42)), createID(kSchema(43))
	res = s.mustBatch("s", []Item{createItem("fresh", kSchema(42)), createItem("t0", typedDoc("/r/s/fresh/rev/"+fresh, 42)), createItem("t1", typedDoc(paths[2], 2))})
	if res.Items[0].IDs[0] != fresh {
		t.Fatalf("fresh written as %s, want %s", res.Items[0].IDs[0], fresh)
	}
	_, err = s.batch("s", []Item{createItem("t2", typedDoc("/r/s/later/rev/"+later, 43)), createItem("later", kSchema(43))}, false)
	if got := itemFails(t, err); fmt.Sprint(got) != fmt.Sprint(map[int]string{0: "schema_unavailable /r/s/later/rev/" + later}) {
		t.Fatalf("failures %v", got)
	}
}

// A schema revision that is purged, or pruned below its resource's
// horizon, is unavailable to a batch's documents, even once the engine
// has parsed it (a dry run resolved it, without referencing it).
func TestSchemaPurgedOrPrunedUnavailable(t *testing.T) {
	t.Parallel()
	s := newSchemaEnv(t)
	s.mkNS("s")
	s.mkNS("d")
	res := s.mustBatch("s", []Item{createItem("gone", kSchema(1)), createItem("old", kSchema(2)), createItem("keep", kSchema(3))})
	gone := "/r/s/gone/rev/" + res.Items[0].IDs[0]
	old := "/r/s/old/rev/" + res.Items[1].IDs[0]
	keep := "/r/s/keep/rev/" + res.Items[2].IDs[0]
	docs := func(prefix string) []Item {
		return []Item{createItem(prefix+"0", typedDoc(gone, 1)), createItem(prefix+"1", typedDoc(old, 2)), createItem(prefix+"2", typedDoc(keep, 3))}
	}
	if r, err := s.batch("d", docs("x"), true); err != nil || r.Status != 200 {
		t.Fatalf("dry run: %v %v", r, err)
	}
	// old gets a second revision and, past the retry window, is pruned to
	// it; gone is purged.
	h := s.put("s", "old", res.Items[1].IDs[0], kSchema(20))
	s.now.Add((48 * time.Hour).Milliseconds())
	s.put("s", "old", h, kSchema(21))
	pr, err := s.e.Prune(context.Background(), s.req("s"), "old", PruneRequest{Horizon: h})
	if err != nil || pr.Horizon != h {
		t.Fatalf("prune: %+v %v", pr, err)
	}
	if _, err := s.e.Purge(context.Background(), s.req("s"), "gone", res.Items[0].IDs[0], false); err != nil {
		t.Fatal(err)
	}
	_, err = s.batch("d", docs("y"), false)
	got := itemFails(t, err)
	want := map[int]string{0: "schema_unavailable " + gone, 1: "schema_unavailable " + old}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("failures %v, want %v", got, want)
	}
}

// In a write to a branch, a path its namespace doesn't have is found among
// the drafts of branches serving it (loadDraft), alongside paths the
// namespace has; a write to the namespace itself doesn't see the draft.
func TestSchemaDraftInBatch(t *testing.T) {
	t.Parallel()
	s := newSchemaEnv(t)
	s.mkNS("s")
	base := s.mustBatch("s", []Item{createItem("a", kSchema(1)), createItem("b", kSchema(2))})
	if _, err := s.e.CreateBranch(context.Background(), s.req("s"), BranchRequest{Name: "dev", IfNoneMatch: true}); err != nil {
		t.Fatal(err)
	}
	draft := s.put("dev", "c", "", kSchema(3))
	a, b, c := "/r/s/a/rev/"+base.Items[0].IDs[0], "/r/s/b/rev/"+base.Items[1].IDs[0], "/r/s/c/rev/"+draft
	s.mustBatch("dev", []Item{createItem("d0", typedDoc(a, 1)), createItem("d1", typedDoc(c, 3)), createItem("d2", typedDoc(b, 2)), createItem("d3", typedDoc(c, 3))})
	_, err := s.batch("dev", []Item{createItem("e0", typedDoc(c, 4)), createItem("e1", typedDoc(a, 1))}, false)
	if got := itemFails(t, err); fmt.Sprint(got) != fmt.Sprint(map[int]string{0: "invalid"}) {
		t.Fatalf("failures %v", got)
	}
	_, err = s.batch("s", []Item{createItem("f0", typedDoc(a, 1)), createItem("f1", typedDoc(c, 3))}, false)
	if got := itemFails(t, err); fmt.Sprint(got) != fmt.Sprint(map[int]string{1: "schema_unavailable " + c}) {
		t.Fatalf("failures %v", got)
	}
}

// Resolving the schemas of a batch's documents costs a few statements per
// namespace, however many documents and schemas there are: the
// statements that read a namespace by name, a resource of the schemas'
// namespaces by name, or a revision by seq, are as many for 10 documents
// typed by 10 schemas as for 120 typed by 60, of the same two namespaces.
func TestSchemaResolutionStatements(t *testing.T) {
	t.Parallel()
	s := newSchemaEnv(t)
	for _, ns := range []string{"s", "u", "d"} {
		s.mkNS(ns)
	}
	schemaNSs := map[any]bool{}
	for _, ns := range []string{"s", "u"} {
		if err := s.e.read(context.Background(), func(t *tx) error {
			schemaNSs[t.nsByName(ns).id] = true
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	var mu sync.Mutex
	var counting bool
	counts := map[string]int{}
	s.e.onStatement = func(q string, args []any) {
		mu.Lock()
		defer mu.Unlock()
		switch {
		case !counting:
		case strings.Contains(q, "FROM namespaces WHERE name"):
			counts["namespace by name"]++
		case strings.Contains(q, "FROM resources WHERE ns = ? AND name") && schemaNSs[args[0]]:
			counts["schema resource by name"]++
		case strings.Contains(q, "FROM revisions WHERE seq"):
			counts["revision by seq"]++
		}
	}
	// Schema i of 60 is s(i/2) of s if i is even, of u if odd.
	ids := map[string][]string{}
	for _, ns := range []string{"s", "u"} {
		var items []Item
		for i := 0; i < 30; i++ {
			items = append(items, createItem(fmt.Sprintf("s%02d", i), kSchema(i)))
		}
		for _, it := range s.mustBatch(ns, items).Items {
			ids[ns] = append(ids[ns], it.IDs[0])
		}
	}
	path := func(i int) string {
		ns := map[bool]string{true: "s", false: "u"}[i%2 == 0]
		return fmt.Sprintf("/r/%s/s%02d/rev/%s", ns, i/2, ids[ns][i/2])
	}
	run := func(prefix string, docs, schemas int) map[string]int {
		t.Helper()
		var items []Item
		for j := 0; j < docs; j++ {
			i := j % schemas
			items = append(items, createItem(fmt.Sprintf("%s%03d", prefix, j), typedDoc(path(i), i/2)))
		}
		mu.Lock()
		counting, counts = true, map[string]int{}
		mu.Unlock()
		s.mustBatch("d", items)
		mu.Lock()
		defer mu.Unlock()
		counting = false
		return counts
	}
	run("w", 4, 4) // the engine's caches warm
	few := run("a", 10, 10)
	many := run("b", 120, 60)
	for k, c := range many {
		if c > few[k] {
			t.Errorf("%q: %d statements for 120 documents typed by 60 schemas, %d for 10 by 10", k, c, few[k])
		}
	}
	t.Logf("10 by 10: %v; 120 by 60: %v", few, many)
}
