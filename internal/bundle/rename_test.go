package bundle_test

import (
	"bytes"
	"errors"
	"io"
	"maps"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/annot"
	"github.com/middle-management/patchlog/internal/bundle"
	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/core"
	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/schema"
	"github.com/middle-management/patchlog/internal/seal"
)

// cloneSource is a source deployment with a set of namespaces to clone
// (§G.4.4 Renaming):
//
//	s-schemas/base  a schema with $defs
//	s-schemas/item  $ref base#/$defs/title; x-ref: pin (pinned), live and tags (live)
//	s-data/b        b1; b2 pins a2
//	s-data/a        a1; a2 pins b1, names b live and in tags (and s-refs/r), and
//	                an undeclared /note pins b1; a3 tests the pin and pins b2
//	s-refs/r        names a live, pins a3
//	s-snap/p        a snapshot: names a live, pins b2
type cloneSource struct {
	d                          *deployment
	base, item                 string
	a1, a2, a3, b1, b2, r, p   string
	full, snap, merged, schema []byte
}

var cloneMap = map[string]string{"s-schemas": "c-schemas", "s-data": "c-data", "s-refs": "c-refs", "s-snap": "c-snap"}

func newCloneSource(t *testing.T) *cloneSource {
	t.Helper()
	s := &cloneSource{d: newDeployment(t, stagingOrigin)}
	d := s.d
	for _, ns := range []string{"s-schemas", "s-data", "s-refs", "s-snap"} {
		d.ns(ns, nil)
	}
	s.base = d.create("s-schemas", "base", map[string]any{"$schema": schema.Dialect2020, "$defs": map[string]any{"title": map[string]any{"type": "string"}}})
	s.item = d.create("s-schemas", "item", map[string]any{"$schema": schema.Dialect2020, "type": "object", "properties": map[string]any{
		"title": map[string]any{"$ref": rev("s-schemas", "base", s.base) + "#/$defs/title"},
		"pin":   map[string]any{"type": "string", "x-ref": map[string]any{"pinned": true}},
		"live":  map[string]any{"type": "string", "x-ref": map[string]any{}},
		"tags":  map[string]any{"type": "array", "items": map[string]any{"type": "string", "x-ref": map[string]any{}}},
		"note":  map[string]any{"type": "string"},
	}})
	typed := func(title string) map[string]any {
		return map[string]any{"$schema": rev("s-schemas", "item", s.item), "title": title}
	}
	s.b1 = d.create("s-data", "b", typed("B"))
	s.a1 = d.create("s-data", "a", typed("A"))
	s.a2 = d.append("s-data", "a", op("add", "/pin", rev("s-data", "b", s.b1)), op("add", "/live", "/r/s-data/b"),
		op("add", "/note", rev("s-data", "b", s.b1)), op("add", "/tags", []any{"/r/s-data/b", "/r/s-refs/r"}))
	s.b2 = d.append("s-data", "b", op("add", "/pin", rev("s-data", "a", s.a2)))
	s.a3 = d.append("s-data", "a", op("test", "/pin", rev("s-data", "b", s.b1)), op("replace", "/pin", rev("s-data", "b", s.b2)))
	s.r = d.create("s-refs", "r", map[string]any{"$schema": rev("s-schemas", "item", s.item), "title": "R",
		"live": "/r/s-data/a", "pin": rev("s-data", "a", s.a3)})
	s.p = d.create("s-snap", "p", map[string]any{"$schema": rev("s-schemas", "item", s.item), "title": "P",
		"live": "/r/s-data/a", "pin": rev("s-data", "b", s.b2)})

	s.full, _ = exportFrom(t, d, bundle.ExportOptions{Select: []string{"s-schemas", "s-data", "s-refs"}})
	s.snap, _ = exportFrom(t, d, bundle.ExportOptions{Select: []string{"s-snap"}, Mode: bundle.Snapshot})
	s.merged = withSnapshots(t, s.full, s.snap, "s-snap")
	s.schema, _ = exportFrom(t, d, bundle.ExportOptions{Select: []string{"s-schemas"}})
	return s
}

// withSnapshots is bundle full with the snapshot documents of namespace ns
// of bundle snap added, so one bundle holds full and snapshot documents.
func withSnapshots(t *testing.T, full, snap []byte, ns string) []byte {
	t.Helper()
	read := func(b []byte) (*bundle.Header, []*bundle.Line) {
		rd, err := bundle.NewReader(bytes.NewReader(b))
		noErr(t, err)
		defer rd.Close()
		var ls []*bundle.Line
		for {
			l, err := rd.Next()
			if err == io.EOF {
				return rd.Header(), ls
			}
			noErr(t, err)
			ls = append(ls, l)
		}
	}
	h, ls := read(full)
	sh, sls := read(snap)
	h.At[ns], h.Access[ns] = sh.At[ns], sh.Access[ns]
	for k, info := range sh.Docs {
		if strings.HasPrefix(k, ns+"/") {
			h.Docs[k] = info
		}
	}
	for _, l := range sls {
		if l.NS == ns {
			ls = append(ls, l)
		}
	}
	var buf bytes.Buffer
	w, err := bundle.NewWriter(&buf, *h)
	noErr(t, err)
	for _, l := range ls {
		noErr(t, w.Line(*l))
	}
	_, err = w.Close()
	noErr(t, err)
	must(bundle.Verify(bytes.NewReader(buf.Bytes())))
	return buf.Bytes()
}

func (d *deployment) at(ns, name, id string) map[string]any {
	d.t.Helper()
	m, _ := must(d.c.Doc(ctx, ns, name, id)).Value.(map[string]any)
	return m
}

func (d *deployment) chain(ns, name string) []string {
	d.t.Helper()
	var out []string
	for _, e := range must(d.c.Log(ctx, ns, name, "", "")) {
		out = append(out, e.ID)
	}
	return out
}

// checkClone checks a clone of cloneSource (cloneMap) in d, imported in
// one batch per namespace (checkCloneDocs), and that the batch's
// source.ids hold the source ids.
func checkClone(t *testing.T, s *cloneSource, d *deployment, rep *bundle.Report) {
	t.Helper()
	checkCloneDocs(t, s, d, rep)
	for _, br := range rep.Batches {
		if br.NS != "c-data" {
			continue
		}
		ids := br.Source["ids"].(map[string]any)
		if br.Source["ns"] != "s-data" || ids["a"] != s.a3 || ids["b"] != s.b2 {
			t.Fatalf("c-data batch source %v", br.Source)
		}
	}
}

// checkCloneDocs checks a clone of cloneSource (cloneMap) in d: every
// reference declared names the clone, pins take the new ids at the same
// place in history, and the undeclared one stays and is reported.
func checkCloneDocs(t *testing.T, s *cloneSource, d *deployment, rep *bundle.Report) {
	t.Helper()
	// base references nothing, so keeps its id (§G.4.4); item's $ref
	// changes, so it gets a new one.
	if got := d.head("c-schemas", "base").ID; got != s.base {
		t.Fatalf("c-schemas/base %s, want the source's %s", got, s.base)
	}
	item := d.head("c-schemas", "item").ID
	if item == s.item || !rep.Doc("s-schemas/item").Renamed || rep.Doc("s-schemas/base").Renamed {
		t.Fatalf("c-schemas/item %s (source %s), report %+v", item, s.item, rep.Doc("s-schemas/item"))
	}
	props := d.doc("c-schemas", "item")["properties"].(map[string]any)
	if got := props["title"].(map[string]any)["$ref"]; got != rev("c-schemas", "base", s.base)+"#/$defs/title" {
		t.Fatalf("item's $ref %v", got)
	}
	// Chains as long as the source's, with new ids.
	a, b := d.chain("c-data", "a"), d.chain("c-data", "b")
	if len(a) != 3 || len(b) != 2 || a[2] == s.a3 || b[1] == s.b2 {
		t.Fatalf("c-data chains a %v b %v", a, b)
	}
	if got := rep.Doc("s-data/a"); !got.Renamed || !slices.Equal(got.Expected, a) || got.Class != "create" {
		t.Fatalf("s-data/a report %+v, chain %v", got, a)
	}
	schemaRef := rev("c-schemas", "item", item)
	want := map[string]any{"$schema": schemaRef, "title": "A", "pin": rev("c-data", "b", b[0]), "live": "/r/c-data/b",
		"note": rev("s-data", "b", s.b1), "tags": []any{"/r/c-data/b", "/r/c-refs/r"}}
	if got := d.at("c-data", "a", a[1]); !jsonv.Equal(jsonv.FromGo(got), jsonv.FromGo(want)) {
		t.Fatalf("c-data/a at its second revision %v, want %v", got, want)
	}
	if got := d.at("c-data", "b", b[1])["pin"]; got != rev("c-data", "a", a[1]) {
		t.Fatalf("c-data/b pins %v, want a's second revision %s", got, a[1])
	}
	if got := d.doc("c-data", "a")["pin"]; got != rev("c-data", "b", b[1]) {
		t.Fatalf("c-data/a pins %v at its head, want %s", got, b[1])
	}
	if got := d.doc("c-refs", "r"); got["live"] != "/r/c-data/a" || got["pin"] != rev("c-data", "a", a[2]) || got["$schema"] != schemaRef {
		t.Fatalf("c-refs/r %v", got)
	}
	p := d.doc("c-snap", "p")
	if p["live"] != "/r/c-data/a" || p["pin"] != rev("c-data", "b", b[1]) || p["$schema"] != schemaRef {
		t.Fatalf("c-snap/p %v", p)
	}
	// The renamed namespace's upstream namespace is named after it.
	if up := d.head("c-snap-upstream", "p"); up.State != client.Live || up.ID != d.head("c-snap", "p").ID {
		t.Fatalf("c-snap-upstream/p %+v", up)
	}
	// Every declared reference names the clone: only the undeclared one
	// names the source.
	for _, k := range []string{"c-schemas/item", "c-data/a", "c-data/b", "c-refs/r", "c-snap/p"} {
		ns, name, _ := bundle.SplitKey(k)
		walk(d.doc(ns, name), "", func(ptr, s string) {
			if r, ok := annot.ParseRefString(s); ok && strings.HasPrefix(r.NS, "s-") && !(k == "c-data/a" && ptr == "/note") {
				t.Errorf("%s at %s still names the source: %s", k, ptr, s)
			}
		})
	}
	und := false
	for _, u := range rep.Undeclared {
		und = und || (u.Doc == "s-data/a" && u.Pointer == "/note" && u.Renamed && u.Rev == s.a2 && u.Value == rev("s-data", "b", s.b1))
	}
	if !und {
		t.Fatalf("undeclared %+v", rep.Undeclared)
	}
}

// walk calls f with every string in v and its pointer.
func walk(v any, at string, f func(ptr, s string)) {
	switch x := v.(type) {
	case string:
		f(at, x)
	case []any:
		for i, e := range x {
			walk(e, at+"/"+strconv.Itoa(i), f)
		}
	case map[string]any:
		for k, e := range x {
			walk(e, at+"/"+k, f)
		}
	}
}

// §G.4.4 Renaming: a set of namespaces cloned under new names, on another
// deployment and on the same one, every reference to them rewritten; a
// dry run writes nothing and lists the undeclared reference; a re-run
// writes nothing.
func TestRenamedImport(t *testing.T) {
	t.Parallel()
	s := newCloneSource(t)
	for _, tc := range []struct {
		name string
		d    func() *deployment
	}{
		{"another deployment", func() *deployment { return newDeployment(t, cmsOrigin) }},
		{"same deployment", func() *deployment { return s.d }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := tc.d()
			dry := importB(t, d, s.merged, bundle.ImportOptions{NSMap: cloneMap, DryRun: true})
			if dry.Renamed["s-data"] != "c-data" || len(dry.Undeclared) == 0 {
				t.Fatalf("dry run %+v", dry)
			}
			if _, err := d.c.NSHead(ctx, "c-data"); !client.IsNotFound(err) {
				t.Fatalf("a dry run wrote c-data: %v", err)
			}
			rep := importB(t, d, s.merged, bundle.ImportOptions{NSMap: cloneMap})
			checkClone(t, s, d, rep)
			if tc.name == "same deployment" {
				if d.head("s-data", "a").ID != s.a3 || d.doc("s-data", "a")["live"] != "/r/s-data/b" {
					t.Fatal("the source changed")
				}
				if !slices.ContainsFunc(rep.Notes, func(n string) bool { return strings.Contains(n, "comes from this deployment") }) {
					t.Fatalf("notes %v", rep.Notes)
				}
			}
			// Same bundle, same new ids: nothing to write.
			again := importB(t, d, s.merged, bundle.ImportOptions{NSMap: cloneMap})
			for _, dr := range again.Docs {
				if dr.Class != "present" || (dr.Upstream != nil && dr.Upstream.Class != "unchanged") {
					t.Errorf("re-run: %s %s %+v", dr.Doc, dr.Class, dr.Upstream)
				}
			}
			if len(again.Batches) != 0 {
				t.Fatalf("a re-run writes %d batches", len(again.Batches))
			}
		})
	}
}

// §G.4.4 Renaming, rewritten steps in a target that requires nonces: each
// gets a fresh $nonce, as new content does there (§C.7), so its ids differ
// from one run to the next; a re-run finds what the first wrote through
// its batches' source.ids, and writes nothing.
func TestRenamedImportNonces(t *testing.T) {
	t.Parallel()
	s := newCloneSource(t)
	d := newDeployment(t, cmsOrigin)
	d.ns("c-data", map[string]any{"read": "public", "nonce": "required"})
	rep := importB(t, d, s.full, bundle.ImportOptions{NSMap: cloneMap})
	a := d.chain("c-data", "a")
	if len(a) != 3 || !rep.Doc("s-data/a").Renamed {
		t.Fatalf("c-data/a %v %+v", a, rep.Doc("s-data/a"))
	}
	for _, id := range a {
		if n, _ := d.at("c-data", "a", id)["$nonce"].(string); n == "" {
			t.Fatalf("revision %s has no $nonce", id)
		}
	}
	// What a re-run recognises its earlier writes by: the source ids, in
	// the import batches' source.ids.
	n := 0
	for _, br := range rep.Batches {
		if br.NS != "c-data" {
			continue
		}
		n++
		if ids, _ := br.Source["ids"].(map[string]any); ids["a"] != s.a3 || ids["b"] != s.b2 {
			t.Fatalf("c-data batch source %v", br.Source)
		}
	}
	if n == 0 {
		t.Fatalf("no c-data batch: %+v", rep.Batches)
	}
	b := d.chain("c-data", "b")
	if got := d.doc("c-refs", "r")["pin"]; got != rev("c-data", "a", a[2]) {
		t.Fatalf("c-refs/r pins %v", got)
	}
	if got := d.at("c-data", "b", b[1])["pin"]; got != rev("c-data", "a", a[1]) {
		t.Fatalf("c-data/b pins %v", got)
	}
	again := importB(t, d, s.full, bundle.ImportOptions{NSMap: cloneMap})
	for _, dr := range again.Docs {
		if dr.Class != "present" {
			t.Errorf("re-run: %s %s", dr.Doc, dr.Class)
		}
	}
	if len(again.Batches) != 0 || !slices.Equal(d.chain("c-data", "a"), a) {
		t.Fatalf("a re-run writes %d batches", len(again.Batches))
	}

	// The clone edited since: a newer bundle still finds what the first
	// run wrote, in the clone's chain under its head, as the common
	// ancestor, and the documents that pin it stay present.
	local := must(d.c.Append(ctx, "c-data", "a", a[2], ops(op("add", "/extra", "local"), op("add", "/$nonce", seal.NewNonce())))).ID
	s.d.append("s-data", "a", op("replace", "/title", "A4"))
	newer, _ := exportFrom(t, s.d, bundle.ExportOptions{Select: []string{"s-schemas", "s-data", "s-refs"}})
	rep = importB(t, d, newer, bundle.ImportOptions{NSMap: cloneMap, Resolutions: map[string]bundle.Resolution{"s-data/a": bundle.ResolveReplay}})
	if r := rep.Doc("s-data/a"); r.Class != "replay" || r.Ancestor != a[2] || r.TargetHead != local {
		t.Fatalf("s-data/a after a local edit %+v", r)
	}
	for _, k := range []string{"s-data/b", "s-refs/r"} {
		if r := rep.Doc(k); r.Class != "present" {
			t.Errorf("%s %s %+v, want present", k, r.Class, r.Conflicts)
		}
	}
	if got := d.doc("c-data", "a"); got["title"] != "A4" || got["extra"] != "local" {
		t.Fatalf("c-data/a %v", got)
	}
}

// §G.4.4 Renaming, an incremental bundle (requires): a document that would
// change is refused (decision (c)); one whose only mention of a renamed
// namespace is undeclared changes nothing, keeps its ids, and imports from
// its base in the target, the undeclared reference listed.
func TestRenamedImportIncremental(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, path string
		refused    bool
	}{
		{"declared", "/note", true},
		{"undeclared", "/other", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			src := newDeployment(t, stagingOrigin)
			src.ns("k", nil)
			src.ns("x", nil)
			refs := src.create("k", "refs", map[string]any{"$schema": schema.Dialect2020, "type": "object",
				"properties": map[string]any{"note": map[string]any{"type": "string", "x-ref": map[string]any{}}}})
			src.create("x", "other", map[string]any{})
			g := src.create("x", "d", map[string]any{"$schema": rev("k", "refs", refs), "t": "a"})
			// The base, imported under the new name: nothing in it names x,
			// so it keeps its ids.
			whole, _ := exportFrom(t, src, bundle.ExportOptions{Select: []string{"k", "x"}})
			dst := newDeployment(t, cmsOrigin)
			importB(t, dst, whole, bundle.ImportOptions{NSMap: map[string]string{"x": "y"}})
			if dst.head("y", "d").ID != g {
				t.Fatalf("y/d %s, want the source's %s", dst.head("y", "d").ID, g)
			}
			r2 := src.append("x", "d", op("add", tc.path, "/r/x/other"))
			inc, _ := exportFrom(t, src, bundle.ExportOptions{Select: []string{"x/d"}, Requires: map[string]string{"x/d": g}})
			opt := bundle.ImportOptions{NSMap: map[string]string{"x": "y"}, Mode: bundle.Atomic}
			if tc.refused {
				_, err := bundle.Import(ctx, dst.c, bundle.BytesOpener(inc), opt)
				var ce *bundle.CheckError
				if !errors.As(err, &ce) || !strings.Contains(err.Error(), "x/d is incremental (requires "+g+"), and a renamed import would rewrite it") {
					t.Fatalf("import: %v", err)
				}
				if dst.head("y", "d").ID != g {
					t.Fatal("written")
				}
				return
			}
			rep := importB(t, dst, inc, opt)
			if r := rep.Doc("x/d"); r.Renamed || r.Class != "fast-forward" || dst.head("y", "d").ID != r2 {
				t.Fatalf("x/d %+v", r)
			}
			if len(rep.Undeclared) != 1 || rep.Undeclared[0].Pointer != "/other" || !rep.Undeclared[0].Renamed || rep.Undeclared[0].Rev != r2 {
				t.Fatalf("undeclared %+v", rep.Undeclared)
			}
		})
	}
}

// §G.4.4 Renaming: what a renamed import can't rewrite is refused before
// anything is written.
func TestRenamedImportRefusals(t *testing.T) {
	t.Parallel()
	s := newCloneSource(t)
	d := s.d

	// (c) An incremental document that changes: its base is in the target
	// under ids this import doesn't know.
	inc, _ := exportFrom(t, d, bundle.ExportOptions{Select: []string{"s-data/a"}, Requires: map[string]string{"s-data/a": s.a2}})
	// (d) A pin into a renamed namespace of a revision the bundle doesn't
	// carry.
	ext, _ := exportFrom(t, d, bundle.ExportOptions{Select: []string{"s-schemas", "s-refs"}, External: []string{"s-data"}})
	// (g) A schema whose $id names its own revision path.
	gp := client.GenesisPatches(map[string]any{"$schema": schema.Dialect2020, "$id": rev("s-schemas", "g", s.base), "type": "object"})
	gv, err := client.ToValue(gp)
	noErr(t, err)
	gid := ids.Revision(nil, jsonv.Canonical(gv)).String()
	var crafted bytes.Buffer
	w, err := bundle.NewWriter(&crafted, bundle.Header{Origin: stagingOrigin, Created: "2026-10-01T00:00:00Z",
		At: map[string]string{"s-schemas": gid}, Docs: map[string]bundle.DocInfo{"s-schemas/g": {History: bundle.Full, Head: gid}},
		Access: map[string]string{"s-schemas": bundle.AccessPublic}})
	noErr(t, err)
	noErr(t, w.Line(bundle.Line{NS: "s-schemas", Resource: "g", ID: gid, Kind: "rev", Patches: gp}))
	_, err = w.Close()
	noErr(t, err)

	// (d) A schema in a renamed namespace that the bundle doesn't carry: on
	// a deployment where it was cloned earlier, with new ids, its path's
	// new id isn't known.
	extSchemas, _ := exportFrom(t, d, bundle.ExportOptions{Select: []string{"s-data"}, External: []string{"s-schemas"}})

	// (d) A full-history document's pin of a snapshot document's revision,
	// which gets the id of its upstream chain: refused where the snapshot's
	// namespace is renamed, also from a namespace that isn't (§G.4.4: the
	// documents of unmapped namespaces that reference a renamed one are
	// rewritten too).
	d.create("s-refs", "q", map[string]any{"$schema": rev("s-schemas", "item", s.item), "title": "Q", "pin": rev("s-snap", "p", s.p)})
	pinsSnap, _ := exportFrom(t, d, bundle.ExportOptions{Select: []string{"s-schemas", "s-data", "s-refs"}, External: []string{"s-snap"}})
	pinsSnap = withSnapshots(t, pinsSnap, s.snap, "s-snap")
	snapPin := "the reference " + rev("s-snap", "p", s.p) + " at /pin in revision " + d.head("s-refs", "q").ID + " can't be rewritten: it pins revision " + s.p +
		" of s-snap/p, a snapshot document's, whose revisions get the ids of its upstream chain, so its new id isn't known"

	for _, tc := range []struct {
		name string
		b    []byte
		opt  bundle.ImportOptions
		want string
	}{
		{"incremental", inc, bundle.ImportOptions{NSMap: cloneMap}, "is incremental (requires " + s.a2},
		// Its base isn't in the target at all: no id to go on from.
		{"incremental, no base", inc, bundle.ImportOptions{NSMap: cloneMap}, "s-data/a is incremental (requires " + s.a2 + "), which c-data/a doesn't hold under that id"},
		{"external schema", extSchemas, bundle.ImportOptions{NSMap: cloneMap},
			"its schema " + rev("s-schemas", "item", s.item) + " can't be rewritten: it pins revision " + s.item + " of s-schemas/item, which the bundle doesn't carry (external)"},
		// Not renamed, the schema is a missing external, as without renaming.
		{"missing external", extSchemas, bundle.ImportOptions{NSMap: map[string]string{"s-data": "c-data"}},
			"external s-schemas/item/rev/" + s.item + ": revision " + s.item + " is not in the target"},
		{"external pin", ext, bundle.ImportOptions{NSMap: cloneMap}, "pins revision " + s.a3 + " of s-data/a, which the bundle doesn't carry"},
		{"left out", s.full, bundle.ImportOptions{NSMap: cloneMap, Only: []string{"s-refs"}}, "which the import leaves out (-only)"},
		{"schema $id", crafted.Bytes(), bundle.ImportOptions{NSMap: cloneMap}, "whose $id names its own revision path"},
		{"snapshot pin", pinsSnap, bundle.ImportOptions{NSMap: cloneMap}, snapPin},
		{"snapshot pin, unmapped", pinsSnap, bundle.ImportOptions{NSMap: map[string]string{"s-snap": "c-snap"}}, snapPin},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dst := newDeployment(t, cmsOrigin)
			switch tc.name {
			case "incremental":
				// The base is there, under the source's ids.
				importB(t, dst, s.full, bundle.ImportOptions{})
			case "external schema":
				importB(t, dst, s.schema, bundle.ImportOptions{NSMap: cloneMap})
			}
			tc.opt.Mode, tc.opt.CreateNamespaces = bundle.Atomic, true
			_, err := bundle.Import(ctx, dst.c, bundle.BytesOpener(tc.b), tc.opt)
			var ce *bundle.CheckError
			if !errors.As(err, &ce) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("import: %v, want a CheckError containing %q", err, tc.want)
			}
			targets := []string{"c-schemas", "c-data", "c-refs", "c-snap", "c-snap-upstream"}
			if tc.name == "snapshot pin, unmapped" {
				targets = append(targets, "s-schemas", "s-data", "s-refs")
			}
			for _, ns := range targets {
				if tc.name == "external schema" && ns == "c-schemas" {
					continue
				}
				if _, err := dst.c.NSHead(ctx, ns); !client.IsNotFound(err) {
					t.Fatalf("%s written: %v", ns, err)
				}
			}
		})
	}
}

// §G.4.4 Renaming: a mapping onto a branch whose base chain reaches the
// source namespace, as an import into a branch first, renames nothing:
// references stay, and the branch fast-forwards with the source's ids. A
// branch of a branch counts; a branch of another namespace doesn't, and is
// renamed onto.
func TestRenamedImportOntoBranch(t *testing.T) {
	t.Parallel()
	s := newCloneSource(t)
	a4 := s.d.append("s-data", "a", op("replace", "/pin", rev("s-data", "b", s.b1)), op("replace", "/live", "/r/s-data/a"))
	b, _ := exportFrom(t, s.d, bundle.ExportOptions{Select: []string{"s-data"}})
	for _, tc := range []struct {
		name    string
		chain   []string // the branches to create, each of the one before, from the first
		renamed bool
	}{
		{"branch", []string{"s-data", "wip"}, false},
		{"branch of a branch", []string{"s-data", "wip", "wip2"}, false},
		{"branch of another namespace", []string{"s-schemas", "other"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dst := newDeployment(t, cmsOrigin)
			if tc.renamed {
				// s-data/a's $schema pins s-schemas/item, which the target
				// needs: only the schemas are there before.
				importB(t, dst, s.schema, bundle.ImportOptions{})
			} else {
				importB(t, dst, s.full, bundle.ImportOptions{})
			}
			for i := 1; i < len(tc.chain); i++ {
				must(dst.c.CreateBranch(ctx, tc.chain[i-1], client.BranchRequest{Name: tc.chain[i]}))
			}
			onto := tc.chain[len(tc.chain)-1]
			rep := importB(t, dst, b, bundle.ImportOptions{NSMap: map[string]string{"s-data": onto}})
			got := dst.doc(onto, "a")
			if tc.renamed {
				// b1 references nothing renamed, so keeps its id.
				if rep.Renamed["s-data"] != onto || !rep.Doc("s-data/a").Renamed || dst.head(onto, "a").ID == a4 ||
					got["pin"] != rev(onto, "b", s.b1) || got["live"] != "/r/"+onto+"/a" {
					t.Fatalf("renamed %v, %s/a %+v: %v", rep.Renamed, onto, rep.Doc("s-data/a"), got)
				}
				return
			}
			if len(rep.Renamed) != 0 {
				t.Fatalf("renamed %v", rep.Renamed)
			}
			if d := rep.Doc("s-data/a"); d.Class != "fast-forward" || d.Renamed || dst.head(onto, "a").ID != a4 {
				t.Fatalf("%s/a %+v", onto, d)
			}
			if got["pin"] != rev("s-data", "b", s.b1) || got["live"] != "/r/s-data/a" {
				t.Fatalf("%s/a %v", onto, got)
			}
			for _, ns := range tc.chain[:len(tc.chain)-1] {
				if dst.head(ns, "a").ID != s.a3 {
					t.Fatalf("the branch's base %s changed", ns)
				}
			}
		})
	}
}

// §G.4.4 Renaming, onto a remote branch (§G.3) of the bundle's origin:
// one whose base is src, or whose base.chain reaches it, is a branch of
// src, so mapping onto it isn't a rename; one of another namespace is.
func TestRenamedImportOntoRemoteBranch(t *testing.T) {
	t.Parallel()
	s := newCloneSource(t)
	at := must(s.d.c.NSHead(ctx, "s-data")).ID
	a4 := s.d.append("s-data", "a", op("replace", "/pin", rev("s-data", "b", s.b1)), op("replace", "/live", "/r/s-data/a"))
	b, _ := exportFrom(t, s.d, bundle.ExportOptions{Select: []string{"s-data"}})
	must(s.d.c.CreateBranch(ctx, "s-data", client.BranchRequest{Name: "wip", At: at}))
	wipAt := must(s.d.c.NSHead(ctx, "wip")).ID
	schemasAt := must(s.d.c.NSHead(ctx, "s-schemas")).ID
	remote := func(o *core.Options) {
		o.Remote = core.RemoteOptions{FollowInterval: -1, Resolve: func(origin string) (core.RemoteEndpoint, error) {
			if origin != stagingOrigin {
				return core.RemoteEndpoint{}, errors.New("unknown origin " + origin)
			}
			return core.RemoteEndpoint{BaseURL: s.d.url}, nil
		}}
	}
	for _, tc := range []struct {
		name, base, at string
		chain          []string // rel's base.chain, as the target records it
		renamed        bool
	}{
		{"remote branch", "s-data", at, []string{"s-data"}, false},
		{"remote branch of a branch", "wip", wipAt, []string{"wip", "s-data"}, false},
		{"remote branch of another namespace", "s-schemas", schemasAt, []string{"s-schemas"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dst := newDeployment(t, cmsOrigin, remote)
			// s-data/a's $schema pins s-schemas/item, which the target needs.
			importB(t, dst, s.schema, bundle.ImportOptions{})
			dst.ns("rel", map[string]any{"read": "public", "base": map[string]any{"origin": stagingOrigin, "ns": tc.base, "at": tc.at}})
			base, _ := dst.nsDoc("rel")["base"].(map[string]any)
			if chain, _ := base["chain"].([]any); !slices.EqualFunc(chain, tc.chain, func(x any, ns string) bool { return x == ns }) {
				t.Fatalf("rel's base %v", base)
			}
			rep := importB(t, dst, b, bundle.ImportOptions{NSMap: map[string]string{"s-data": "rel"}})
			got := dst.doc("rel", "a")
			if tc.renamed {
				if rep.Renamed["s-data"] != "rel" || !rep.Doc("s-data/a").Renamed || dst.head("rel", "a").ID == a4 ||
					got["pin"] != rev("rel", "b", s.b1) || got["live"] != "/r/rel/a" {
					t.Fatalf("renamed %v, rel/a %+v: %v", rep.Renamed, rep.Doc("s-data/a"), got)
				}
				return
			}
			if len(rep.Renamed) != 0 {
				t.Fatalf("renamed %v", rep.Renamed)
			}
			if d := rep.Doc("s-data/a"); d.Class != "fast-forward" || d.Renamed || dst.head("rel", "a").ID != a4 {
				t.Fatalf("rel/a %+v", d)
			}
			if got["pin"] != rev("s-data", "b", s.b1) || got["live"] != "/r/s-data/a" {
				t.Fatalf("rel/a %v", got)
			}
		})
	}
}

// §G.4.4 Renaming, by the CLI: -ns src=dst renames, and the report lists
// the undeclared reference it leaves.
func TestRenamedImportCLI(t *testing.T) {
	t.Parallel()
	s := newCloneSource(t)
	dst := newDeployment(t, cmsOrigin)
	path := t.TempDir() + "/set.jsonl"
	noErr(t, os.WriteFile(path, s.merged, 0o644))
	var out, errb bytes.Buffer
	args := []string{"-api", dst.url, "-i", path, "-author", "alice", "-atomic",
		"-ns", "s-schemas=c-schemas,s-data=c-data,s-refs=c-refs,s-snap=c-snap"}
	if code := bundle.CLI(ctx, "import", args, &out, &errb); code != 0 {
		t.Fatalf("import: %d %s", code, errb.String())
	}
	for _, want := range []string{"(rewritten: new ids)", "undeclared reference in s-data/a at /note, written by " + s.a2, "renames s-data=c-data"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("report lacks %q:\n%s", want, out.String())
		}
	}
	if dst.doc("c-data", "a")["live"] != "/r/c-data/b" {
		t.Fatal("not rewritten")
	}
}

// §G.4.4 Renaming, in a backfill whose batches cut the rewritten chains:
// each batch's source.ids records the source id of the last step it
// writes, and the rewritten documents are as in one batch.
func TestRenamedImportCut(t *testing.T) {
	t.Parallel()
	s := newCloneSource(t)
	d := newDeployment(t, cmsOrigin)
	d.ns("c-data", map[string]any{"read": "public", "limits": map[string]any{"itemsPerBatch": 1, "batchSize": 300}})
	rep := importB(t, d, s.merged, bundle.ImportOptions{NSMap: cloneMap, Mode: bundle.Backfill, Pace: 1})
	checkCloneDocs(t, s, d, rep)
	var got []string
	for _, br := range rep.Batches {
		if br.NS == "c-data" {
			for name, id := range br.Source["ids"].(map[string]any) {
				got = append(got, name+":"+id.(string))
			}
		}
	}
	want := []string{"a:" + s.a1, "a:" + s.a2, "a:" + s.a3, "b:" + s.b2}
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("source.ids of the c-data batches %v, want %v", got, want)
	}
}

// §G.4.4 Renaming: a target that has the start of a rewritten history, as
// a run stopped part-way leaves it, goes on along it (resume), the new ids
// the same.
func TestRenamedImportResume(t *testing.T) {
	t.Parallel()
	s := newCloneSource(t)
	whole := newDeployment(t, cmsOrigin)
	importB(t, whole, s.full, bundle.ImportOptions{NSMap: cloneMap})
	a := whole.chain("c-data", "a")

	d := newDeployment(t, cmsOrigin)
	importB(t, d, s.schema, bundle.ImportOptions{NSMap: cloneMap})
	d.ns("c-data", nil)
	if got := d.create("c-data", "a", whole.at("c-data", "a", a[0])); got != a[0] {
		t.Fatalf("c-data/a genesis %s, want %s", got, a[0])
	}
	rep := importB(t, d, s.full, bundle.ImportOptions{NSMap: cloneMap})
	if r := rep.Doc("s-data/a"); r.Class != "resume" || r.Steps != 2 || !slices.Equal(r.Expected, a[1:]) {
		t.Fatalf("s-data/a %+v", r)
	}
	if !slices.Equal(d.chain("c-data", "a"), a) || d.head("c-refs", "r").ID != whole.head("c-refs", "r").ID {
		t.Fatal("resumed history differs")
	}
}

// §G.4.4 Renaming: a reference written where it isn't declared stays, and
// is reported; once a later step's schema declares its position, that
// step rewrites it with a replace op of its own.
func TestRenamedImportDeclaredLater(t *testing.T) {
	t.Parallel()
	src := newDeployment(t, stagingOrigin)
	src.ns("x", nil)
	plain := src.create("x", "plain", map[string]any{"$schema": schema.Dialect2020, "type": "object"})
	refs := src.create("x", "refs", map[string]any{"$schema": schema.Dialect2020, "type": "object",
		"properties": map[string]any{"note": map[string]any{"type": "string", "x-ref": map[string]any{}}}})
	src.create("x", "other", map[string]any{})
	src.create("x", "d", map[string]any{"$schema": rev("x", "plain", plain), "note": "/r/x/other"})
	r2 := src.append("x", "d", op("replace", "/$schema", rev("x", "refs", refs)))
	b, _ := exportFrom(t, src, bundle.ExportOptions{Select: []string{"x"}})
	dst := newDeployment(t, cmsOrigin)
	rep := importB(t, dst, b, bundle.ImportOptions{NSMap: map[string]string{"x": "y"}})
	if u := rep.Undeclared; len(u) != 1 || u[0].Pointer != "/note" || !u[0].Renamed || u[0].RewrittenFrom != r2 {
		t.Fatalf("undeclared %+v", rep.Undeclared)
	}
	chain := dst.chain("y", "d")
	if got := dst.at("y", "d", chain[0])["note"]; got != "/r/x/other" {
		t.Fatalf("genesis note %v", got)
	}
	if got := dst.doc("y", "d")["note"]; got != "/r/y/other" {
		t.Fatalf("note %v", got)
	}
	found := false
	for _, rw := range rep.Doc("x/d").Rewritten {
		found = found || (rw.Pointer == "/note" && rw.Rev == r2 && rw.To == "/r/y/other")
	}
	if !found {
		t.Fatalf("rewritten %+v", rep.Doc("x/d").Rewritten)
	}
	// The source's step changes only $schema: the rewritten one has a
	// replace op of its own added for /note.
	entries := must(dst.c.Log(ctx, "y", "d", "", ""))
	want := jsonv.FromGo([]any{
		map[string]any{"op": "replace", "path": "/$schema", "value": rev("y", "refs", refs)},
		map[string]any{"op": "replace", "path": "/note", "value": "/r/y/other"},
	})
	if len(entries) != 2 || !jsonv.Equal(entries[1].Patches, want) {
		t.Fatalf("rewritten step %s", jsonv.Canonical(entries[len(entries)-1].Patches))
	}
}

// §G.4.4 Renaming: documents of the bundle's unmapped namespaces that
// reference a renamed one are rewritten too, full-history ones step by
// step with new ids and snapshot ones through their own upstream
// namespace, and keep their namespace; those that don't reference it keep
// their ids.
func TestRenamedImportUnmapped(t *testing.T) {
	t.Parallel()
	src := newDeployment(t, stagingOrigin)
	for _, ns := range []string{"x", "z", "w"} {
		src.ns(ns, nil)
	}
	sch := src.create("x", "s", map[string]any{"$schema": schema.Dialect2020, "type": "object", "properties": map[string]any{
		"live": map[string]any{"type": "string", "x-ref": map[string]any{}},
		"pin":  map[string]any{"type": "string", "x-ref": map[string]any{"pinned": true}},
	}})
	tg := src.create("x", "t", map[string]any{"title": "T"})
	f1 := src.create("z", "f", map[string]any{"$schema": rev("x", "s", sch), "title": "F"})
	f2 := src.append("z", "f", op("add", "/live", "/r/x/t"), op("add", "/pin", rev("x", "t", tg)))
	q := src.create("z", "q", map[string]any{"title": "Q"})
	src.create("w", "p", map[string]any{"$schema": rev("x", "s", sch), "live": "/r/x/t"})
	full, _ := exportFrom(t, src, bundle.ExportOptions{Select: []string{"x", "z"}})
	snap, _ := exportFrom(t, src, bundle.ExportOptions{Select: []string{"w"}, Mode: bundle.Snapshot})
	b := withSnapshots(t, full, snap, "w")

	dst := newDeployment(t, cmsOrigin)
	rep := importB(t, dst, b, bundle.ImportOptions{NSMap: map[string]string{"x": "y"}})
	if len(rep.Renamed) != 1 || rep.Renamed["x"] != "y" {
		t.Fatalf("renamed %v", rep.Renamed)
	}
	// x's documents reference nothing renamed: they keep their ids.
	if dst.head("y", "s").ID != sch || dst.head("y", "t").ID != tg {
		t.Fatalf("y/s %s, y/t %s", dst.head("y", "s").ID, dst.head("y", "t").ID)
	}
	if _, err := dst.c.NSHead(ctx, "x"); !client.IsNotFound(err) {
		t.Fatalf("x written: %v", err)
	}
	schemaRef := rev("y", "s", sch)
	chain := dst.chain("z", "f")
	if r := rep.Doc("z/f"); !r.Renamed || r.Target != "z/f" || len(chain) != 2 || chain[0] == f1 || chain[1] == f2 {
		t.Fatalf("z/f %+v, chain %v", r, chain)
	}
	if got := dst.at("z", "f", chain[0])["$schema"]; got != schemaRef {
		t.Fatalf("z/f's genesis $schema %v", got)
	}
	want := map[string]any{"$schema": schemaRef, "title": "F", "live": "/r/y/t", "pin": rev("y", "t", tg)}
	if got := dst.doc("z", "f"); !jsonv.Equal(jsonv.FromGo(got), jsonv.FromGo(want)) {
		t.Fatalf("z/f %v, want %v", got, want)
	}
	if r := rep.Doc("z/q"); r.Renamed || dst.head("z", "q").ID != q {
		t.Fatalf("z/q %+v", r)
	}
	// The unmapped snapshot document goes through its own namespace's
	// upstream.
	if got := dst.doc("w", "p"); got["$schema"] != schemaRef || got["live"] != "/r/y/t" {
		t.Fatalf("w/p %v", got)
	}
	if up := dst.head("w-upstream", "p"); up.State != client.Live || up.ID != dst.head("w", "p").ID {
		t.Fatalf("w-upstream/p %+v", up)
	}
	for _, ns := range []string{"y-upstream", "x-upstream"} {
		if _, err := dst.c.NSHead(ctx, ns); !client.IsNotFound(err) {
			t.Fatalf("%s written: %v", ns, err)
		}
	}
}

// §G.4.4 Renaming: a renamed namespace's upstream is {dst}-upstream, which
// must fit the name limit of §3.6: one that doesn't is refused at step 1,
// before anything is written, a dry run included; one that fits exactly
// imports, and so does a bundle without snapshot documents, which needs
// no upstream namespace. A source namespace too long for its own upstream
// imports once renamed to a shorter name.
func TestRenamedImportUpstreamName(t *testing.T) {
	t.Parallel()
	s := newCloneSource(t)
	long, fits := strings.Repeat("c", 64), strings.Repeat("c", 64-len("-upstream"))
	mapped := func(ns, to string) map[string]string {
		m := maps.Clone(cloneMap)
		m[ns] = to
		return m
	}
	for _, dry := range []bool{true, false} {
		dst := newDeployment(t, cmsOrigin)
		_, err := bundle.Import(ctx, dst.c, bundle.BytesOpener(s.merged), bundle.ImportOptions{NSMap: mapped("s-snap", long), Mode: bundle.Atomic, CreateNamespaces: true, DryRun: dry})
		want := "s-snap is renamed to " + long + ", whose upstream namespace for its snapshot documents, " + long + "-upstream, is 73 characters, over the 64 a namespace name may have (§3.6, §G.4.4)"
		var ce *bundle.CheckError
		if !errors.As(err, &ce) || len(ce.Problems) != 1 || !strings.Contains(err.Error(), want) {
			t.Fatalf("dry run %v: import: %v, want a CheckError containing %q", dry, err, want)
		}
		for _, ns := range []string{"c-schemas", "c-data", "c-refs", long} {
			if _, err := dst.c.NSHead(ctx, ns); !client.IsNotFound(err) {
				t.Fatalf("dry run %v: %s written: %v", dry, ns, err)
			}
		}
	}

	dst := newDeployment(t, cmsOrigin)
	importB(t, dst, s.merged, bundle.ImportOptions{NSMap: mapped("s-snap", fits)})
	if up := dst.head(fits+"-upstream", "p"); up.State != client.Live || up.ID != dst.head(fits, "p").ID {
		t.Fatalf("%s-upstream/p %+v", fits, up)
	}

	dst = newDeployment(t, cmsOrigin)
	importB(t, dst, s.full, bundle.ImportOptions{NSMap: mapped("s-data", long)})
	if got := dst.doc(long, "a")["live"]; got != "/r/"+long+"/b" {
		t.Fatalf("%s/a live %v", long, got)
	}

	// Only the upstream namespaces the import uses are checked: a partial
	// import that leaves out the renamed s-snap, and holds none of its
	// documents, writes no upstream for it.
	dst = newDeployment(t, cmsOrigin)
	importB(t, dst, s.merged, bundle.ImportOptions{NSMap: mapped("s-snap", long), Only: []string{"s-schemas", "s-data", "s-refs"}})
	if dst.doc("c-data", "a")["live"] != "/r/c-data/b" {
		t.Fatal("c-data/a not imported")
	}
	if _, err := dst.c.NSHead(ctx, long); !client.IsNotFound(err) {
		t.Fatalf("%s written: %v", long, err)
	}
	// One it holds, as a snapshot document it brings pins it, is checked
	// under its upstream path (partial.go): its name is checked too.
	s.d.ns("s-snap2", nil)
	s.d.create("s-snap2", "q", map[string]any{"$schema": rev("s-schemas", "item", s.item), "title": "Q", "pin": rev("s-snap", "p", s.p)})
	snaps, _ := exportFrom(t, s.d, bundle.ExportOptions{Select: []string{"s-snap", "s-snap2"}, Mode: bundle.Snapshot})
	dst = newDeployment(t, cmsOrigin)
	importB(t, dst, s.full, bundle.ImportOptions{})
	_, err := bundle.Import(ctx, dst.c, bundle.BytesOpener(snaps), bundle.ImportOptions{NSMap: map[string]string{"s-snap": long},
		Only: []string{"s-snap2"}, Mode: bundle.Atomic, CreateNamespaces: true})
	var ce *bundle.CheckError
	if !errors.As(err, &ce) || len(ce.Problems) != 1 || !strings.Contains(ce.Problems[0], "s-snap is renamed to "+long+", whose upstream namespace") {
		t.Fatalf("held: import: %v, want a CheckError for s-snap's upstream", err)
	}
	for _, ns := range []string{"s-snap2", "s-snap2-upstream"} {
		if _, err := dst.c.NSHead(ctx, ns); !client.IsNotFound(err) {
			t.Fatalf("held: %s written: %v", ns, err)
		}
	}
	importB(t, dst, snaps, bundle.ImportOptions{NSMap: map[string]string{"s-snap": fits}, Only: []string{"s-snap"}})
	importB(t, dst, snaps, bundle.ImportOptions{NSMap: map[string]string{"s-snap": fits}, Only: []string{"s-snap2"}})
	if q := dst.doc("s-snap2", "q"); q["title"] != "Q" || !strings.HasPrefix(q["pin"].(string), "/r/"+fits+"-upstream/p/rev/") {
		t.Fatalf("held: s-snap2/q %v", q)
	}

	// Not renamed, a source namespace's own upstream name is checked the
	// same way.
	src := newDeployment(t, stagingOrigin)
	ns := strings.Repeat("s", 60)
	src.ns(ns, nil)
	src.create(ns, "p", map[string]any{"title": "P"})
	snap, _ := exportFrom(t, src, bundle.ExportOptions{Select: []string{ns}, Mode: bundle.Snapshot})
	dst = newDeployment(t, cmsOrigin)
	_, err = bundle.Import(ctx, dst.c, bundle.BytesOpener(snap), bundle.ImportOptions{Mode: bundle.Atomic, CreateNamespaces: true})
	want := "the upstream namespace of " + ns + "'s snapshot documents, " + ns + "-upstream, is 69 characters"
	if !errors.As(err, &ce) || !strings.Contains(err.Error(), want) {
		t.Fatalf("import: %v, want a CheckError containing %q", err, want)
	}
	if _, err := dst.c.NSHead(ctx, ns); !client.IsNotFound(err) {
		t.Fatalf("%s written: %v", ns, err)
	}
	if !strings.Contains(err.Error(), "map it to a shorter name (-ns src=dst), or a shorter upstream suffix") {
		t.Fatalf("import: %v, want the hint to rename", err)
	}
	importB(t, dst, snap, bundle.ImportOptions{NSMap: map[string]string{ns: "short"}})
	if dst.head("short-upstream", "p").State != client.Live || dst.doc("short", "p")["title"] != "P" {
		t.Fatal("short/p not imported through short-upstream")
	}
}
