package bundle_test

import (
	"bytes"
	"errors"
	"io"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/annot"
	"github.com/middle-management/patchlog/internal/bundle"
	"github.com/middle-management/patchlog/internal/client"
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

	for _, tc := range []struct {
		name string
		b    []byte
		opt  bundle.ImportOptions
		want string
	}{
		{"incremental", inc, bundle.ImportOptions{NSMap: cloneMap}, "is incremental (requires " + s.a2},
		{"external schema", extSchemas, bundle.ImportOptions{NSMap: cloneMap},
			"its schema " + rev("s-schemas", "item", s.item) + " can't be rewritten: it pins revision " + s.item + " of s-schemas/item, which the bundle doesn't carry (external)"},
		// Not renamed, the schema is a missing external, as without renaming.
		{"missing external", extSchemas, bundle.ImportOptions{NSMap: map[string]string{"s-data": "c-data"}},
			"external s-schemas/item/rev/" + s.item + ": revision " + s.item + " is not in the target"},
		{"external pin", ext, bundle.ImportOptions{NSMap: cloneMap}, "pins revision " + s.a3 + " of s-data/a, which the bundle doesn't carry"},
		{"left out", s.full, bundle.ImportOptions{NSMap: cloneMap, Only: []string{"s-refs"}}, "which the import leaves out (-only)"},
		{"schema $id", crafted.Bytes(), bundle.ImportOptions{NSMap: cloneMap}, "whose $id names its own revision path"},
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
			for _, ns := range []string{"c-schemas", "c-data", "c-refs"} {
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

// §G.4.4 Renaming: a mapping onto a branch of the source namespace, as an
// import into a branch first, renames nothing: references stay, and the
// branch fast-forwards with the source's ids.
func TestRenamedImportOntoBranch(t *testing.T) {
	t.Parallel()
	s := newCloneSource(t)
	dst := newDeployment(t, cmsOrigin)
	importB(t, dst, s.full, bundle.ImportOptions{})
	must(dst.c.CreateBranch(ctx, "s-data", client.BranchRequest{Name: "wip"}))
	a4 := s.d.append("s-data", "a", op("replace", "/pin", rev("s-data", "b", s.b1)), op("replace", "/live", "/r/s-data/a"))
	b, _ := exportFrom(t, s.d, bundle.ExportOptions{Select: []string{"s-data"}})
	rep := importB(t, dst, b, bundle.ImportOptions{NSMap: map[string]string{"s-data": "wip"}})
	if len(rep.Renamed) != 0 {
		t.Fatalf("renamed %v", rep.Renamed)
	}
	if d := rep.Doc("s-data/a"); d.Class != "fast-forward" || d.Renamed || dst.head("wip", "a").ID != a4 {
		t.Fatalf("wip/a %+v", d)
	}
	if got := dst.doc("wip", "a"); got["pin"] != rev("s-data", "b", s.b1) || got["live"] != "/r/s-data/a" {
		t.Fatalf("wip/a %v", got)
	}
	if dst.head("s-data", "a").ID != s.a3 {
		t.Fatal("the branch's base changed")
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
}
