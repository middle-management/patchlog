package bundle_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/bundle"
	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/jsonv"
)

func lines(b []byte) [][]byte {
	return bytes.Split(bytes.TrimRight(b, "\n"), []byte("\n"))
}

func join(ls [][]byte) []byte { return append(bytes.Join(ls, []byte("\n")), '\n') }

func verifyErr(t *testing.T, b []byte, want string) {
	t.Helper()
	_, err := bundle.Verify(bytes.NewReader(b))
	if err == nil {
		t.Fatalf("verify accepted a bad bundle (want %q)", want)
	}
	if !errors.Is(err, bundle.ErrInvalid) || !strings.Contains(err.Error(), want) {
		t.Fatalf("verify: %v, want an invalid-bundle error containing %q", err, want)
	}
}

// editHeader rewrites the header line.
func editHeader(t *testing.T, b []byte, fn func(h map[string]any)) []byte {
	ls := lines(b)
	h := jsonv.MustParse(ls[0]).(map[string]any)
	fn(h)
	ls[0] = jsonv.Canonical(h)
	return join(ls)
}

func TestHistoryRoundTrip(t *testing.T) { t.Parallel(); testHistoryRoundTrip(t) }

func testHistoryRoundTrip(t *testing.T) {
	f := newFixture(t)
	b, _, sum := f.export(t, bundle.ExportOptions{Select: []string{"matches/derby"}})
	want := []string{"matches/cup", "matches/derby", "matches/layout", "media/photo", "schemas/common", "schemas/match"}
	var got []string
	for k, d := range sum.Header.Docs {
		got = append(got, k)
		if d.History != bundle.Full {
			t.Errorf("%s: history %s", k, d.History)
		}
	}
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Fatalf("docs %v, want %v", got, want)
	}
	if sum.Header.Origin != stagingOrigin || len(sum.Header.At) != 3 {
		t.Fatalf("header %+v", sum.Header)
	}
	if v := must(bundle.Verify(bytes.NewReader(b))); v.Digest != sum.Digest || v.Lines != sum.Lines {
		t.Fatalf("verify %+v, export %+v", v, sum)
	}

	dst := newDeployment(t, cmsOrigin)
	rep := importB(t, dst, b, bundle.ImportOptions{})
	for _, k := range want {
		ns, name, _ := bundle.SplitKey(k)
		if s, d := f.src.head(ns, name), dst.head(ns, name); s.ID != d.ID || d.State != client.Live {
			t.Fatalf("%s: source %+v, target %+v", k, s, d)
		}
		if c := rep.Doc(k).Class; c != "create" {
			t.Errorf("%s: class %s", k, c)
		}
	}
	// Dependencies first: schemas and media before matches.
	idx := func(ns string) int { return slices.Index(rep.Order, ns) }
	if idx("schemas") < 0 || idx("schemas") > idx("matches") || idx("media") > idx("matches") {
		t.Fatalf("order %v", rep.Order)
	}
	// Each batch records source { origin, ns, at, bundle, ids }.
	nh := must(dst.c.NSHead(ctx, "matches"))
	log := must(dst.c.NSLog(ctx, "matches", nh.ID, ""))
	last := log[len(log)-1]
	src := last.Source
	if last.Kind != "batch" || src["origin"] != stagingOrigin || src["ns"] != "matches" || src["at"] != sum.Header.At["matches"] ||
		src["bundle"] != sum.Digest || src["ids"].(map[string]any)["derby"] != f.derby {
		t.Fatalf("batch entry %+v", last)
	}

	// Re-importing is idempotent: everything is present, nothing written.
	rep2 := importB(t, dst, b, bundle.ImportOptions{})
	for _, d := range rep2.Docs {
		if d.Class != "present" {
			t.Errorf("re-import %s: %s", d.Doc, d.Class)
		}
	}
	if len(rep2.Batches) != 0 {
		t.Fatalf("re-import wrote batches %+v", rep2.Batches)
	}
	if nh2 := must(dst.c.NSHead(ctx, "matches")); nh2.ID != nh.ID {
		t.Fatal("re-import moved the namespace")
	}

	// An incremental bundle fast-forwards from what the target has.
	f.src.append("matches", "derby", op("replace", "/score", "3-1"))
	inc, _, isum := f.export(t, bundle.ExportOptions{Select: []string{"matches/derby"}, Requires: map[string]string{"matches/derby": f.derby}})
	if isum.Header.Requires["matches/derby"] != f.derby {
		t.Fatalf("requires %v", isum.Header.Requires)
	}
	rep3 := importB(t, dst, inc, bundle.ImportOptions{})
	if d := rep3.Doc("matches/derby"); d.Class != "fast-forward" || d.Steps != 1 {
		t.Fatalf("incremental %+v", d)
	}
	if s, d := f.src.head("matches", "derby"), dst.head("matches", "derby"); s.ID != d.ID {
		t.Fatal("incremental import changed ids")
	}
}

func TestVerifyCatchesTampering(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	b, _, sum := f.export(t, bundle.ExportOptions{Select: []string{"matches/derby"}})

	// The digest is the truncated SHA-256 of the canonical lines, which is
	// the file itself for a bundle the Writer wrote, and doesn't depend on
	// whitespace.
	h := sha256.Sum256(b)
	var id ids.ID
	copy(id[:], h[:])
	if sum.Digest != id.String() {
		t.Fatalf("digest %s, want %s", sum.Digest, id)
	}
	var spaced [][]byte
	for _, l := range lines(b) {
		spaced = append(spaced, append([]byte("  "), l...))
	}
	if v := must(bundle.Verify(bytes.NewReader(join(spaced)))); v.Digest != sum.Digest {
		t.Fatal("whitespace changed the digest")
	}

	// A tampered patch set: its id no longer matches.
	verifyErr(t, bytes.Replace(b, []byte(`"Derby"`), []byte(`"Derbx"`), 1), "does not match its content")
	// Truncated: the last line is missing.
	ls := lines(b)
	verifyErr(t, join(ls[:len(ls)-1]), "truncated")
	// A header head that isn't the chain's last line.
	verifyErr(t, editHeader(t, b, func(h map[string]any) {
		h["docs"].(map[string]any)["matches/cup"].(map[string]any)["head"] = f.layout
	}), "not the header's head")
	// A docs entry without lines.
	var noPhoto [][]byte
	for _, l := range ls {
		if !bytes.Contains(l, []byte(`"ns":"media"`)) {
			noPhoto = append(noPhoto, l)
		}
	}
	verifyErr(t, join(noPhoto), "has no lines")
	// requires that the chain doesn't start after.
	verifyErr(t, editHeader(t, b, func(h map[string]any) {
		h["requires"] = map[string]any{"matches/derby": f.cup}
	}), "must start right after requires")
	// A chain that starts after its parent without requires (a missing requires).
	var noGenesis [][]byte
	dropped := false
	for _, l := range ls {
		if !dropped && bytes.Contains(l, []byte(`"resource":"derby"`)) {
			dropped = true
			continue
		}
		noGenesis = append(noGenesis, l)
	}
	verifyErr(t, join(noGenesis), "must start at genesis")
	// Lines out of order.
	sw := slices.Clone(ls)
	for i := 1; i < len(sw)-1; i++ {
		if bytes.Contains(sw[i], []byte(`"resource":"match"`)) {
			sw[i], sw[i+1] = sw[i+1], sw[i]
			break
		}
	}
	verifyErr(t, join(sw), "chain")
	// Authors in a bundle without authors.
	verifyErr(t, bytes.Replace(b, []byte(`"kind":"rev"`), []byte(`"author":"mallory","kind":"rev"`), 1), "without authors")

	// The importer checks requires against the target: nothing is written.
	inc, _, _ := f.export(t, bundle.ExportOptions{Select: []string{"matches/cup"}, Requires: map[string]string{"schemas/match": f.matchV1}})
	dst := newDeployment(t, cmsOrigin)
	_, err := bundle.Import(ctx, dst.c, bundle.BytesOpener(inc), bundle.ImportOptions{Mode: bundle.Atomic, CreateNamespaces: true})
	var ce *bundle.CheckError
	if !errors.As(err, &ce) || !strings.Contains(err.Error(), "requires") {
		t.Fatalf("import with a missing requires: %v", err)
	}
	if h := dst.head("schemas", "common"); h.State != client.NotFound {
		t.Fatal("a failed check wrote something")
	}

	// A tampered bundle is rejected by the importer before anything is written.
	_, err = bundle.Import(ctx, dst.c, bundle.BytesOpener(bytes.Replace(b, []byte(`"Derby"`), []byte(`"Derbx"`), 1)),
		bundle.ImportOptions{Mode: bundle.Atomic, CreateNamespaces: true})
	if !errors.Is(err, bundle.ErrInvalid) {
		t.Fatalf("import of a tampered bundle: %v", err)
	}
}

func TestWriterRefusesBadBundles(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	h := bundle.Header{Origin: stagingOrigin, Created: "2026-09-25T10:00:00Z", At: map[string]string{"n": ids.Of([]byte("x")).String()},
		Docs: map[string]bundle.DocInfo{"n/a": {History: bundle.Snapshot, Head: ids.Of([]byte("a")).String()}}}
	w := must(bundle.NewWriter(&buf, h))
	if err := w.SnapshotDoc("n", "a", ids.Of([]byte("b")).String(), map[string]any{}, false); err == nil {
		t.Fatal("wrote a snapshot that isn't the head")
	}
	if _, err := w.Close(); err == nil {
		t.Fatal("closed a bundle with a docs entry without lines")
	}
	buf.Reset()
	w = must(bundle.NewWriter(&buf, h))
	noErr(t, w.SnapshotDoc("n", "a", h.Docs["n/a"].Head, map[string]any{"x": 1}, false))
	d := must(w.Close())
	if s := must(bundle.Verify(&buf)); s.Digest != d {
		t.Fatalf("digest %s != %s", s.Digest, d)
	}
}

func TestClosure(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	p := must(bundle.PlanExport(ctx, f.src.c, bundle.ExportOptions{Select: []string{"matches/derby"}, Mode: bundle.Snapshot}))
	modes := map[string]string{}
	for k, d := range p.Docs {
		modes[k] = d.Mode
	}
	want := map[string]string{
		"matches/derby": bundle.Snapshot, "matches/layout": bundle.Snapshot, "matches/cup": bundle.Snapshot, "media/photo": bundle.Snapshot,
		"schemas/match": bundle.Full, "schemas/common": bundle.Full,
	}
	if fmt.Sprint(modes) != fmt.Sprint(want) {
		t.Fatalf("modes %v, want %v", modes, want)
	}
	if r := strings.Join(p.Docs["schemas/common"].Reasons, ";"); !strings.Contains(r, "$ref") {
		t.Fatalf("common reasons %q", r)
	}
	if r := strings.Join(p.Docs["matches/cup"].Reasons, ";"); !strings.Contains(r, "live x-ref") {
		t.Fatalf("cup reasons %q", r)
	}

	// Full mode closes downward: pinned targets become full, and every
	// exported revision's $schema is included (derby used match v1, then v2).
	pf := must(bundle.PlanExport(ctx, f.src.c, bundle.ExportOptions{Select: []string{"matches/derby"}}))
	for k, d := range pf.Docs {
		if d.Mode != bundle.Full {
			t.Errorf("full export: %s is %s", k, d.Mode)
		}
	}
	var buf bytes.Buffer
	sum := must(pf.Write(ctx, &buf))
	if !bytes.Contains(buf.Bytes(), []byte(f.matchV1)) || sum.Header.Docs["schemas/match"].Head != f.matchV2 {
		t.Fatal("schema history missing")
	}

	// A pinned reference to a revision other than the head forces full.
	f.src.append("matches", "derby", op("replace", "/hero", rev("media", "photo", f.photo1)))
	p2 := must(bundle.PlanExport(ctx, f.src.c, bundle.ExportOptions{Select: []string{"matches/derby"}, Mode: bundle.Snapshot}))
	if d := p2.Docs["media/photo"]; d.Mode != bundle.Full || !strings.Contains(strings.Join(d.Reasons, ";"), "not its head") {
		t.Fatalf("photo %+v", d)
	}

	// external leaves dependencies out; the importer checks them.
	b, p3, s3 := f.export(t, bundle.ExportOptions{Select: []string{"matches/derby"}, Mode: bundle.Snapshot, External: []string{"media"}})
	if _, in := p3.Docs["media/photo"]; in || !slices.Equal(s3.Header.External, []string{"media/photo/rev/" + f.photo1}) {
		t.Fatalf("external %v, docs %v", s3.Header.External, p3.Docs)
	}
	dst := newDeployment(t, cmsOrigin)
	_, err := bundle.Import(ctx, dst.c, bundle.BytesOpener(b), bundle.ImportOptions{Mode: bundle.Atomic, CreateNamespaces: true})
	var ce *bundle.CheckError
	if !errors.As(err, &ce) || !strings.Contains(err.Error(), "external media/photo") {
		t.Fatalf("missing external: %v", err)
	}

	// Application resolvers add what no schema expresses; untyped
	// references are opt-in.
	f.src.create("media", "album", map[string]any{"cover": "/r/media/photo"})
	res := bundle.ResolverFunc(func(_ context.Context, _ *client.Client, ns, name string, _ any) ([]bundle.Target, error) {
		if ns == "matches" && name == "cup" {
			return []bundle.Target{{NS: "media", Name: "album"}}, nil
		}
		return nil, nil
	})
	p4 := must(bundle.PlanExport(ctx, f.src.c, bundle.ExportOptions{Select: []string{"matches/cup"}, Resolvers: []bundle.Resolver{res}}))
	if _, in := p4.Docs["media/album"]; !in {
		t.Fatal("resolver target missing")
	}
	if _, in := p4.Docs["media/photo"]; in {
		t.Fatal("untyped reference followed without opt-in")
	}
	p5 := must(bundle.PlanExport(ctx, f.src.c, bundle.ExportOptions{Select: []string{"matches/cup"}, Resolvers: []bundle.Resolver{res}, UntypedRefs: true}))
	if _, in := p5.Docs["media/photo"]; !in {
		t.Fatal("untyped reference not followed")
	}
}

func TestSnapshotImportThroughUpstream(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	// A pinned string the schema doesn't declare.
	f.src.append("matches", "derby", op("add", "/note", rev("matches", "layout", f.layout)))
	b, _, sum := f.export(t, bundle.ExportOptions{Select: []string{"matches/derby"}, Mode: bundle.Snapshot})
	if sum.Header.Docs["matches/derby"].History != bundle.Snapshot || sum.Header.Docs["schemas/match"].History != bundle.Full {
		t.Fatalf("docs %+v", sum.Header.Docs)
	}
	dst := newDeployment(t, cmsOrigin)
	dry := must(bundle.Import(ctx, dst.c, bundle.BytesOpener(b), bundle.ImportOptions{Mode: bundle.Atomic, DryRun: true, CreateNamespaces: true}))
	if len(dry.Undeclared) != 1 || dry.Undeclared[0].Pointer != "/note" || !dry.Undeclared[0].Bundled {
		t.Fatalf("undeclared %+v", dry.Undeclared)
	}
	if h := dst.head("schemas", "match"); h.State != client.NotFound {
		t.Fatal("dry run wrote")
	}

	rep := importB(t, dst, b, bundle.ImportOptions{})
	for _, n := range []string{"derby", "layout", "cup"} {
		up, tg := dst.head("matches-upstream", n), dst.head("matches", n)
		if up.State != client.Live || up.ID != tg.ID {
			t.Fatalf("%s: upstream %+v, target %+v (the first import fast-forwards)", n, up, tg)
		}
	}
	upLayout, upPhoto := dst.head("matches-upstream", "layout").ID, dst.head("media-upstream", "photo").ID
	derby := dst.doc("matches", "derby")
	if derby["trigger"] != rev("matches-upstream", "layout", upLayout)+"#t-42" {
		t.Fatalf("trigger %v", derby["trigger"])
	}
	if derby["hero"] != rev("media-upstream", "photo", upPhoto) {
		t.Fatalf("hero %v", derby["hero"])
	}
	if derby["note"] != rev("matches", "layout", f.layout) {
		t.Fatalf("an undeclared string was rewritten: %v", derby["note"])
	}
	if dst.doc("media-upstream", "photo")["url"] != "https://img.example/2.jpg" || len(rep.Doc("matches/derby").Rewritten) != 2 {
		t.Fatalf("report %+v", rep.Doc("matches/derby"))
	}
	// Upstream ids depend only on the snapshots: the upstream genesis is
	// the snapshot itself (after rewriting).
	if up := dst.head("media-upstream", "photo").ID; up != must(client.ExpectedRevision("", client.GenesisPatches(f.src.doc("media", "photo")))) {
		t.Fatal("upstream id is not the genesis of the snapshot")
	}
	// Schemas kept their ids.
	if dst.head("schemas", "match").ID != f.matchV2 {
		t.Fatal("schema ids changed")
	}
	derbyUp1 := dst.head("matches-upstream", "derby").ID

	// Both sides change different fields: the upstream revision replays
	// onto the target's head.
	f.src.append("matches", "derby", op("replace", "/score", "1-0"))
	dst.append("matches", "derby", op("replace", "/title", "Derby!"))
	b2, _, _ := f.export(t, bundle.ExportOptions{Select: []string{"matches/derby"}, Mode: bundle.Snapshot})
	rep2 := importB(t, dst, b2, bundle.ImportOptions{})
	if d := rep2.Doc("matches/derby"); d.Class != "replay" || d.Upstream.Class != "append" || d.Ancestor != derbyUp1 {
		t.Fatalf("second import %+v %+v", d, d.Upstream)
	}
	if d := rep2.Doc("matches/layout"); d.Class != "present" || d.Upstream.Class != "unchanged" {
		t.Fatalf("layout %+v", d)
	}
	if d := dst.doc("matches", "derby"); d["score"] != "1-0" || d["title"] != "Derby!" {
		t.Fatalf("merged derby %v", d)
	}

	// Idempotent.
	rep3 := importB(t, dst, b2, bundle.ImportOptions{})
	if len(rep3.Batches) != 0 || rep3.Doc("matches/derby").Class != "present" {
		t.Fatalf("re-import %+v", rep3.Doc("matches/derby"))
	}

	// Both sides change the same field: a conflict in the dry run.
	f.src.append("matches", "derby", op("replace", "/score", "2-0"))
	dst.append("matches", "derby", op("replace", "/score", "9-9"))
	b3, _, _ := f.export(t, bundle.ExportOptions{Select: []string{"matches/derby"}, Mode: bundle.Snapshot})
	dry3 := must(bundle.Import(ctx, dst.c, bundle.BytesOpener(b3), bundle.ImportOptions{Mode: bundle.Atomic, DryRun: true}))
	d3 := dry3.Doc("matches/derby")
	if !d3.Unresolved || len(d3.Conflicts) != 1 || d3.Conflicts[0].Kind != "overlap" || !slices.Contains(d3.Conflicts[0].Paths, "/score") {
		t.Fatalf("dry run %+v", d3)
	}
	if _, err := bundle.Import(ctx, dst.c, bundle.BytesOpener(b3), bundle.ImportOptions{Mode: bundle.Atomic}); !errors.Is(err, bundle.ErrConflicts) {
		t.Fatalf("import with a conflict: %v", err)
	}
	rep4 := importB(t, dst, b3, bundle.ImportOptions{Resolutions: map[string]bundle.Resolution{"matches/derby": bundle.ResolveTake}})
	if d := dst.doc("matches", "derby"); d["score"] != "2-0" || rep4.Doc("matches/derby").Class != "take" {
		t.Fatalf("take: %v", d)
	}
	// The upstream chain is the sequence of snapshots as imported.
	up := must(dst.c.Log(ctx, "matches-upstream", "derby", "", ""))
	if len(up) != 3 {
		t.Fatalf("upstream chain %d entries", len(up))
	}
}

func TestFullImportOntoMovedTarget(t *testing.T) { t.Parallel(); testFullImportOntoMovedTarget(t) }

func testFullImportOntoMovedTarget(t *testing.T) {
	f := newFixture(t)
	b, _, _ := f.export(t, bundle.ExportOptions{Select: []string{"matches/derby"}})
	dst := newDeployment(t, cmsOrigin)
	importB(t, dst, b, bundle.ImportOptions{})

	f.src.append("matches", "derby", op("replace", "/score", "1-0"))
	dst.append("matches", "derby", op("replace", "/title", "Derby (cms)"))
	dst.append("matches", "cup", op("replace", "/title", "Cup (cms)"))
	b2, _, _ := f.export(t, bundle.ExportOptions{Select: []string{"matches/derby"}})
	rep := must(bundle.Import(ctx, dst.c, bundle.BytesOpener(b2), bundle.ImportOptions{Mode: bundle.Atomic, DryRun: true}))
	d := rep.Doc("matches/derby")
	if d.Class != "conflict" || !d.Unresolved || d.Ancestor != f.derby || d.Conflicts[0].Kind != bundle.ConflictDiverged {
		t.Fatalf("derby %+v", d)
	}
	for _, c := range d.Conflicts {
		if c.Kind == "overlap" {
			t.Fatalf("unexpected overlap %+v", c)
		}
	}
	if c := rep.Doc("matches/cup"); c.Class != "behind" {
		t.Fatalf("cup %+v", c)
	}
	if _, err := bundle.Import(ctx, dst.c, bundle.BytesOpener(b2), bundle.ImportOptions{Mode: bundle.Atomic}); !errors.Is(err, bundle.ErrConflicts) {
		t.Fatalf("want ErrConflicts, got %v", err)
	}
	rep2 := importB(t, dst, b2, bundle.ImportOptions{Resolutions: map[string]bundle.Resolution{"matches/derby": bundle.ResolveReplay}})
	if rep2.Doc("matches/derby").Class != "replay" {
		t.Fatalf("replay %+v", rep2.Doc("matches/derby"))
	}
	if doc := dst.doc("matches", "derby"); doc["score"] != "1-0" || doc["title"] != "Derby (cms)" {
		t.Fatalf("replayed derby %v", doc)
	}
}

// bulkSource has a namespace with seven documents, one with a long chain.
func bulkSource(t *testing.T) []byte {
	src := newDeployment(t, stagingOrigin)
	src.ns("bulk", nil)
	for i := 0; i < 6; i++ {
		src.create("bulk", fmt.Sprintf("doc-%d", i), map[string]any{"i": i})
	}
	src.create("bulk", "long", map[string]any{"v": 0})
	for i := 1; i <= 6; i++ {
		src.append("bulk", "long", op("replace", "/v", strings.Repeat("x", 300)+fmt.Sprint(i)))
	}
	var buf bytes.Buffer
	_, _, err := bundle.Export(ctx, src.c, &buf, bundle.ExportOptions{Select: []string{"bulk"}})
	noErr(t, err)
	return buf.Bytes()
}

func bulkTarget(t *testing.T) *deployment {
	dst := newDeployment(t, cmsOrigin)
	dst.ns("bulk", map[string]any{
		"limits": map[string]any{"itemsPerBatch": 3, "batchSize": 1 << 10},
		"allowances": []any{map[string]any{"sub": "svc:importer", "kid": "ops-2026", "bucket": map[string]any{"rate": 1000, "burst": 1000},
			"itemsPerBatch": 50, "batchSize": 1 << 20}},
	})
	return dst
}

func TestAtomicAndBackfill(t *testing.T) {
	t.Parallel()
	b := bulkSource(t)
	longHead := ""
	for _, l := range lines(b)[1:] {
		m := jsonv.MustParse(l).(map[string]any)
		if m["resource"] == "long" {
			longHead = m["id"].(string)
		}
	}

	// Atomic without an allowance: 413, explained, nothing written.
	dst := bulkTarget(t)
	bob := dst.c.With(client.WithAuthor("bob"))
	rep, err := bundle.Import(ctx, bob, bundle.BytesOpener(b), bundle.ImportOptions{Mode: bundle.Atomic})
	var tl *bundle.TooLargeError
	if !errors.As(err, &tl) || !strings.Contains(err.Error(), "allowance") || !strings.Contains(err.Error(), "413") {
		t.Fatalf("atomic import without an allowance: %v", err)
	}
	if len(rep.Batches) != 1 || rep.Batches[0].DryRun != "failed" {
		t.Fatalf("report %+v", rep.Batches)
	}
	if h := dst.head("bulk", "doc-0"); h.State != client.NotFound {
		t.Fatal("a failed atomic import wrote")
	}

	// Backfill: split to fit the limits (items and bytes, cutting the long
	// chain), paced at a fraction of the rate. The clock stands still, so
	// no batch takes any of its wait.
	var sleeps []time.Duration
	now := time.Now()
	rep = must(bundle.Import(ctx, bob, bundle.BytesOpener(b), bundle.ImportOptions{Mode: bundle.Backfill, Pace: 0.5,
		Sleep: func(_ context.Context, d time.Duration) error { sleeps = append(sleeps, d); return nil },
		Now:   func() time.Time { return now }}))
	if len(rep.Batches) < 4 {
		t.Fatalf("backfill batches %d", len(rep.Batches))
	}
	longParts := 0
	for _, br := range rep.Batches {
		if len(br.Resources) > 3 || br.NSID == "" {
			t.Fatalf("batch %+v", br)
		}
		if slices.Contains(br.Resources, "long") {
			longParts++
		}
	}
	if longParts < 2 {
		t.Fatalf("the long chain wasn't split: %d parts", longParts)
	}
	if len(sleeps) != len(rep.Batches) {
		t.Fatalf("sleeps %v", sleeps)
	}
	// 3 items at 0.5 × min(500/s namespace, 50/s principal).
	if want := time.Duration(float64(len(rep.Batches[0].Resources)) / 25 * float64(time.Second)); sleeps[0] != want {
		t.Fatalf("pace %v, want %v", sleeps[0], want)
	}
	if br := rep.Batches[0]; br.PacedBy != "ratePerPrincipal" || br.Rate != 25 {
		t.Fatalf("paced by %q at %v", br.PacedBy, br.Rate)
	}
	if h := dst.head("bulk", "long"); h.ID != longHead {
		t.Fatalf("long head %s, want %s (ids kept across parts)", h.ID, longHead)
	}

	// Atomic with an allowance: one batch.
	dst2 := bulkTarget(t)
	imp := dst2.c.With(client.WithAuthor("svc:importer"))
	rep = must(bundle.Import(ctx, imp, bundle.BytesOpener(b), bundle.ImportOptions{Mode: bundle.Atomic}))
	if len(rep.Batches) != 1 || len(rep.Batches[0].Resources) != 7 || rep.Batches[0].NSID == "" {
		t.Fatalf("atomic batches %+v", rep.Batches)
	}
	if h := dst2.head("bulk", "long"); h.ID != longHead {
		t.Fatal("atomic import changed ids")
	}
	// Retrying is harmless.
	rep = must(bundle.Import(ctx, imp, bundle.BytesOpener(b), bundle.ImportOptions{Mode: bundle.Atomic}))
	if len(rep.Batches) != 0 {
		t.Fatalf("re-import %+v", rep.Batches)
	}

	// The mode is explicit.
	if _, err := bundle.Import(ctx, imp, bundle.BytesOpener(b), bundle.ImportOptions{}); err == nil || !strings.Contains(err.Error(), "choose a mode") {
		t.Fatalf("no mode: %v", err)
	}
}

func TestCLI(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "release.jsonl")
	var out, errb bytes.Buffer
	if code := bundle.CLI(ctx, "export", []string{"-api", f.src.url, "-ns", "matches", "-resource", "derby", "-mode", "snapshot", "-o", path}, &out, &errb); code != 0 {
		t.Fatalf("export: %d %s", code, errb.String())
	}
	b := must(os.ReadFile(path))
	sum := must(bundle.Verify(bytes.NewReader(b)))

	out.Reset()
	errb.Reset()
	if code := bundle.CLI(ctx, "bundle", []string{"verify", "-i", path}, &out, &errb); code != 0 || !strings.Contains(out.String(), sum.Digest) {
		t.Fatalf("verify: %d %q %q", code, out.String(), errb.String())
	}
	bad := filepath.Join(dir, "bad.jsonl")
	noErr(t, os.WriteFile(bad, bytes.Replace(b, []byte(f.matchV1), []byte(f.matchV2), 1), 0o644))
	errb.Reset()
	if code := bundle.CLI(ctx, "bundle", []string{"verify", "-i", bad}, &out, &errb); code != 1 || !strings.Contains(errb.String(), "bundle:") {
		t.Fatalf("verify of a tampered bundle: %d %q", code, errb.String())
	}

	dst := newDeployment(t, cmsOrigin)
	errb.Reset()
	if code := bundle.CLI(ctx, "import", []string{"-api", dst.url, "-ns", "matches", "-i", path, "-author", "alice"}, &out, &errb); code != 1 ||
		!strings.Contains(errb.String(), "-atomic") {
		t.Fatalf("import without a mode: %d %q", code, errb.String())
	}
	out.Reset()
	if code := bundle.CLI(ctx, "import", []string{"-api", dst.url, "-ns", "matches", "-i", path, "-author", "alice", "-atomic", "-dry-run", "-json"}, &out, &errb); code != 0 {
		t.Fatalf("dry run: %d %s", code, errb.String())
	}
	var rep bundle.Report
	noErr(t, json.Unmarshal(out.Bytes(), &rep))
	if !rep.DryRun || rep.Doc("matches/derby") == nil {
		t.Fatalf("dry-run report %s", out.String())
	}
	out.Reset()
	if code := bundle.CLI(ctx, "import", []string{"-api", dst.url, "-ns", "matches", "-i", path, "-author", "alice", "-pace", "1"}, &out, &errb); code != 0 {
		t.Fatalf("import: %d %s", code, errb.String())
	}
	if dst.head("matches-upstream", "derby").State != client.Live {
		t.Fatalf("not imported: %s", out.String())
	}

	// -ns maps the one document namespace into another (e.g. a branch).
	dst2 := newDeployment(t, cmsOrigin)
	full := filepath.Join(dir, "full.jsonl")
	if code := bundle.CLI(ctx, "export", []string{"-api", f.src.url, "-ns", "matches", "-resource", "cup", "-o", full}, &out, &errb); code != 0 {
		t.Fatalf("export: %s", errb.String())
	}
	if code := bundle.CLI(ctx, "import", []string{"-api", dst2.url, "-ns", "staging", "-i", full, "-author", "alice", "-atomic"}, &out, &errb); code != 0 {
		t.Fatalf("mapped import: %s", errb.String())
	}
	if dst2.head("staging", "cup").ID != f.cup || dst2.head("schemas", "match").ID != f.matchV2 {
		t.Fatal("mapped import")
	}
}

func TestSnapshotDeletion(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	dst := newDeployment(t, cmsOrigin)
	b, _, _ := f.export(t, bundle.ExportOptions{Select: []string{"matches/cup"}, Mode: bundle.Snapshot})
	importB(t, dst, b, bundle.ImportOptions{})
	must(f.src.c.Delete(ctx, "matches", "cup", f.cup))
	b2, _, s2 := f.export(t, bundle.ExportOptions{Select: []string{"matches/cup"}, Mode: bundle.Snapshot})
	if !bytes.Contains(b2, []byte(`"deleted":true`)) || s2.Header.Docs["matches/cup"].Head != f.src.head("matches", "cup").ID {
		t.Fatalf("deleted snapshot line missing:\n%s", b2)
	}
	rep := importB(t, dst, b2, bundle.ImportOptions{})
	if d := rep.Doc("matches/cup"); d.Upstream.Class != "delete" || d.Class != "fast-forward" {
		t.Fatalf("cup %+v %+v", d, d.Upstream)
	}
	up, tg := dst.head("matches-upstream", "cup"), dst.head("matches", "cup")
	if up.State != client.Tombstoned || tg.ID != up.ID {
		t.Fatalf("upstream %+v, target %+v", up, tg)
	}
}

// branchSource has a base "matches" and a branch "r7" of it with a
// read-through resource (cup), a resource continuing from its foreign
// parent (derby) and a resource the branch created (final).
func branchSource(t *testing.T) (*deployment, map[string]string) {
	src := newDeployment(t, stagingOrigin)
	src.ns("matches", nil)
	src.create("matches", "derby", map[string]any{"score": "0-0", "title": "Derby"})
	base := map[string]string{"derby": src.append("matches", "derby", op("replace", "/score", "1-0"))}
	base["cup"] = src.create("matches", "cup", map[string]any{"title": "Cup"})
	must(src.c.CreateBranch(ctx, "matches", client.BranchRequest{Name: "r7"}))
	src.append("r7", "derby", op("replace", "/score", "2-0"))
	src.append("r7", "derby", op("add", "/note", "late goal"))
	src.create("r7", "final", map[string]any{"title": "Final"})
	return src, base
}

func exportFrom(t *testing.T, d *deployment, opt bundle.ExportOptions) ([]byte, *bundle.Summary) {
	t.Helper()
	var buf bytes.Buffer
	_, s, err := bundle.Export(ctx, d.c, &buf, opt)
	noErr(t, err)
	must(bundle.Verify(bytes.NewReader(buf.Bytes())))
	return buf.Bytes(), s
}

func sameHeads(t *testing.T, a *deployment, ans string, b *deployment, bns string, names ...string) {
	t.Helper()
	for _, n := range names {
		if ha, hb := a.head(ans, n), b.head(bns, n); ha.ID != hb.ID || ha.State != hb.State {
			t.Fatalf("%s: %s/%s %+v, %s/%s %+v", n, ans, n, ha, bns, n, hb)
		}
	}
}

func TestBranchExport(t *testing.T) { t.Parallel(); testBranchExport(t) }

func testBranchExport(t *testing.T) {
	src, base := branchSource(t)
	baseBundle, _ := exportFrom(t, src, bundle.ExportOptions{Select: []string{"matches"}})

	// Default: chains include the base's entries back to genesis, under
	// the branch's name (§G.4.1), so the bundle stands alone.
	b, sum := exportFrom(t, src, bundle.ExportOptions{Select: []string{"r7"}})
	if len(sum.Header.Docs) != 3 || len(sum.Header.Requires) != 0 || sum.Header.Docs["r7/cup"].Head != base["cup"] {
		t.Fatalf("header %+v", sum.Header)
	}
	if bytes.Contains(b, []byte(`"ns":"matches"`)) {
		t.Fatal("a line names the base namespace; ns is always the exporting namespace")
	}

	// Into an empty deployment: the branch becomes a plain namespace with
	// the same ids, the base's history included.
	empty := newDeployment(t, cmsOrigin)
	importB(t, empty, b, bundle.ImportOptions{})
	sameHeads(t, src, "r7", empty, "r7", "derby", "cup", "final")
	if l := must(empty.c.Log(ctx, "r7", "derby", "", "")); len(l) != 4 {
		t.Fatalf("derby chain %d entries", len(l))
	}

	// Into a deployment that has the base: mapped onto it, the branch's
	// changes fast-forward.
	withBase := newDeployment(t, cmsOrigin)
	importB(t, withBase, baseBundle, bundle.ImportOptions{})
	rep := importB(t, withBase, b, bundle.ImportOptions{NSMap: map[string]string{"r7": "matches"}})
	if d := rep.Doc("r7/derby"); d.Class != "fast-forward" || d.Steps != 2 || d.TargetHead != base["derby"] {
		t.Fatalf("derby %+v", d)
	}
	if rep.Doc("r7/cup").Class != "present" || rep.Doc("r7/final").Class != "create" {
		t.Fatalf("report %+v %+v", rep.Doc("r7/cup"), rep.Doc("r7/final"))
	}
	sameHeads(t, src, "r7", withBase, "matches", "derby", "cup", "final")

	// Into a branch of the base on the target: read-through resources are
	// present, and derby fast-forwards from its foreign parent.
	withBranch := newDeployment(t, cmsOrigin)
	importB(t, withBranch, baseBundle, bundle.ImportOptions{})
	must(withBranch.c.CreateBranch(ctx, "matches", client.BranchRequest{Name: "r7"}))
	rep = importB(t, withBranch, b, bundle.ImportOptions{})
	if rep.Doc("r7/derby").Class != "fast-forward" || rep.Doc("r7/cup").Class != "present" {
		t.Fatalf("into a branch: %+v %+v", rep.Doc("r7/derby"), rep.Doc("r7/cup"))
	}
	sameHeads(t, src, "r7", withBranch, "r7", "derby", "cup", "final")
	if withBranch.head("matches", "derby").ID != base["derby"] {
		t.Fatal("the target's base changed")
	}

	// ForeignParents: chains start after the foreign parent, named in
	// requires; the read-through resource is a pinned external.
	fb, fsum := exportFrom(t, src, bundle.ExportOptions{Select: []string{"r7"}, ForeignParents: true})
	if fsum.Header.Requires["r7/derby"] != base["derby"] || len(fsum.Header.Docs) != 2 ||
		!slices.Equal(fsum.Header.External, []string{"r7/cup/rev/" + base["cup"]}) {
		t.Fatalf("foreign-parent header %+v", fsum.Header)
	}
	var e *bundle.CheckError
	if _, err := bundle.Import(ctx, newDeployment(t, cmsOrigin).c, bundle.BytesOpener(fb), bundle.ImportOptions{Mode: bundle.Atomic, CreateNamespaces: true}); !errors.As(err, &e) {
		t.Fatalf("foreign-parent bundle into an empty deployment: %v", err)
	}
	withBase2 := newDeployment(t, cmsOrigin)
	importB(t, withBase2, baseBundle, bundle.ImportOptions{})
	rep = importB(t, withBase2, fb, bundle.ImportOptions{NSMap: map[string]string{"r7": "matches"}})
	if d := rep.Doc("r7/derby"); d.Class != "fast-forward" || d.Steps != 2 {
		t.Fatalf("derby %+v", d)
	}
	sameHeads(t, src, "r7", withBase2, "matches", "derby", "cup", "final")
}
