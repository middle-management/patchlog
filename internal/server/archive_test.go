package server

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/archive"
	"github.com/middle-management/patchlog/internal/bundle"
	"github.com/middle-management/patchlog/internal/core"
)

// withArchive configures a file:// archiver with default destination def
// and extra allowed roots (plain paths).
func withArchive(t *testing.T, def string, roots ...string) envOpt {
	return func(o *core.Options) {
		var urls []string
		for _, r := range roots {
			urls = append(urls, archive.URL(r))
		}
		d := ""
		if def != "" {
			d = archive.URL(def)
		}
		a, err := archive.NewDir(d, urls...)
		if err != nil {
			t.Fatal(err)
		}
		o.Archiver = a
	}
}

func withoutRetentionLoop(o *core.Options) { o.RetentionInterval = -1 }

func verifyArchive(t *testing.T, path string) *bundle.Summary {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("archive: %v", err)
	}
	defer f.Close()
	s, err := bundle.Verify(f)
	if err != nil {
		t.Fatalf("archive %s: %v", path, err)
	}
	return s
}

func (e *tenv) prune(ns, name string, body map[string]any, who string) *resp {
	e.t.Helper()
	q := req{method: "POST", path: "/r/" + ns + "/" + name + "/prune", body: body}
	if e.auth {
		q.bearer = who
	} else {
		q.author = who
	}
	return e.do(q)
}

// chain creates ns/name with n revisions and returns their ids.
func (e *tenv) chain(ns, name string, n int, who ...string) []string {
	e.t.Helper()
	revs := []string{e.create(ns, name, map[string]any{"n": 0.0}, who...)}
	for i := 1; i < n; i++ {
		revs = append(revs, e.appendRev(ns, name, revs[i-1], ops(op("replace", "/n", float64(i))), who...))
	}
	return revs
}

// §8.6 archive: the pruned range is a verified full-history bundle; the 410
// links to it; a second prune archives incrementally with requires; restore
// brings everything back with identical ids.
func TestArchivePruneAndRestore(t *testing.T) {
	dir := t.TempDir()
	e := newEnv(t, withArchive(t, dir), withoutRetentionLoop)
	e.mkNS("main", map[string]any{"read": "public"})
	revs := e.chain("main", "a", 6)
	fullLog := e.get("/r/main/a/rev/" + revs[5] + "/log")
	expect(t, fullLog, 200)

	e.clock.Advance(time.Hour)
	r := e.prune("main", "a", map[string]any{"horizon": revs[3]}, "admin")
	expect(t, r, 200)
	p1 := filepath.Join(dir, "main", "a", revs[3]+".jsonl")
	url1 := archive.URL(p1)
	if r.Str("archive") != url1 || r.Str("horizon") != revs[3] {
		t.Fatalf("prune answer %s, want archive %s", r.Body, url1)
	}
	s := verifyArchive(t, p1)
	h := s.Header
	if s.Lines != 3 || h.Docs["main/a"].Head != revs[2] || h.Docs["main/a"].History != bundle.Full || len(h.Requires) != 0 || !h.Authors || h.Origin != "https://cms.example" {
		t.Fatalf("archive 1: %d lines, header %+v", s.Lines, h)
	}
	g := e.get("/r/main/a/rev/" + revs[1])
	expectCode(t, g, 410, "pruned")
	if g.Str("archive") != url1 || g.Str("horizon") != revs[3] {
		t.Fatalf("410 %s", g.Body)
	}
	lg := e.get("/r/main/a/rev/" + revs[5] + "/log")
	expectCode(t, lg, 410, "pruned")
	if lg.Str("archive") != url1 {
		t.Fatalf("log 410 %s", lg.Body)
	}
	expect(t, e.get("/r/main/a/rev/"+revs[3]), 200)

	// Second prune: incremental, requires the first archive's head.
	revs = append(revs, e.appendRev("main", "a", revs[5], ops(op("replace", "/n", 6.0))))
	revs = append(revs, e.appendRev("main", "a", revs[6], ops(op("replace", "/n", 7.0))))
	e.clock.Advance(time.Hour)
	r = e.prune("main", "a", map[string]any{"horizon": revs[6]}, "admin")
	expect(t, r, 200)
	p2 := filepath.Join(dir, "main", "a", revs[6]+".jsonl")
	s2 := verifyArchive(t, p2)
	if s2.Lines != 3 || s2.Header.Requires["main/a"] != revs[2] || s2.Header.Docs["main/a"].Head != revs[5] {
		t.Fatalf("archive 2: %d lines, header %+v", s2.Lines, s2.Header)
	}
	if g := e.get("/r/main/a/rev/" + revs[4]); g.Str("archive") != archive.URL(p2) {
		t.Fatalf("410 in the second archive %s", g.Body)
	}
	if g := e.get("/r/main/a/rev/" + revs[0]); g.Str("archive") != url1 {
		t.Fatalf("410 in the first archive %s", g.Body)
	}

	// Offline restore, from a moved archive directory.
	moved := t.TempDir()
	if err := os.Rename(filepath.Join(dir, "main"), filepath.Join(moved, "main")); err != nil {
		t.Fatal(err)
	}
	reps, err := archive.Restore(context.Background(), e.e, archive.RestoreOptions{From: archive.URL(moved)})
	if err != nil {
		t.Fatal(err)
	}
	if len(reps) != 1 || !reps[0].Cleared || reps[0].Restored != 6 || len(reps[0].Failed) != 0 {
		t.Fatalf("restore %+v", reps)
	}
	for i, id := range revs {
		d := e.get("/r/main/a/rev/" + id)
		expect(t, d, 200)
		if d.Obj()["n"] != float64(i) {
			t.Fatalf("restored rev %d: %s", i, d.Body)
		}
	}
	lg = e.get("/r/main/a/rev/" + revs[5] + "/log")
	expect(t, lg, 200)
	if string(canonical(lg.JSON())) != string(canonical(fullLog.JSON())) {
		t.Fatalf("restored log differs:\n%s\n%s", lg.Body, fullLog.Body)
	}
	// Writes continue; restoring again changes nothing.
	e.appendRev("main", "a", revs[7], ops(op("replace", "/n", 8.0)))
	reps, err = archive.Restore(context.Background(), e.e, archive.RestoreOptions{From: archive.URL(moved)})
	if err != nil || reps[0].Restored != 0 {
		t.Fatalf("second restore %+v %v", reps, err)
	}
}

// A restore with a missing archive leaves the horizon; tampered lines are
// skipped; purged resources are skipped (§8.3).
func TestArchiveRestorePartialAndPurged(t *testing.T) {
	dir := t.TempDir()
	e := newEnv(t, withArchive(t, dir), withoutRetentionLoop)
	e.mkNS("main", map[string]any{"read": "public"})
	a := e.chain("main", "a", 4)
	b := e.chain("main", "b", 3)
	e.clock.Advance(time.Hour)
	expect(t, e.prune("main", "a", map[string]any{"horizon": a[2]}, "admin"), 200)
	expect(t, e.prune("main", "b", map[string]any{"horizon": b[2]}, "admin"), 200)
	a = append(a, e.appendRev("main", "a", a[3], ops(op("replace", "/n", 4.0))))
	e.clock.Advance(time.Hour)
	expect(t, e.prune("main", "a", map[string]any{"horizon": a[4]}, "admin"), 200)
	// Lose a's first archive.
	os.Remove(filepath.Join(dir, "main", "a", a[2]+".jsonl"))
	reps, err := archive.Restore(context.Background(), e.e, archive.RestoreOptions{NS: "main", Name: "a"})
	if err != nil {
		t.Fatal(err)
	}
	if len(reps) != 1 || reps[0].Cleared || reps[0].Restored != 2 || len(reps[0].Failed) != 1 {
		t.Fatalf("partial restore %+v", reps)
	}
	expectCode(t, e.get("/r/main/a/rev/"+a[0]), 410, "pruned")
	expect(t, e.get("/r/main/a/rev/"+a[4]), 200)

	// Purge b: its archive is deleted and restore skips it.
	pb := filepath.Join(dir, "main", "b", b[2]+".jsonl")
	if _, err := os.Stat(pb); err != nil {
		t.Fatal(err)
	}
	expect(t, e.purge("main", "b", b[2], "admin"), 204)
	if _, err := os.Stat(pb); !os.IsNotExist(err) {
		t.Fatalf("purge left the archive: %v", err)
	}
	reps, err = archive.Restore(context.Background(), e.e, archive.RestoreOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range reps {
		if r.Name == "b" {
			t.Fatalf("restore saw purged b: %+v", reps)
		}
	}
}

// §8.3: purge reaches archives, also through propagation and namespace purge.
func TestArchivePurge(t *testing.T) {
	dir := t.TempDir()
	e := newEnv(t, withArchive(t, dir), withoutRetentionLoop)
	e.mkNS("main", map[string]any{"read": "public"})
	e.mkNS("other", map[string]any{"read": "public"})
	a := e.chain("main", "a", 3)
	o := e.chain("other", "x", 3)
	e.clock.Advance(time.Hour)
	expect(t, e.prune("main", "a", map[string]any{"horizon": a[2]}, "admin"), 200)
	expect(t, e.prune("other", "x", map[string]any{"horizon": o[2]}, "admin"), 200)
	pa := filepath.Join(dir, "main", "a", a[2]+".jsonl")
	po := filepath.Join(dir, "other", "x", o[2]+".jsonl")
	verifyArchive(t, pa)
	verifyArchive(t, po)
	expect(t, e.branch("main", map[string]any{"name": "br"}, "alice"), 201)
	expect(t, e.purge("main", "a", a[2], "admin"), 204)
	if _, err := os.Stat(pa); !os.IsNotExist(err) {
		t.Fatalf("resource purge left the archive: %v", err)
	}
	expect(t, e.get("/r/br/a"), 410)
	// Namespace purge.
	expect(t, e.patchNS("other", ops(op("add", "/frozen", true)), ""), 201)
	expect(t, e.do(req{method: "POST", path: "/ns/other/purge", ifMatch: e.nsHead("other"), author: "admin"}), 204)
	if _, err := os.Stat(po); !os.IsNotExist(err) {
		t.Fatalf("namespace purge left the archive: %v", err)
	}
}

// §8.6: the prune verb suffices with an archive and within retention;
// otherwise a * key is needed.
func TestArchivePruneAuth(t *testing.T) {
	// No archive configured: only a * key prunes.
	f := newAuthFixture(t, nil, withoutRetentionLoop)
	e := f.tenv
	pruner := e.grant(f.issuer, "user:p", []string{"sec"}, []string{"read", "create", "append", "prune"})
	revs := e.chain("sec", "a", 5, pruner)
	e.clock.Advance(time.Hour)
	pruner = e.grant(f.issuer, "user:p", []string{"sec"}, []string{"read", "create", "append", "prune"})
	adminG := e.grant(f.admin, "user:root", []string{"sec"}, allVerbs)
	expectCode(t, e.prune("sec", "a", map[string]any{"horizon": revs[2]}, pruner), 403, "forbidden")
	r := e.prune("sec", "a", map[string]any{"horizon": revs[2]}, adminG)
	expect(t, r, 200)
	if r.Str("archive") != "" {
		t.Fatalf("archive without an archiver: %s", r.Body)
	}

	// With an archive, and retention keeping the last 3 revisions.
	dir := t.TempDir()
	f = newAuthFixture(t, map[string]any{"retention": []any{map[string]any{"keep": map[string]any{"revisions": 3.0}}}}, withArchive(t, dir), withoutRetentionLoop)
	e = f.tenv
	pruner = e.grant(f.issuer, "user:p", []string{"sec"}, []string{"read", "create", "append", "prune"})
	revs = e.chain("sec", "a", 6, pruner)
	e.clock.Advance(time.Hour)
	pruner = e.grant(f.issuer, "user:p", []string{"sec"}, []string{"read", "create", "append", "prune"})
	adminG = e.grant(f.admin, "user:root", []string{"sec"}, allVerbs)
	noPrune := e.grant(f.issuer, "user:p", []string{"sec"}, []string{"read", "append"})
	expectCode(t, e.prune("sec", "a", map[string]any{"horizon": revs[2]}, noPrune), 403, "forbidden")
	r = e.prune("sec", "a", map[string]any{"horizon": revs[2]}, pruner)
	expect(t, r, 200)
	verifyArchive(t, filepath.Join(dir, "sec", "a", revs[2]+".jsonl"))
	// revs[3] is the oldest of the last 3: pruning to it is within retention.
	expect(t, e.prune("sec", "a", map[string]any{"horizon": revs[3]}, pruner), 200)
	// Going below what retention keeps.
	r = e.prune("sec", "a", map[string]any{"horizon": revs[4]}, pruner)
	expectCode(t, r, 403, "forbidden")
	expect(t, e.prune("sec", "a", map[string]any{"horizon": revs[4]}, adminG), 200)
	g := e.get("/r/sec/a/rev/"+revs[3], adminG)
	expectCode(t, g, 410, "pruned")
	if g.Str("archive") != archive.URL(filepath.Join(dir, "sec", "a", revs[4]+".jsonl")) {
		t.Fatalf("410 %s", g.Body)
	}
}

// §8.6: archive destinations are only those the operator allows (422).
func TestArchiveDestinations(t *testing.T) {
	root := t.TempDir()
	def := filepath.Join(root, "default")
	allowed := filepath.Join(root, "allowed")
	e := newEnv(t, withArchive(t, def, allowed), withoutRetentionLoop)
	rule := func(dest string) map[string]any {
		return map[string]any{"retention": []any{map[string]any{"keep": map[string]any{"age": "P1D"}, "archive": dest}}}
	}
	for _, bad := range []string{"file:///elsewhere/x", "s3://bucket/x", archive.URL(root), archive.URL(allowed) + "/../x", "file://host/" + allowed} {
		q := req{method: "PATCH", path: "/ns/bad", ifNoneMatch: "*", body: addRoot(rule(bad)), author: "admin"}
		expectCode(t, e.do(q), 422, "invalid")
	}
	// Malformed retention.
	for _, bad := range []any{
		[]any{map[string]any{}},
		[]any{map[string]any{"keep": map[string]any{}}},
		[]any{map[string]any{"keep": map[string]any{"revisions": -1.0}}},
		[]any{map[string]any{"keep": map[string]any{"age": "soon"}}},
		[]any{map[string]any{"keep": map[string]any{"age": "P1D"}, "select": map[string]any{"prefix": "a", "names": []any{"b"}}}},
		[]any{map[string]any{"keep": map[string]any{"age": "P1D"}, "other": 1.0}},
	} {
		q := req{method: "PATCH", path: "/ns/bad", ifNoneMatch: "*", body: addRoot(map[string]any{"retention": bad}), author: "admin"}
		expectCode(t, e.do(q), 422, "invalid")
	}
	e.mkNS("good", rule(archive.URL(filepath.Join(allowed, "good"))))
	expectCode(t, e.patchNS("good", ops(op("replace", "/retention/0/archive", "file:///tmp/x")), ""), 422, "invalid")
	expect(t, e.patchNS("good", ops(op("replace", "/retention/0/archive", archive.URL(def)+"/sub")), ""), 201)

	// The rule's destination is used.
	e.mkNS("tel", rule(archive.URL(filepath.Join(allowed, "tel"))))
	revs := e.chain("tel", "a", 3)
	e.clock.Advance(48 * time.Hour)
	r := e.prune("tel", "a", map[string]any{"horizon": revs[2]}, "admin")
	expect(t, r, 200)
	verifyArchive(t, filepath.Join(allowed, "tel", "tel", "a", revs[2]+".jsonl"))

	// Without an archiver no rule may name an archive.
	e2 := newEnv(t, withoutRetentionLoop)
	q := req{method: "PATCH", path: "/ns/n", ifNoneMatch: "*", body: addRoot(rule("file:///x")), author: "admin"}
	expectCode(t, e2.do(q), 422, "invalid")
}

// §8.6 retention policy: the applier prunes per rule, keeps whichever is
// longer, respects the retry window and branch points, and skips branches.
func TestRetentionApplier(t *testing.T) {
	dir := t.TempDir()
	e := newEnv(t, withArchive(t, dir), withoutRetentionLoop)
	e.mkNS("tel", map[string]any{"read": "public", "retention": []any{
		map[string]any{"select": map[string]any{"prefix": "telemetry-"}, "keep": map[string]any{"revisions": 2.0}},
		map[string]any{"select": map[string]any{"names": []any{"b"}}, "keep": map[string]any{"age": "PT1H", "revisions": 1.0}},
		map[string]any{"select": map[string]any{"names": []any{"k"}}, "keep": map[string]any{"age": "PT1H", "revisions": 3.0}},
	}})
	x := e.chain("tel", "telemetry-x", 6)
	z := e.chain("tel", "telemetry-z", 2)
	expect(t, e.branch("tel", map[string]any{"name": "tel-br"}, "alice"), 201) // at z[1]
	b := e.chain("tel", "b", 2)
	k := e.chain("tel", "k", 5)
	c := e.chain("tel", "c", 4) // no rule
	for i := 2; i < 5; i++ {
		z = append(z, e.appendRev("tel", "telemetry-z", z[i-1], ops(op("replace", "/n", float64(i)))))
	}
	q := e.chain("tel-br", "telemetry-q", 5) // a branch's own chain
	e.clock.Advance(2 * time.Hour)
	b = append(b, e.appendRev("tel", "b", b[1], ops(op("replace", "/n", 2.0))))
	b = append(b, e.appendRev("tel", "b", b[2], ops(op("replace", "/n", 3.0))))
	e.clock.Advance(10 * time.Minute)
	y := e.chain("tel", "telemetry-y", 4) // inside the retry window

	rep, err := e.e.ApplyRetention(context.Background())
	if err != nil || len(rep.Errors) > 0 {
		t.Fatalf("retention %+v %v", rep, err)
	}
	gone := func(ns, name string, revs []string, below int) {
		t.Helper()
		for i, id := range revs {
			g := e.get("/r/" + ns + "/" + name + "/rev/" + id)
			if i < below {
				if g.Code != 410 {
					t.Fatalf("%s rev %d: %d %s", name, i, g.Code, g.Body)
				}
				if g.Str("archive") == "" {
					t.Fatalf("%s rev %d: no archive: %s", name, i, g.Body)
				}
			} else {
				expect(t, g, 200)
			}
		}
	}
	gone("tel", "telemetry-x", x, 4) // last 2 kept
	gone("tel", "b", b, 2)           // age keeps b[2], b[3] (more than 1 revision)
	gone("tel", "k", k, 2)           // 3 revisions keep more than the age
	gone("tel", "c", c, 0)
	gone("tel", "telemetry-z", z, 1)    // the branch point z[1] is protected
	gone("tel", "telemetry-y", y, 0)    // retry window
	gone("tel-br", "telemetry-q", q, 0) // branches don't prune
	if rep.Pruned != 4 {
		t.Fatalf("pruned %d resources, want 4: %+v", rep.Pruned, rep)
	}
	verifyArchive(t, filepath.Join(dir, "tel", "telemetry-x", x[4]+".jsonl"))
	// The prune entries are authored by the system principal.
	lg := e.get("/ns/tel/rev/" + e.nsHead("tel") + "/log").Arr()
	last := lg[len(lg)-1].(map[string]any)
	if last["kind"] != "prune" || last["author"] != core.RetentionAuthor {
		t.Fatalf("last ns entry %v", last)
	}
	// A second run changes nothing.
	head := e.nsHead("tel")
	rep, err = e.e.ApplyRetention(context.Background())
	if err != nil || rep.Pruned != 0 || e.nsHead("tel") != head {
		t.Fatalf("second run %+v %v", rep, err)
	}
}
