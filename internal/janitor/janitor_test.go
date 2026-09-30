package janitor_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/grant"
	"github.com/middle-management/patchlog/internal/janitor"
	"github.com/middle-management/patchlog/internal/merge"
)

var ctx = context.Background()

const day = 24 * time.Hour

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

func op(o, path string, v any) map[string]any {
	return map[string]any{"op": o, "path": path, "value": v}
}

var devAuthors = map[string]any{"authors": []any{map[string]any{"sub": "alice", "kid": "dev"}}}

type env struct {
	t *testing.T
	s *clienttest.Server
	c *client.Client
}

func newEnv(t *testing.T, baseDoc map[string]any) *env {
	s := clienttest.New(t, clienttest.Options{})
	c := s.Client(t, client.WithAuthor("alice"))
	if baseDoc == nil {
		// Authentication is off: entries carry no kid, so merge.authors
		// matches alice on sub alone (merge.Listed).
		baseDoc = map[string]any{"read": "public", "merge": devAuthors}
	}
	must(c.CreateNamespace(ctx, "matches", baseDoc))
	must(c.CreateDoc(ctx, "matches", "derby", map[string]any{"score": "0-0"}))
	return &env{t: t, s: s, c: c}
}

func (e *env) branch(base, name string, cleanup map[string]any) {
	e.t.Helper()
	br := client.BranchRequest{Name: name}
	if cleanup != nil {
		br.Patches = []any{op("add", "/cleanup", cleanup)}
	}
	must(e.c.CreateBranch(ctx, base, br))
}

func (e *env) edit(ns, name, score string) {
	e.t.Helper()
	h := must(e.c.Head(ctx, ns, name))
	must(e.c.Append(ctx, ns, name, h.ID, []any{op("replace", "/score", score)}))
}

func (e *env) config(ns string, patches ...map[string]any) {
	e.t.Helper()
	h := must(e.c.NSHead(ctx, ns))
	ps := make([]any, len(patches))
	for i, p := range patches {
		ps[i] = p
	}
	must(e.c.PatchConfig(ctx, ns, h.Config, ps))
}

func (e *env) merge(branch string) string {
	e.t.Helper()
	p := must(merge.NewPlan(ctx, e.c, "matches", branch, merge.Options{}))
	return must(p.Apply(ctx)).NSID
}

func (e *env) sweep(dry bool) map[string]janitor.Decision {
	e.t.Helper()
	j := janitor.New(e.c, janitor.Options{Bases: []string{"matches"}, Now: e.s.Clock.Now, DryRun: dry})
	ds, err := j.Sweep(ctx)
	if err != nil {
		e.t.Fatal(err)
	}
	out := map[string]janitor.Decision{}
	for _, d := range ds {
		out[d.NS] = d
	}
	return out
}

func (e *env) purged(ns string) bool {
	e.t.Helper()
	parent := "matches"
	h := must(e.c.NSHead(ctx, ns))
	d := must(e.c.NSDoc(ctx, ns, h.ID))
	if b, ok := d.Value["base"].(map[string]any); ok {
		parent = b["ns"].(string)
	}
	for _, b := range must(e.c.Branches(ctx, parent)) {
		if b.Name == ns {
			return b.Purged
		}
	}
	e.t.Fatalf("%s not listed", ns)
	return false
}

func wantKeep(t *testing.T, d janitor.Decision, reason string) {
	t.Helper()
	if d.Action != janitor.ActionKeep || !strings.Contains(d.Reason, reason) {
		t.Fatalf("decision %+v, want keep with %q", d, reason)
	}
}

func TestPurgesGenuinelyMergedAfterPeriod(t *testing.T) {
	e := newEnv(t, nil)
	e.branch("matches", "r7", map[string]any{"merged": "P7D"})
	e.edit("r7", "derby", "1-0")
	wantKeep(t, e.sweep(false)["r7"], "not frozen")
	at := e.merge("r7")
	must(merge.Freeze(ctx, e.c, "r7", at))

	wantKeep(t, e.sweep(false)["r7"], "cleanup period runs until")
	e.s.Clock.Advance(6 * day)
	wantKeep(t, e.sweep(false)["r7"], "cleanup period")
	e.s.Clock.Advance(2 * day)
	if d := e.sweep(true)["r7"]; d.Action != janitor.ActionWouldPurge || d.Claim != "merged" {
		t.Fatalf("dry run %+v", d)
	}
	if e.purged("r7") {
		t.Fatal("dry run purged")
	}
	d := e.sweep(false)["r7"]
	if d.Action != janitor.ActionPurged || d.Purge == "" {
		t.Fatalf("decision %+v", d)
	}
	if !e.purged("r7") {
		t.Fatal("not purged")
	}
	// The base is untouched.
	if h := must(e.c.Head(ctx, "matches", "derby")); h.State != client.Live {
		t.Fatalf("base derby %+v", h)
	}
}

func TestRefusesForgedMergedClaim(t *testing.T) {
	e := newEnv(t, nil)
	e.branch("matches", "r7", map[string]any{"merged": "P1D"})
	e.edit("r7", "derby", "1-0")
	bh := must(e.c.NSHead(ctx, "matches"))
	must(merge.Freeze(ctx, e.c, "r7", bh.ID)) // claims merged, never merged
	e.s.Clock.Advance(3 * day)
	wantKeep(t, e.sweep(false)["r7"], "merged claim not verified")

	// Merged, then changed again, then frozen: work after the merge is kept.
	e.branch("matches", "r8", map[string]any{"merged": "P1D"})
	e.edit("r8", "derby", "2-0")
	at := e.merge("r8")
	e.edit("r8", "derby", "3-0")
	must(merge.Freeze(ctx, e.c, "r8", at))
	e.s.Clock.Advance(3 * day)
	ds := e.sweep(false)
	wantKeep(t, ds["r8"], "changed documents after")
	if e.purged("r7") || e.purged("r8") {
		t.Fatal("purged on a forged claim")
	}

	// A batch whose source names the branch but whose source.at isn't in its
	// chain can't be written (§7.5 checks local sources), so a forged
	// successor is the remaining case: r7-b exists with the same base but
	// never took r9's work.
	e.branch("matches", "r9", map[string]any{"superseded": "P1D"})
	e.edit("r9", "derby", "4-0")
	e.branch("matches", "r9-b", nil)
	e.config("r9", op("add", "/frozen", true), op("add", "/successor", "r9-b"))
	e.s.Clock.Advance(3 * day)
	wantKeep(t, e.sweep(false)["r9"], "superseded claim not verified")
}

func TestNoOwnEntriesCountsAsMerged(t *testing.T) {
	e := newEnv(t, nil)
	e.branch("matches", "empty", map[string]any{"merged": "PT1H"})
	e.config("empty", op("add", "/frozen", true))
	e.s.Clock.Advance(2 * time.Hour)
	if d := e.sweep(false)["empty"]; d.Action != janitor.ActionPurged || d.Claim != "merged" {
		t.Fatalf("decision %+v", d)
	}
}

func TestDependentsLeavesFirst(t *testing.T) {
	e := newEnv(t, nil)
	e.branch("matches", "r7", map[string]any{"merged": "P1D"})
	e.edit("r7", "derby", "1-0")
	e.branch("r7", "b2", map[string]any{"merged": "P1D"})
	at := e.merge("r7")
	must(merge.Freeze(ctx, e.c, "r7", at))
	e.s.Clock.Advance(2 * day)
	ds := e.sweep(false)
	wantKeep(t, ds["r7"], "has dependents: b2")
	wantKeep(t, ds["b2"], "not frozen")

	// b2 has no document entries of its own: once frozen and expired it goes
	// first, and r7 right after it in the same sweep.
	e.config("b2", op("add", "/frozen", true))
	e.s.Clock.Advance(2 * day)
	ds = e.sweep(false)
	if ds["b2"].Action != janitor.ActionPurged || ds["r7"].Action != janitor.ActionPurged {
		t.Fatalf("decisions %+v", ds)
	}
}

func TestBaseMinimum(t *testing.T) {
	e := newEnv(t, map[string]any{"read": "public", "merge": devAuthors, "cleanup": map[string]any{"merged": "P30D"}})
	e.branch("matches", "r7", map[string]any{"merged": "P1D"}) // shorter than the base allows
	e.edit("r7", "derby", "1-0")
	must(merge.Freeze(ctx, e.c, "r7", e.merge("r7")))
	e.s.Clock.Advance(2 * day)
	wantKeep(t, e.sweep(false)["r7"], "cleanup period runs until")
	e.s.Clock.Advance(29 * day)
	if d := e.sweep(false)["r7"]; d.Action != janitor.ActionPurged {
		t.Fatalf("decision %+v", d)
	}
}

func TestNoPeriodMeansKeep(t *testing.T) {
	e := newEnv(t, nil)
	e.branch("matches", "r7", nil)
	e.edit("r7", "derby", "1-0")
	must(merge.Freeze(ctx, e.c, "r7", e.merge("r7")))
	e.s.Clock.Advance(365 * day)
	wantKeep(t, e.sweep(false)["r7"], "no cleanup period")
}

func TestPurgesSupersededBranch(t *testing.T) {
	e := newEnv(t, nil)
	e.branch("matches", "r7", map[string]any{"superseded": "P2D"})
	e.edit("r7", "derby", "1-0")
	e.edit("matches", "derby", "0-1") // derby replays into the successor... with overlap
	must(e.c.CreateDoc(ctx, "r7", "extra", map[string]any{"n": 1}))
	res, err := merge.Rebase(ctx, e.c, merge.RebaseOptions{Branch: "r7", New: "r7-b", Switch: true})
	if err == nil {
		t.Fatalf("expected a conflict on derby, got %+v", res)
	}
	// Resolve and continue: the rebase resumes into r7-b.
	p := res.First
	if err := p.Resolve("derby", client.PatchStep([]any{op("replace", "/score", "1-1")})); err != nil {
		t.Fatal(err)
	}
	must(p.Apply(ctx))
	res = must(merge.Rebase(ctx, e.c, merge.RebaseOptions{Branch: "r7", New: "r7-b", Switch: true}))
	if !res.Switched {
		t.Fatalf("%+v", res)
	}
	e.s.Clock.Advance(day)
	ds := e.sweep(false)
	wantKeep(t, ds["r7"], "superseded; cleanup period")
	e.s.Clock.Advance(2 * day)
	ds = e.sweep(false)
	if ds["r7"].Action != janitor.ActionPurged || ds["r7"].Claim != "superseded" {
		t.Fatalf("decision %+v", ds["r7"])
	}
	wantKeep(t, ds["r7-b"], "not frozen")
}

func TestAddDuration(t *testing.T) {
	t0 := time.Date(2026, 1, 31, 0, 0, 0, 0, time.UTC)
	for s, want := range map[string]time.Time{
		"P7D":            t0.AddDate(0, 0, 7),
		"P2W":            t0.AddDate(0, 0, 14),
		"PT1H30M":        t0.Add(90 * time.Minute),
		"P1Y2M3DT4H5M6S": t0.AddDate(1, 2, 3).Add(4*time.Hour + 5*time.Minute + 6*time.Second),
		"PT0.5S":         t0.Add(500 * time.Millisecond),
	} {
		got, err := janitor.AddDuration(t0, s)
		if err != nil || !got.Equal(want) {
			t.Fatalf("%s: %v %v, want %v", s, got, err, want)
		}
	}
	for _, s := range []string{"", "P", "PT", "7D", "P1H", "P-1D"} {
		if _, err := janitor.AddDuration(t0, s); err == nil {
			t.Fatalf("%q accepted", s)
		}
	}
}

func TestRunPurgesOnSchedule(t *testing.T) {
	e := newEnv(t, nil)
	e.branch("matches", "r7", map[string]any{"merged": "PT1M"})
	e.edit("r7", "derby", "1-0")
	must(merge.Freeze(ctx, e.c, "r7", e.merge("r7")))
	e.s.Clock.Advance(2 * time.Minute)
	rctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	got := make(chan janitor.Decision, 16)
	j := janitor.New(e.c, janitor.Options{Bases: []string{"matches"}, Now: e.s.Clock.Now, Interval: 50 * time.Millisecond,
		OnDecision: func(d janitor.Decision) {
			select {
			case got <- d:
			default:
			}
		}})
	go j.Run(rctx)
	for {
		select {
		case d := <-got:
			if d.NS == "r7" && d.Action == janitor.ActionPurged {
				return
			}
		case <-rctx.Done():
			t.Fatal("not purged by Run")
		}
	}
}

// With authentication on, a merged claim counts only if the merge batch's
// author (root sub and kid) is in the base's merge.authors.
func TestMergedClaimNeedsListedAuthor(t *testing.T) {
	for _, tc := range []struct {
		name, sub string
		listedKey bool
		want      string
	}{
		{"listed", "svc:merge", true, janitor.ActionPurged},
		{"other sub", "user:ed", true, janitor.ActionKeep},
		{"other kid", "svc:merge", false, janitor.ActionKeep},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := clienttest.New(t, clienttest.Options{Auth: true})
			ops, other := clienttest.NewKey("ops-2026"), clienttest.NewKey("other")
			grantFor := func(k clienttest.Key, sub string) *client.Client {
				return s.Client(t, client.WithBearer(k.Grant(t, s.Now(), sub, []string{"matches", "r7"}, grant.Verbs,
					map[string]any{"exp": s.Now().Add(30 * day).Format(time.RFC3339)})))
			}
			must(s.Client(t, client.WithBearer(s.OperatorGrant(t, "matches"))).CreateNamespace(ctx, "matches", map[string]any{
				"read":  "public",
				"keys":  []any{ops.Entry("*"), other.Entry("*")},
				"merge": map[string]any{"authors": []any{map[string]any{"sub": "svc:merge", "kid": "ops-2026"}}},
			}))
			ed := grantFor(ops, "user:ed")
			e := &env{t: t, s: s, c: ed}
			must(ed.CreateDoc(ctx, "matches", "derby", map[string]any{"score": "0-0"}))
			e.branch("matches", "r7", map[string]any{"merged": "P1D"})
			e.edit("r7", "derby", "1-0")
			k := ops
			if !tc.listedKey {
				k = other
			}
			m := grantFor(k, tc.sub)
			res := must(must(merge.NewPlan(ctx, m, "matches", "r7", merge.Options{})).Apply(ctx))
			must(merge.Freeze(ctx, m, "r7", res.NSID))
			s.Clock.Advance(2 * day)
			j := janitor.New(grantFor(ops, "svc:janitor"), janitor.Options{Bases: []string{"matches"}, Now: s.Clock.Now})
			ds := must(j.Sweep(ctx))
			if len(ds) != 1 || ds[0].Action != tc.want {
				t.Fatalf("decisions %+v, want %s", ds, tc.want)
			}
			if tc.want == janitor.ActionKeep && !strings.Contains(ds[0].Reason, "merge.authors") {
				t.Fatalf("reason %q", ds[0].Reason)
			}
		})
	}
}
