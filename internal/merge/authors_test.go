package merge_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/grant"
	"github.com/middle-management/patchlog/internal/keystore"
	"github.com/middle-management/patchlog/internal/merge"
	"github.com/middle-management/patchlog/internal/seal"
)

// authEnv runs with authentication on, so namespace log entries carry the
// root kid of the grant they were written under. The base lists
// svc:merge/ops-2026 in merge.authors; the ops and other keys are both
// * keys of the base.
type authEnv struct {
	*env
	ops, other clienttest.Key
	editor     *client.Client
}

func newAuthEnv(t *testing.T) *authEnv {
	s := clienttest.New(t, clienttest.Options{Auth: true})
	ops, other := clienttest.NewKey("ops-2026"), clienttest.NewKey("other")
	op := s.Client(t, client.WithBearer(s.OperatorGrant(t, "matches")))
	must(op.CreateNamespace(ctx, "matches", map[string]any{
		"read":  "public",
		"keys":  []any{ops.Entry("*"), other.Entry("*")},
		"merge": map[string]any{"authors": []any{map[string]any{"sub": "svc:merge", "kid": "ops-2026"}}},
	}))
	a := &authEnv{ops: ops, other: other}
	a.editor = s.Client(t, client.WithBearer(ops.Grant(t, s.Now(), "user:ed", []string{"matches", "r7"}, grant.Verbs)))
	a.env = &env{t: t, s: s, c: a.editor}
	a.create("matches", "derby", map[string]any{"title": "Derby", "score": "0-0"})
	a.create("matches", "cup", map[string]any{"title": "Cup", "score": "1-1"})
	a.branch("matches", "r7")
	return a
}

func (a *authEnv) merger(k clienttest.Key, sub string) *client.Client {
	return a.s.Client(a.t, client.WithBearer(k.Grant(a.t, a.s.Now(), sub, []string{"matches", "r7"}, grant.Verbs)))
}

func (a *authEnv) lastEntry(ns string) client.NSEntry {
	a.t.Helper()
	log := must(a.c.NSLog(ctx, ns, must(a.c.NSHead(ctx, ns)).ID, ""))
	return log[len(log)-1]
}

// A second merge after a replayed merge picks up only the new work when the
// earlier batch's author is in merge.authors; by anyone else (another sub,
// or the listed sub under another kid) the batch isn't a merge point and
// the second merge conflicts, with a hint to rebase.
func TestSecondMergeAfterReplayNeedsListedAuthor(t *testing.T) {
	cases := []struct {
		name    string
		key     func(a *authEnv) clienttest.Key
		sub     string
		trusted bool
	}{
		{"listed", func(a *authEnv) clienttest.Key { return a.ops }, "svc:merge", true},
		{"other sub", func(a *authEnv) clienttest.Key { return a.ops }, "user:ed", false},
		{"other kid", func(a *authEnv) clienttest.Key { return a.other }, "svc:merge", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := newAuthEnv(t)
			a.append("r7", "derby", op("replace", "/score", "1-0"))
			a.append("matches", "derby", op("replace", "/title", "Derby!")) // derby replays
			first := a.merger(tc.key(a), tc.sub)
			p1 := must(merge.NewPlan(ctx, first, "matches", "r7", merge.Options{}))
			wantClasses(t, p1, map[string]merge.Class{"derby": merge.Replay})
			res := must(p1.Apply(ctx))
			be := a.lastEntry("matches")
			if be.ID != res.NSID || be.Author != tc.sub || be.Kid != tc.key(a).Kid {
				t.Fatalf("batch entry %+v", be)
			}
			if at, _ := be.Source["at"].(string); at != p1.BranchAt {
				t.Fatalf("source.at %v, want %s", be.Source["at"], p1.BranchAt)
			}

			a.append("r7", "derby", op("replace", "/score", "2-0"))
			listed := a.merger(a.ops, "svc:merge")
			p2 := must(merge.NewPlan(ctx, listed, "matches", "r7", merge.Options{}))
			d := p2.Resource("derby")
			if tc.trusted {
				if d.Class != merge.Replay || d.NeedsPerson() || len(d.Steps) != 1 {
					t.Fatalf("derby %+v", d)
				}
				if d.Pair == nil || !d.Pair.Used || d.Pair.Batch != res.NSID || d.Pair.Author != "svc:merge" || d.Pair.Kid != "ops-2026" || d.Pair.At != p1.BranchAt {
					t.Fatalf("pair %+v", d.Pair)
				}
				if len(p2.Ignored) != 0 {
					t.Fatalf("ignored %+v", p2.Ignored)
				}
				must(p2.Apply(ctx))
				doc := a.doc("matches", "derby").(map[string]any)
				if doc["score"] != "2-0" || doc["title"] != "Derby!" {
					t.Fatalf("doc %v", doc)
				}
				return
			}
			if d.Pair != nil || !d.NeedsPerson() || !hasConflict(d, merge.ConflictOverlap) {
				t.Fatalf("derby %+v", d)
			}
			if len(p2.Ignored) != 1 || p2.Ignored[0].Batch != res.NSID || !strings.Contains(p2.Ignored[0].Reason, "merge.authors") {
				t.Fatalf("ignored %+v", p2.Ignored)
			}
			if !strings.Contains(d.Note, "rebase") || len(p2.Hints()) == 0 || !strings.Contains(p2.Hints()[0], "rebase") {
				t.Fatalf("note %q hints %v", d.Note, p2.Hints())
			}
		})
	}
}

// Without merge.authors there are no merge points, and the plan says so.
func TestNoMergeAuthorsNoMergePoints(t *testing.T) {
	s := clienttest.New(t, clienttest.Options{})
	c := s.Client(t, client.WithAuthor("alice"))
	e := &env{t: t, s: s, c: c}
	must(c.CreateNamespace(ctx, "matches", map[string]any{"read": "public"}))
	e.create("matches", "derby", map[string]any{"title": "Derby", "score": "0-0"})
	e.branch("matches", "r7")
	e.append("r7", "derby", op("replace", "/score", "1-0"))
	e.append("matches", "derby", op("replace", "/title", "Derby!"))
	must(e.plan("matches", "r7", merge.Options{}).Apply(ctx))
	e.append("r7", "derby", op("replace", "/score", "2-0"))
	p := e.plan("matches", "r7", merge.Options{})
	if p.AuthorsDeclared || !p.Resource("derby").NeedsPerson() {
		t.Fatalf("plan %+v derby %+v", p, p.Resource("derby"))
	}
	if h := p.Hints(); len(h) != 1 || !strings.Contains(h[0], "no merge.authors") || !strings.Contains(h[0], "rebase") {
		t.Fatalf("hints %v", h)
	}
}

// source.at is the branch revision the plan was classified from, also
// when a 412 re-classification resubmits after the branch moved on.
func TestSourceAtAfterReclassification(t *testing.T) {
	a := newAuthEnv(t)
	a.append("r7", "derby", op("replace", "/score", "1-0"))
	a.append("r7", "cup", op("replace", "/score", "2-1"))
	m := a.merger(a.ops, "svc:merge")
	p := must(merge.NewPlan(ctx, m, "matches", "r7", merge.Options{}))
	at := p.BranchAt
	a.append("r7", "cup", op("replace", "/score", "3-1"))          // the branch moves on
	a.append("matches", "derby", op("replace", "/title", "Moved")) // and so does the base: 412
	res := must(p.Apply(ctx))
	if res.Attempts != 2 {
		t.Fatalf("attempts %d", res.Attempts)
	}
	if got, _ := a.lastEntry("matches").Source["at"].(string); got != at || p.BranchAt != at {
		t.Fatalf("source.at %s, plan %s, want %s", got, p.BranchAt, at)
	}
	// The branch's newer work is left for the next merge, which fast-
	// forwards cup from the merged revision.
	p2 := must(merge.NewPlan(ctx, m, "matches", "r7", merge.Options{}))
	if c := p2.Resource("cup"); c.Class != merge.FastForward || len(c.Steps) != 1 {
		t.Fatalf("cup %+v", c)
	}
	if p2.BranchAt == at {
		t.Fatal("a new plan must classify from the branch's new head")
	}
}

// Keeping the base's version records the pair with an empty step when the
// base head is live, so a later merge replays only what is new.
func TestKeptAtBaseRecorded(t *testing.T) {
	a := newAuthEnv(t)
	a.append("r7", "derby", op("replace", "/score", "1-0"))
	a.append("matches", "derby", op("replace", "/score", "0-1"))
	m := a.merger(a.ops, "svc:merge")
	p := must(merge.NewPlan(ctx, m, "matches", "r7", merge.Options{}))
	d := p.Resource("derby")
	if !hasConflict(d, merge.ConflictOverlap) {
		t.Fatalf("derby %+v", d)
	}
	before := a.head("matches", "derby").ID
	noErr(t, p.Resolve("derby"))
	if !d.Kept || !d.HasItem() || len(d.Steps) != 1 || d.Steps[0].Delete {
		t.Fatalf("derby %+v", d)
	}
	if ps, ok := d.Steps[0].Patches.([]any); !ok || len(ps) != 0 {
		t.Fatalf("keep step %#v, want []", d.Steps[0].Patches)
	}
	if b, _ := json.Marshal(p.Batch().Items[0].Steps[0].Patches); string(b) != "[]" {
		t.Fatalf("keep step renders %s", b)
	}
	res := must(p.Apply(ctx))
	after := a.head("matches", "derby").ID
	if after == before || res.IDs["derby"][0] != after {
		t.Fatalf("derby not recorded: %s → %s (%v)", before, after, res.IDs)
	}
	if doc := a.doc("matches", "derby").(map[string]any); doc["score"] != "0-1" {
		t.Fatalf("doc %v", doc)
	}
	// The next merge starts from the recorded pair: only the new change.
	a.append("r7", "derby", op("replace", "/title", "Derby 7"))
	p2 := must(merge.NewPlan(ctx, m, "matches", "r7", merge.Options{}))
	d2 := p2.Resource("derby")
	if d2.NeedsPerson() || len(d2.Steps) != 1 || d2.Pair == nil || !d2.Pair.Used || d2.Pair.Target != after {
		t.Fatalf("derby %+v pair %+v", d2, d2.Pair)
	}
	must(p2.Apply(ctx))
	if doc := a.doc("matches", "derby").(map[string]any); doc["score"] != "0-1" || doc["title"] != "Derby 7" {
		t.Fatalf("doc %v", doc)
	}
}

// On a tombstoned base head, keeping can't be recorded: no item, and the
// resource is offered again.
func TestKeptAtTombstoneNotRecorded(t *testing.T) {
	a := newAuthEnv(t)
	a.append("r7", "derby", op("replace", "/score", "1-0"))
	a.append("r7", "cup", op("replace", "/score", "2-1"))
	a.del("matches", "derby")
	m := a.merger(a.ops, "svc:merge")
	p := must(merge.NewPlan(ctx, m, "matches", "r7", merge.Options{}))
	d := p.Resource("derby")
	if !hasConflict(d, merge.ConflictChangeVsDelete) {
		t.Fatalf("derby %+v", d)
	}
	noErr(t, p.Resolve("derby"))
	if d.Kept || d.HasItem() || !strings.Contains(d.Note, "stays unmerged") {
		t.Fatalf("derby %+v", d)
	}
	must(p.Apply(ctx))
	for _, s := range a.lastEntry("matches").Entries {
		if s.Resource == "derby" {
			t.Fatalf("derby recorded: %+v", s)
		}
	}
	if h := a.head("matches", "derby"); h.State != client.Tombstoned {
		t.Fatalf("derby %+v", h)
	}
	p2 := must(merge.NewPlan(ctx, m, "matches", "r7", merge.Options{}))
	if d2 := p2.Resource("derby"); !d2.NeedsPerson() {
		t.Fatalf("derby not offered again: %+v", d2)
	}
}

// In a sealed namespace the keep step only adds a fresh $nonce.
func TestKeptAtBaseSealed(t *testing.T) {
	ks, err := keystore.New(keystore.Generate())
	noErr(t, err)
	s := clienttest.New(t, clienttest.Options{KeyStore: ks})
	c := s.Client(t, client.WithAuthor("alice")).With(client.WithKeys(client.NewKeys(nil)))
	e := &env{t: t, s: s, c: c}
	must(c.CreateNamespace(ctx, "matches", map[string]any{"read": "public", "encryption": map[string]any{"level": "sealed"}, "merge": devAuthors}))
	nonced := func(ps ...map[string]any) []any {
		return append(ops(ps...), op("add", "/$nonce", seal.NewNonce()))
	}
	must(c.Create(ctx, "matches", "derby", nonced(op("add", "", map[string]any{"score": "0-0"}))))
	e.branch("matches", "r7")
	must(c.Append(ctx, "r7", "derby", e.head("r7", "derby").ID, nonced(op("replace", "/score", "1-0"))))
	must(c.Append(ctx, "matches", "derby", e.head("matches", "derby").ID, nonced(op("replace", "/score", "0-1"))))
	p := e.plan("matches", "r7", merge.Options{})
	if p.TargetLevel != "sealed" {
		t.Fatalf("level %q", p.TargetLevel)
	}
	noErr(t, p.Resolve("derby"))
	d := p.Resource("derby")
	ps, _ := d.Steps[0].Patches.([]any)
	if !d.Kept || len(ps) != 1 {
		t.Fatalf("derby %+v", d)
	}
	o, _ := ps[0].(map[string]any)
	if o["op"] != "add" || o["path"] != "/$nonce" || !seal.ValidNonce(o["value"].(string)) {
		t.Fatalf("keep step %v", ps)
	}
	before := e.head("matches", "derby").ID
	must(p.Apply(ctx))
	if e.head("matches", "derby").ID == before {
		t.Fatal("not recorded")
	}
	if doc := e.doc("matches", "derby").(map[string]any); doc["score"] != "0-1" {
		t.Fatalf("doc %v", doc)
	}
}

// The plan and status report, per resource, which merge batch and author
// the common-ancestor pair came from.
func TestPairProvenanceReported(t *testing.T) {
	a := newAuthEnv(t)
	a.append("r7", "derby", op("replace", "/score", "1-0"))
	a.append("matches", "derby", op("replace", "/title", "Derby!"))
	m := a.merger(a.ops, "svc:merge")
	res := must(must(merge.NewPlan(ctx, m, "matches", "r7", merge.Options{})).Apply(ctx))
	a.append("r7", "derby", op("replace", "/score", "2-0"))
	p := must(merge.NewPlan(ctx, m, "matches", "r7", merge.Options{}))
	st := p.Status()
	if len(st) != 1 || st[0].Pair == nil || st[0].Pair.Batch != res.NSID {
		t.Fatalf("status %+v", st)
	}
	line := st[0].Pair.String()
	for _, want := range []string{res.NSID, "svc:merge/ops-2026"} {
		if !strings.Contains(line, want) {
			t.Fatalf("%q lacks %q", line, want)
		}
	}
	b := must(json.Marshal(p))
	for _, want := range []string{`"pair":{"batch":"` + res.NSID + `","author":"svc:merge","kid":"ops-2026"`, `"used":true`} {
		if !strings.Contains(string(b), want) {
			t.Fatalf("plan JSON lacks %s: %s", want, b)
		}
	}
}

func TestListed(t *testing.T) {
	authors := []merge.Author{{Sub: "svc:merge", Kid: "ops-2026"}}
	for _, tc := range []struct {
		sub, kid string
		want     bool
	}{
		{"svc:merge", "ops-2026", true},
		{"svc:merge", "other", false},
		{"user:ed", "ops-2026", false},
		{"svc:merge", "", true}, // development mode: no kid recorded
		{"", "", false},
	} {
		if got := merge.Listed(authors, tc.sub, tc.kid); got != tc.want {
			t.Fatalf("Listed(%q, %q) = %v", tc.sub, tc.kid, got)
		}
	}
}
