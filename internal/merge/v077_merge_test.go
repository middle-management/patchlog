package merge_test

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/merge"
	"github.com/middle-management/patchlog/internal/release"
)

// frozenWith reports whether ns is frozen, and its successor.
func (e *env) frozenWith(ns string) (bool, string) {
	e.t.Helper()
	d := must(e.c.NSDoc(ctx, ns, must(e.c.NSHead(ctx, ns)).ID)).Value
	frozen, _ := d["frozen"].(bool)
	succ, _ := d["successor"].(string)
	return frozen, succ
}

// purgedInSuccessor rebases r7 (which changed derby) into succ without
// switching, purges derby in succ only, and changes derby in r7 again: a
// resource the old branch changed that the successor can't record.
func purgedInSuccessor(t *testing.T, succ string) *env {
	e := newEnv(t)
	e.branch("matches", "r7")
	e.append("r7", "derby", op("replace", "/score", "1-0"))
	res := must(merge.Rebase(ctx, e.c, merge.RebaseOptions{Branch: "r7", New: succ}))
	if res.Switched || res.First.Resource("derby").Class != merge.FastForward {
		t.Fatalf("first rebase: %+v", res)
	}
	must(e.c.Purge(ctx, succ, "derby", e.head(succ, "derby").ID, false))
	e.append("r7", "derby", op("replace", "/score", "2-0"))
	return e
}

// OTHER-3 (§F.5 Switch, §F.6): Switch waits until every resource the old
// branch changed up to source.at is recorded in the successor, apart from
// §F.6's exceptions (the keyring at E3, resources purged in the old
// branch). A resource purged only in the successor is neither, so the
// rebase stops before the switch with ErrLeftOut naming it, unless a
// person gives it up (LeaveOut).
func TestV077RebaseSwitchWaitsForPurgedInSuccessor(t *testing.T) {
	t.Parallel()
	e := purgedInSuccessor(t, "r7b")
	opt := merge.RebaseOptions{Branch: "r7", New: "r7b", Switch: true}
	res, err := merge.Rebase(ctx, e.c, opt)
	if !errors.Is(err, merge.ErrLeftOut) || res.Switched || !reflect.DeepEqual(res.LeftOut, []string{"derby"}) || !strings.Contains(err.Error(), "derby") {
		t.Fatalf("rebase: %v, %+v", err, res)
	}
	if r := res.First.Resource("derby"); r.Class != merge.Purged {
		t.Fatalf("derby in the replay: %+v", r)
	}
	if frozen, _ := e.frozenWith("r7"); frozen {
		t.Fatal("r7 frozen although derby is purged in r7b only")
	}
	opt.LeaveOut = true
	res = must(merge.Rebase(ctx, e.c, opt))
	if frozen, succ := e.frozenWith("r7"); !res.Switched || !frozen || succ != "r7b" || !reflect.DeepEqual(res.LeftOut, []string{"derby"}) {
		t.Fatalf("rebase with LeaveOut: %+v", res)
	}
}

// OTHER-3 (§F.6): a resource purged in the old branch is one of §F.6's
// exceptions: it doesn't hold the switch up.
func TestV077RebaseSwitchExceptsPurgedInBranch(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.branch("matches", "r7")
	e.append("r7", "derby", op("replace", "/score", "1-0"))
	e.append("r7", "cup", op("replace", "/score", "2-1"))
	must(e.c.Purge(ctx, "r7", "derby", e.head("r7", "derby").ID, false))
	res := must(merge.Rebase(ctx, e.c, merge.RebaseOptions{Branch: "r7", New: "r7b", Switch: true}))
	if frozen, succ := e.frozenWith("r7"); !res.Switched || !frozen || succ != "r7b" || len(res.LeftOut) != 0 {
		t.Fatalf("rebase: %+v", res)
	}
}

// OTHER-4 (§F.5 Switch): with Switch, the gate counts every resource the
// old branch changed, not only those Plan.Resources limits the replay to:
// a replay of derby alone leaves cup unrecorded, so r7 isn't switched.
func TestV077RebaseSwitchGateUnrestricted(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.branch("matches", "r7")
	e.append("r7", "derby", op("replace", "/score", "1-0"))
	e.append("r7", "cup", op("replace", "/score", "2-1"))
	opt := merge.RebaseOptions{Branch: "r7", New: "r7b", Switch: true, Plan: merge.Options{Resources: []string{"derby"}}}
	res, err := merge.Rebase(ctx, e.c, opt)
	if !errors.Is(err, merge.ErrLeftOut) || res.Switched || !reflect.DeepEqual(res.LeftOut, []string{"cup"}) {
		t.Fatalf("rebase: %v, %+v", err, res)
	}
	if frozen, _ := e.frozenWith("r7"); frozen {
		t.Fatal("r7 frozen although cup wasn't replayed")
	}
	if got := e.doc("r7b", "derby").(map[string]any)["score"]; got != "1-0" {
		t.Fatalf("r7b derby score %v", got)
	}
	// Replaying the rest lets it switch.
	opt.Plan.Resources = []string{"cup"}
	res = must(merge.Rebase(ctx, e.c, opt))
	if frozen, succ := e.frozenWith("r7"); !res.Switched || !frozen || succ != "r7b" || len(res.LeftOut) != 0 {
		t.Fatalf("rebase of the rest: %+v", res)
	}
}

// OTHER-3 (§F.5): Plan.Unrecorded counts, before Apply, every resource
// that has an item; once Apply has written them, only what the target
// still doesn't record.
func TestV077PlanUnrecorded(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.branch("matches", "r7")
	e.append("r7", "derby", op("replace", "/score", "1-0"))
	e.append("r7", "cup", op("replace", "/score", "2-1"))
	e.del("matches", "cup")
	p := e.plan("matches", "r7", merge.Options{})
	if got := p.Unrecorded(); !reflect.DeepEqual(got, []string{"cup", "derby"}) {
		t.Fatalf("before Apply: %v", got)
	}
	noErr(t, p.Resolve("cup")) // kept over a tombstone: no item
	must(p.Apply(ctx))
	if got := p.Unrecorded(); !reflect.DeepEqual(got, []string{"cup"}) || !reflect.DeepEqual(p.LeftOut(), []string{"cup"}) {
		t.Fatalf("after Apply: %v (left out %v)", got, p.LeftOut())
	}
}

// OTHER-5 (§F.5 "or a person has given up the rest"): a release rebase
// passes LeaveOut to each branch's rebase, so a successor that can't
// record a resource switches once a person gives it up.
func TestV077RebaseReleaseLeaveOut(t *testing.T) {
	t.Parallel()
	e := purgedInSuccessor(t, "r7-b")
	must(e.c.CreateNamespace(ctx, "releases", map[string]any{}))
	nd := must(e.c.NSDoc(ctx, "r7", must(e.c.NSHead(ctx, "r7")).ID))
	at, _ := nd.Value["base"].(map[string]any)["at"].(string)
	must(release.Write(ctx, e.c, release.Ref{NS: "releases", Name: "rel"}, "", &release.Doc{Name: "rel", Branches: map[string]release.Branch{"matches": {NS: "r7", At: at}}}))
	opt := merge.RebaseReleaseOptions{Release: "/r/releases/rel", Suffix: "-b"}
	if _, err := merge.RebaseRelease(ctx, e.c, opt); !errors.Is(err, merge.ErrLeftOut) {
		t.Fatalf("without LeaveOut: %v, want ErrLeftOut", err)
	}
	if frozen, _ := e.frozenWith("r7"); frozen {
		t.Fatal("r7 frozen without LeaveOut")
	}
	opt.LeaveOut = true
	res := must(merge.RebaseRelease(ctx, e.c, opt))
	r := res.Rebases["matches"]
	if frozen, succ := e.frozenWith("r7"); r == nil || !r.Switched || !frozen || succ != "r7-b" || !reflect.DeepEqual(r.LeftOut, []string{"derby"}) {
		t.Fatalf("release rebase with LeaveOut: %+v", r)
	}
}
