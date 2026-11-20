package merge_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/janitor"
	"github.com/middle-management/patchlog/internal/merge"
)

// Spec v0.34 (§F.9, §F.8): the plan digest and merged.at.

// entryOf returns the target's log entry with ns_id id.
func entryOf(t *testing.T, c *client.Client, ns, id string) client.NSEntry {
	t.Helper()
	h := must(c.NSHead(ctx, ns))
	for _, e := range must(c.NSLog(ctx, ns, h.ID, "")) {
		if e.ID == id {
			return e
		}
	}
	t.Fatalf("no entry %s in %s", id, ns)
	return client.NSEntry{}
}

// Approval binds to the plan's digest: it fails if planning again gives
// another digest, or if the person reviewed another one; applying stops
// for a new approval if a step differs from the approved plan.
func TestReleaseDigest(t *testing.T) {
	t.Parallel()
	w := newRelWorld(t)
	w.release7()
	o := w.opts("release-7")
	rp := must(merge.PlanRelease(ctx, w.anna, o))
	noErr(t, merge.SaveReleasePlan(ctx, w.anna, o, rp))
	again := must(merge.PlanRelease(ctx, w.anna, o))
	if again.Digest != rp.Digest {
		t.Fatalf("planning twice gives %s and %s", rp.Digest, again.Digest)
	}
	// The base moves under a content item: its precondition changes.
	w.appendTo("matches", "cup", op("add", "/score", "2-2"))
	w.appendTo("matches-r7", "cup", op("add", "/note", "branch"))
	w.writeRelease("release-7", map[string]string{"schemas": "schemas-r7", "matches": "matches-r7", "cat-season": "cat-season-r7"})
	rp = must(merge.PlanRelease(ctx, w.anna, o))
	noErr(t, merge.SaveReleasePlan(ctx, w.anna, o, rp))
	w.appendTo("matches", "cup", op("replace", "/score", "3-2"))
	if _, err := merge.ApproveRelease(ctx, w.anna, o); !errors.Is(err, merge.ErrDigest) {
		t.Fatalf("approve after the plan changed: %v", err)
	}
	// Plan again; a person who reviewed another digest can't approve it.
	stored := must(merge.LoadReleasePlan(ctx, w.anna, o))
	rp = must(merge.PlanRelease(ctx, w.anna, o))
	merge.AdoptHead(rp, stored)
	noErr(t, merge.SaveReleasePlan(ctx, w.anna, o, rp))
	bad := o
	bad.Digest = again.Digest
	if _, err := merge.ApproveRelease(ctx, w.anna, bad); !errors.Is(err, merge.ErrDigest) {
		t.Fatalf("approve of another digest: %v", err)
	}
	good := o
	good.Digest = rp.Digest
	approved := must(merge.ApproveRelease(ctx, w.anna, good))
	if approved.Digest != rp.Digest {
		t.Fatalf("approved %s, reviewed %s", approved.Digest, rp.Digest)
	}
	// The base moves again after the approval: step 2 differs, and the
	// merge stops there for a new approval (step 1 went in).
	w.appendTo("matches", "cup", op("replace", "/score", "4-2"))
	_, err := merge.ApplyRelease(ctx, w.anna, o)
	if !errors.Is(err, merge.ErrPlanChanged) || !strings.Contains(err.Error(), "step 2") {
		t.Fatalf("apply after the base moved: %v", err)
	}
	if w.live("matches", "final") {
		t.Fatal("step 2 went in")
	}
}

// §F.9 Abandoning: the branches are frozen with abandoned: true by an
// administrator, and the janitor cleans them up (§F.6); an editor's
// abandoning isn't accepted.
func TestReleaseAbandon(t *testing.T) {
	t.Parallel()
	w := newRelWorld(t)
	w.release7()
	o := w.opts("release-7")
	noErr(t, merge.SaveReleasePlan(ctx, w.anna, o, must(merge.PlanRelease(ctx, w.anna, o))))
	got := must(merge.AbandonRelease(ctx, w.ops, o))
	if len(got) != 3 {
		t.Fatalf("abandoned %v", got)
	}
	if rp := must(merge.LoadReleasePlan(ctx, w.anna, o)); rp.State != merge.ReleaseAbandoned {
		t.Fatalf("plan state %s", rp.State)
	}
	if _, err := merge.ApproveRelease(ctx, w.anna, o); err == nil {
		t.Fatal("approved an abandoned release")
	}
	j := janitor.New(w.anna, janitor.Options{DryRun: true, Now: func() time.Time { return w.s.Now().Add(time.Hour) }})
	for base, br := range map[string]string{"schemas": "schemas-r7", "matches": "matches-r7", "cat-season": "cat-season-r7"} {
		dec := must(j.Check(ctx, base, br))
		if dec.Claim != "abandoned" || dec.Action != janitor.ActionWouldPurge {
			t.Fatalf("janitor on %s: %+v", br, dec)
		}
	}
	// By an editor (anna's key isn't a * key): not accepted.
	w.branch("schemas", "schemas-x")
	w.appendTo("schemas-x", "match", op("add", "/properties/x", map[string]any{"type": "string"})) // unmerged work
	w.writeRelease("release-x", map[string]string{"schemas": "schemas-x"})
	must(merge.AbandonRelease(ctx, w.anna, w.opts("release-x")))
	if dec := must(j.Check(ctx, "schemas", "schemas-x")); dec.Claim != "" || dec.Action != janitor.ActionKeep {
		t.Fatalf("janitor on an editor's abandoning: %+v", dec)
	}
}
