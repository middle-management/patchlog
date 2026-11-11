package merge_test

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/grant"
	"github.com/middle-management/patchlog/internal/janitor"
	"github.com/middle-management/patchlog/internal/merge"
)

// BT-9 (TOOLS §F.5 Switch, §F.6; v0.82: "A give-up is recorded nowhere"):
// a rebase switches although cup, which the branch changed and the base
// deleted, can't be recorded in the successor, because a person gave it
// up (LeaveOut). Nothing records the give-up: the successor's batches
// don't name cup, the janitor doesn't purge the old branch as superseded,
// and a later replay, once cup can be recorded again, takes the rest;
// then the old branch is superseded.
func TestV082ReplayAfterGiveUpTakesTheRest(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.branch("matches", "r7")
	// With a cleanup period, so that only the claim decides (§F.6).
	must(e.c.PatchConfig(ctx, "r7", must(e.c.NSHead(ctx, "r7")).Config, ops(op("add", "/cleanup", map[string]any{"superseded": "P1D"}))))
	e.append("r7", "derby", op("replace", "/score", "1-0"))
	e.append("r7", "cup", op("replace", "/score", "2-1"))
	e.del("matches", "cup")
	keep := func(ctx context.Context, p *merge.Plan) error {
		if r := p.Resource("cup"); r != nil && r.NeedsPerson() {
			return p.Resolve("cup")
		}
		return nil
	}
	opt := merge.RebaseOptions{Branch: "r7", New: "r7-b", Switch: true, Prepare: keep}
	res, err := merge.Rebase(ctx, e.c, opt)
	if !errors.Is(err, merge.ErrLeftOut) || res.Switched || !reflect.DeepEqual(res.LeftOut, []string{"cup"}) {
		t.Fatalf("the rebase, cup kept over the base's delete: %v, %+v", err, res)
	}
	// A person gives cup up: the switch is made.
	opt.LeaveOut = true
	res = must(merge.Rebase(ctx, e.c, opt))
	if !res.Switched || !reflect.DeepEqual(res.LeftOut, []string{"cup"}) {
		t.Fatalf("the rebase with the give-up: %+v", res)
	}
	old := must(e.c.NSDoc(ctx, "r7", must(e.c.NSHead(ctx, "r7")).ID)).Value
	if old["frozen"] != true || old["successor"] != "r7-b" {
		t.Fatalf("the old branch after the switch: %v", old)
	}
	if d := e.doc("r7-b", "derby").(map[string]any); d["score"] != "1-0" {
		t.Fatalf("derby in the successor: %v", d)
	}

	// The give-up is recorded nowhere: no entry of the successor names
	// cup, and the old branch's document says only that it switched.
	recorded := func() map[string]bool {
		out := map[string]bool{}
		h := must(e.c.NSHead(ctx, "r7-b"))
		for _, en := range must(e.c.NSLog(ctx, "r7-b", h.ID, "")) {
			if en.Resource != "" {
				out[en.Resource] = true
			}
			for _, it := range en.Entries {
				if it.Resource != "" {
					out[it.Resource] = true
				}
			}
		}
		return out
	}
	if got := recorded(); got["cup"] || !got["derby"] {
		t.Fatalf("the successor's log records %v", got)
	}
	for k := range old {
		switch k {
		case "read", "merge", "base", "frozen", "successor", "keys", "roles", "cleanup":
		default:
			t.Fatalf("the old branch's document has %q after the give-up: %v", k, old)
		}
	}

	// So the janitor doesn't take the old branch for superseded (§F.6).
	later := func() time.Time { return e.s.Now().Add(100 * 24 * time.Hour) }
	j := janitor.New(e.c, janitor.Options{DryRun: true, Now: later})
	if d := must(j.Check(ctx, "matches", "r7")); d.Action != janitor.ActionKeep || d.Claim != "" {
		t.Fatalf("the janitor on the old branch after a give-up: %+v", d)
	}

	// A later replay may still take the rest (§F.5 step 3): cup is offered
	// again, and once it is live in the successor its change is recorded.
	p := must(merge.NewPlan(ctx, e.c, "r7-b", "r7", merge.Options{}))
	if un := p.Unrecorded(); !reflect.DeepEqual(un, []string{"cup"}) {
		t.Fatalf("offered again after the give-up: %v", un)
	}
	if r := p.Resource("derby"); r != nil && r.HasItem() {
		t.Fatalf("derby, merged already, offered again: %+v", r)
	}
	tomb := e.head("r7-b", "cup")
	if tomb.State != client.Tombstoned {
		t.Fatalf("cup in the successor: %+v", tomb)
	}
	must(e.c.Restore(ctx, "r7-b", "cup", tomb.ID, ops()))
	take := func(ctx context.Context, p *merge.Plan) error {
		if r := p.Resource("cup"); r != nil && r.NeedsPerson() {
			return p.Resolve("cup", client.Step{Patches: ops(op("replace", "/score", "2-1"))})
		}
		return nil
	}
	res = must(merge.Rebase(ctx, e.c, merge.RebaseOptions{Branch: "r7", New: "r7-b", Switch: true, Prepare: take}))
	if len(res.LeftOut) != 0 {
		t.Fatalf("the later replay left out %v", res.LeftOut)
	}
	if d := e.doc("r7-b", "cup").(map[string]any); d["score"] != "2-1" {
		t.Fatalf("cup in the successor after the later replay: %v", d)
	}
	if got := recorded(); !got["cup"] {
		t.Fatalf("the successor's log after the later replay records %v", got)
	}
	if un := must(merge.NewPlan(ctx, e.c, "r7-b", "r7", merge.Options{})).Unrecorded(); len(un) != 0 {
		t.Fatalf("still unrecorded: %v", un)
	}
	// Now every change of the old branch is in the successor: superseded.
	if d := must(j.Check(ctx, "matches", "r7")); d.Claim != "superseded" || d.Action != janitor.ActionWouldPurge {
		t.Fatalf("the janitor on the old branch after the later replay: %+v", d)
	}
}

// BT-6 (TOOLS §F.8 Filtered reads; tools scenario 46): release-7 has
// branch matches-r7 of private matches. A collaborator whose matches
// grant is fixed to derby gets, on the branch, a grant fixed to derby
// too, never unrestricted read: a branch reads through all of its base,
// so with it cup is 404 in the branch, as any resource the grant doesn't
// cover, by name, by revision and in its log, and nothing the branch
// lists is served (filtered reads don't cover branches). Only a
// collaborator who reads the base unrestricted reads cup through the
// branch. The reference issues no collaborator grants; this pins what an
// issuer relies on at the origin.
func TestV082ReleaseBranchGrantFixedToBaseResources(t *testing.T) {
	t.Parallel()
	s := clienttest.New(t, clienttest.Options{Auth: true})
	k := clienttest.NewKey("ops")
	must(s.Client(t, client.WithBearer(s.OperatorGrant(t, "matches"))).CreateNamespace(ctx, "matches", map[string]any{"read": "grant", "keys": []any{k.Entry("*")}}))
	both := []string{"matches", "matches-r7"}
	owner := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:anna", both, grant.Verbs)))
	derby := must(owner.CreateDoc(ctx, "matches", "derby", map[string]any{"title": "Derby"})).ID
	cup := must(owner.CreateDoc(ctx, "matches", "cup", map[string]any{"title": "Cup", "note": "embargoed"})).ID
	must(owner.CreateBranch(ctx, "matches", client.BranchRequest{Name: "matches-r7"}))
	draft := must(owner.Append(ctx, "matches-r7", "derby", derby, ops(op("add", "/score", "1-0")))).ID

	// The collaborator's grants: fixed to derby in the base, and so in the
	// branch (§F.8: "fixed to the resources their base grants cover").
	fixed := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:li", both, []string{"read", "append"},
		map[string]any{"rules": []any{op("test", "/resource", "derby")}})))
	if _, d := must2(fixed.Load(ctx, "matches-r7", "derby")); d == nil || d.Value.(map[string]any)["score"] != "1-0" {
		t.Fatalf("the fixed grant's read of the branch's derby: %+v", d)
	}
	notFound := func(what string, err error) {
		t.Helper()
		if ae, ok := client.AsAPIError(err); !ok || ae.Status != 404 {
			t.Fatalf("%s with the grant fixed to derby: %v, want 404", what, err)
		}
	}
	for _, ns := range both {
		// The head reads as that of a name never used does.
		h, err := fixed.Head(ctx, ns, "cup")
		none, nerr := fixed.Head(ctx, ns, "nothing")
		if err != nil || nerr != nil || h.State != client.NotFound || !reflect.DeepEqual(h, none) {
			t.Fatalf("%s/cup's head with the grant fixed to derby: %+v, %v (a name never used: %+v, %v)", ns, h, err, none, nerr)
		}
		_, err = fixed.Doc(ctx, ns, "cup", cup)
		notFound(ns+"/cup by revision", err)
		_, err = fixed.Log(ctx, ns, "cup", cup, "")
		notFound(ns+"/cup's log", err)
		// And as a resource that never existed answers.
		_, err = fixed.Doc(ctx, ns, "nothing", cup)
		notFound(ns+"/nothing by revision", err)
	}
	// Nothing that lists the branch: no unrestricted read, and no filtered
	// form of it either (§B.11.9, §F.8).
	at := must(owner.NSHead(ctx, "matches-r7")).ID
	for what, err := range map[string]error{
		"the branch's heads": func() error { _, err := fixed.Heads(ctx, "matches-r7", at); return err }(),
		"the branch's log":   func() error { _, err := fixed.NSLog(ctx, "matches-r7", at, ""); return err }(),
	} {
		if ae, ok := client.AsAPIError(err); !ok || ae.Status != 403 {
			t.Fatalf("%s with the grant fixed to derby: %v, want 403", what, err)
		}
	}
	// Its own resource it still writes.
	must(fixed.Append(ctx, "matches-r7", "derby", draft, ops(op("replace", "/score", "2-0"))))

	// A collaborator who reads the base unrestricted reads all of the
	// branch, cup through it.
	full := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:sam", both, []string{"read"})))
	if _, d := must2(full.Load(ctx, "matches-r7", "cup")); d == nil || d.Value.(map[string]any)["note"] != "embargoed" {
		t.Fatalf("the unrestricted reader's cup through the branch: %+v", d)
	}
	if hs := must(full.Heads(ctx, "matches-r7", at)); len(hs) != 2 {
		t.Fatalf("the unrestricted reader's heads of the branch: %+v", hs)
	}
}
