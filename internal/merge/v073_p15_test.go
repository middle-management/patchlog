package merge_test

import (
	"errors"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/merge"
)

// §7.2, §8.1 (GB-55): a create on a resource deleted between plan and
// apply gets 410 gone with head, the tombstone, where it used to get 412;
// Apply re-classifies it as a target that moved instead of failing.
func TestV073P15ApplyAfterTargetDeleted(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.branch("matches", "r7")
	e.create("r7", "final", map[string]any{"title": "Final"})
	p := e.plan("matches", "r7", merge.Options{})
	if f := p.Resource("final"); f.Class != merge.FastForward || !f.IfNoneMatch {
		t.Fatalf("final: %+v", f)
	}
	e.create("matches", "final", map[string]any{"title": "Other"})
	tomb := e.del("matches", "final")
	_, err := p.Apply(ctx)
	if ae, ok := client.AsAPIError(err); ok {
		t.Fatalf("apply answered %d %s: the moved target wasn't re-classified", ae.Status, ae.Code)
	}
	// Re-classified against the tombstone: a person decides between the
	// target's delete and the branch's document.
	if !errors.Is(err, merge.ErrConflicts) {
		t.Fatalf("apply: %v, want ErrConflicts", err)
	}
	if f := p.Resource("final"); f.Class == merge.FastForward || !f.NeedsPerson() {
		t.Fatalf("final not re-classified: %+v", f)
	}
	if h := e.head("matches", "final"); h.State != client.Tombstoned || h.ID != tomb {
		t.Fatalf("final: %+v", h)
	}
}

// §7.5 (GB-26): a dry run reports an explicit config change that fails
// after its step 1 in a 200, judging the items against the configuration
// in force. DryRun fails with it, as the *client.APIError Apply fails
// with, so a plan whose change is invalid (a failing test op, step 3) or
// stale (the target's configuration moved since the plan, step 2) never
// dry-runs ok; a passing change still does.
func TestV073P15DryRunConfigFails(t *testing.T) {
	t.Parallel()
	for name, mk := range map[string]func(e *env) *merge.Plan{
		"invalid": func(e *env) *merge.Plan {
			return e.plan("matches", "r7", merge.Options{Config: ops(op("test", "/x-nope", 1))})
		},
		"stale": func(e *env) *merge.Plan {
			p := e.plan("matches", "r7", merge.Options{Config: ops(op("add", "/x-release", 7))})
			must(e.c.PatchConfig(ctx, "matches", must(e.c.NSHead(ctx, "matches")).Config, ops(op("add", "/x-other", 1))))
			return p
		},
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			e.branch("matches", "r7")
			e.append("r7", "derby", op("replace", "/score", "1-0"))
			dry, err := mk(e).DryRun(ctx)
			de, ok := client.AsAPIError(err)
			if !ok {
				t.Fatalf("dry run: %v, want the config change's failure", err)
			}
			if dry == nil || len(dry.Items) != 1 {
				t.Fatalf("dry run report %+v", dry)
			}
			_, err = mk(e).Apply(ctx)
			ae, ok := client.AsAPIError(err)
			if !ok || ae.Status != de.Status || ae.Code != de.Code || de.Error() != ae.Error() {
				t.Fatalf("dry run fails with %v, apply with %v", de, err)
			}
		})
	}

	e := newEnv(t)
	e.branch("matches", "r7")
	e.append("r7", "derby", op("replace", "/score", "1-0"))
	dry := must(e.plan("matches", "r7", merge.Options{Config: ops(op("add", "/x-release", 7))}).DryRun(ctx))
	if dry.ConfigError() != nil || dry.ConfigReport["status"] != 201.0 || dry.ConfigReport["config"] == "" || dry.Config != "" {
		t.Fatalf("passing config change: report %v, config %q", dry.ConfigReport, dry.Config)
	}
}
