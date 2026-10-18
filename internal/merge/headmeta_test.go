package merge_test

import (
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/merge"
)

// headItems lists ns's /heads at its head by resource.
func (e *env) headItems(ns string) map[string]client.HeadItem {
	e.t.Helper()
	out := map[string]client.HeadItem{}
	for _, it := range must(e.c.Heads(ctx, ns, must(e.c.NSHead(ctx, ns)).ID)) {
		out[it.Resource] = it
	}
	return out
}

// A merge's apply writes a batch, whose heads store their documents' sizes
// and digests (/heads, §7.4): a fast-forward, which
// reproduces the branch's ids and so its entries' digests, and a replay,
// a new revision with its own; a deletion's tombstone has none.
func TestMergeHeadMeta(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.branch("matches", "r7")
	e.append("r7", "derby", op("replace", "/score", "1-0"))
	e.create("r7", "final", map[string]any{"title": "Final"})
	e.del("r7", "cup")
	e.append("matches", "derby", op("replace", "/title", "The Derby"))
	p := e.plan("matches", "r7", merge.Options{})
	wantClasses(t, p, map[string]merge.Class{"derby": merge.Replay, "final": merge.FastForward, "cup": merge.FastForward})
	must(p.Apply(ctx))
	base, br := e.headItems("matches"), e.headItems("r7")
	for _, name := range []string{"derby", "final"} {
		it := base[name]
		d := must(e.c.Doc(ctx, "matches", name, it.Target))
		lg := must(e.c.Log(ctx, "matches", name, it.Target, ""))
		if it.Kind != "head" || it.Size != int64(len(d.Raw)) || it.Digest != client.ReprDigest(d.Raw) || it.Created != lg[len(lg)-1].Created {
			t.Fatalf("%s: entry %+v, document %d bytes %s", name, it, len(d.Raw), client.ReprDigest(d.Raw))
		}
	}
	if f := base["final"]; f.Target != br["final"].Target || f.Digest != br["final"].Digest || f.Size != br["final"].Size {
		t.Fatalf("fast-forward: base %+v, branch %+v", f, br["final"])
	}
	if d := base["derby"]; d.Digest == br["derby"].Digest {
		t.Fatalf("replay: base %+v, branch %+v", d, br["derby"])
	}
	if c := base["cup"]; c.Kind != "tombstone" || c.Created == "" || c.Size != 0 || c.Digest != "" {
		t.Fatalf("tombstone %+v", c)
	}
}
