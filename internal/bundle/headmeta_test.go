package bundle_test

import (
	"testing"

	"github.com/middle-management/patchlog/internal/bundle"
	"github.com/middle-management/patchlog/internal/client"
)

// liveHeadsMatch checks every live head of ns's /heads listing against the
// document it names: Size and Digest those of the bytes served, Created
// its log entry's (§7.4). It returns how many
// live heads it checked.
func liveHeadsMatch(t *testing.T, c *client.Client, ns string) int {
	t.Helper()
	n := 0
	for _, it := range must(c.Heads(ctx, ns, must(c.NSHead(ctx, ns)).ID)) {
		if it.Kind != "head" {
			continue
		}
		d := must(c.Doc(ctx, ns, it.Resource, it.Target))
		lg := must(c.Log(ctx, ns, it.Resource, it.Target, ""))
		if it.Size != int64(len(d.Raw)) || it.Digest != client.ReprDigest(d.Raw) || it.Digest != d.Digest || it.Created != lg[len(lg)-1].Created {
			t.Fatalf("%s/%s: entry %+v, document %d bytes %s, created %s", ns, it.Resource, it, len(d.Raw), client.ReprDigest(d.Raw), lg[len(lg)-1].Created)
		}
		n++
	}
	return n
}

// A bundle import writes through batches, whose heads store their
// documents' sizes and digests (/heads, §7.4): a full
// import, and an incremental one fast-forwarding a document.
func TestImportHeadMeta(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	b, _, _ := f.export(t, bundle.ExportOptions{Select: []string{"matches/derby"}})
	dst := newDeployment(t, cmsOrigin)
	importB(t, dst, b, bundle.ImportOptions{})
	for _, ns := range []string{"matches", "media", "schemas"} {
		if liveHeadsMatch(t, dst.c, ns) == 0 {
			t.Fatalf("%s: no live heads", ns)
		}
	}
	f.src.append("matches", "derby", op("replace", "/score", "3-1"))
	inc, _, _ := f.export(t, bundle.ExportOptions{Select: []string{"matches/derby"}, Requires: map[string]string{"matches/derby": f.derby}})
	if d := importB(t, dst, inc, bundle.ImportOptions{}).Doc("matches/derby"); d.Class != "fast-forward" {
		t.Fatalf("incremental %+v", d)
	}
	liveHeadsMatch(t, dst.c, "matches")
}
