package core

import (
	"context"
	"crypto/sha256"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/pgtest"
)

// headsAt returns ns's /heads page at nsID by resource, and its bytes as
// served.
func headsAt(t *testing.T, e *Engine, ns, nsID string) (map[string]map[string]any, string) {
	t.Helper()
	page, err := e.NamespaceHeads(context.Background(), ns, nsID, "", Credentials{})
	if err != nil {
		t.Fatalf("heads of %s at %s: %v", ns, nsID, err)
	}
	out := map[string]map[string]any{}
	items := make([]any, len(page.Items))
	for i, it := range page.Items {
		out[it["resource"].(string)] = it
		items[i] = it
	}
	return out, string(jsonv.Canonical(jsonv.FromGo(map[string]any{"items": items})))
}

// checkHeadMeta checks a /heads entry of ns against what the namespace
// serves of its target: created as the target's log entry gives it, and
// for a live head size and digest as the bytes GET …/rev/{target} serves,
// which carry the same digest (Repr-Digest) and created time
// (Last-Modified). Tombstones carry no size or digest.
func checkHeadMeta(t *testing.T, e *Engine, ns string, it map[string]any) {
	t.Helper()
	ctx := context.Background()
	name, target := it["resource"].(string), it["target"].(string)
	lg, err := e.ResourceLog(ctx, ns, name, target, "", 0, Credentials{})
	if err != nil || lg.Status != 200 {
		t.Fatalf("%s/%s log at %s: %v %+v", ns, name, target, err, lg)
	}
	if created := lg.Entries[len(lg.Entries)-1]["created"]; it["created"] != created {
		t.Errorf("%s/%s: created %v, its log entry's %v", ns, name, it["created"], created)
	}
	if it["kind"] != "head" {
		if _, ok := it["size"]; ok || it["digest"] != nil {
			t.Errorf("%s/%s (%s): size or digest %v", ns, name, it["kind"], it)
		}
		return
	}
	rev, err := e.ResourceRev(ctx, ns, name, target, Credentials{})
	if err != nil || rev.Status != 200 {
		t.Fatalf("%s/%s at %s: %v %+v", ns, name, target, err, rev)
	}
	sum := sha256.Sum256(rev.Doc)
	if it["size"] != float64(len(rev.Doc)) || it["digest"] != ReprDigest(sum[:]) {
		t.Errorf("%s/%s: size %v digest %v, served %d bytes %s", ns, name, it["size"], it["digest"], len(rev.Doc), ReprDigest(sum[:]))
	}
	if string(rev.Digest) != string(sum[:]) || formatTime(rev.Created.UnixMilli()) != it["created"] {
		t.Errorf("%s/%s at %s: Rev digest %x created %v, entry %v", ns, name, target, rev.Digest, rev.Created, it)
	}
}

// §7.4 in a plain namespace: /heads entries carry created, and live
// heads the size and digest of their document, stored by every path that
// moves a head at write time: a create, an append, a tombstone, a restore,
// a batch's multi-step items (only the head they leave stores them), and a
// branch's own writes, while its read-through entries are the base's.
// A page never gains them once served: later writes, a prune below a
// listed head (which keeps them, as it keeps the target) and a branch
// leave it as it was; a purge makes the entry a purge, with none.
func TestHeadMeta(t *testing.T) {
	t.Parallel()
	var clock atomic.Int64 // Unix ms, moved past the retry window to prune
	clock.Store(time.Now().UnixMilli())
	lim := DefaultLimits()
	fast := Rate{1e9, 1e9}
	lim.RatePerResource, lim.RatePerPrincipal, lim.RatePerNamespace = fast, fast, fast
	e, err := Open(Options{Path: pgtest.DB(t), BlobDir: t.TempDir(), AuthDisabled: true, RetentionInterval: -1, Remote: RemoteOptions{FollowInterval: -1},
		Limits: lim, TailInterval: tailEvery, Purger: discardPurger{}, Now: func() time.Time { return time.UnixMilli(clock.Load()) }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close() })
	ctx := context.Background()
	mkNS(t, e, "n", map[string]any{"read": "public"})
	write := func(ns string, items ...Item) *WriteResult {
		t.Helper()
		r := who
		r.NS = ns
		res, err := e.Batch(ctx, r, items, nil, nil, false)
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	add := func(path string, v any) Step {
		return Step{Patches: []any{map[string]any{"op": "add", "path": path, "value": v}}}
	}
	pages := map[string]string{} // ns_id -> page as first served
	check := func(ns, nsID string, names ...string) map[string]map[string]any {
		t.Helper()
		hs, raw := headsAt(t, e, ns, nsID)
		for _, name := range names {
			it := hs[name]
			if it == nil {
				t.Fatalf("%s at %s: no %s in %v", ns, nsID, name, hs)
			}
			checkHeadMeta(t, e, ns, it)
		}
		pages[ns+"@"+nsID] = raw
		return hs
	}

	r := write("n", Item{Resource: "a", IfNoneMatch: true, Steps: []Step{add("", map[string]any{"x": 1.0})}})
	a0 := r.Items[0].IDs[0]
	check("n", r.NSID, "a")
	r = write("n", Item{Resource: "a", IfMatch: a0, Steps: []Step{add("/s", strings.Repeat("é", 100))}})
	a1 := r.Items[0].IDs[0]
	at1 := r.NSID
	check("n", at1, "a")
	r = write("n", Item{Resource: "a", IfMatch: a1, Steps: []Step{{Delete: true}}})
	tomb := r.Items[0].IDs[0]
	if hs := check("n", r.NSID, "a"); hs["a"]["kind"] != "tombstone" || hs["a"]["created"] == nil {
		t.Fatalf("tombstone %v", hs["a"])
	}
	r = write("n", Item{Resource: "a", IfMatch: tomb, Steps: []Step{add("/r", true)}})
	a2 := r.Items[0].IDs[0]
	check("n", r.NSID, "a")
	// A batch: a three-step create, a create deleted in the same item,
	// and an append.
	r = write("n",
		Item{Resource: "b", IfNoneMatch: true, Steps: []Step{add("", map[string]any{}), add("/k", "v"), add("/l", []any{1.0, 2.0})}},
		Item{Resource: "c", IfNoneMatch: true, Steps: []Step{add("", "c"), {Delete: true}}},
		Item{Resource: "a", IfMatch: a2, Steps: []Step{add("/t", nil)}})
	at5 := r.NSID
	check("n", at5, "a", "b", "c")
	// Only the head each item leaves stores them.
	var stored, live int
	if err := e.read(ctx, func(t *tx) error {
		t.must(t.QueryRow(`SELECT COUNT(size), COUNT(*) FROM revisions WHERE kind = 0 AND res = (SELECT res FROM resources WHERE name = 'b')`).Scan(&stored, &live))
		return nil
	}); err != nil || stored != 1 || live != 3 {
		t.Fatalf("b's revisions storing size: %d of %d (%v)", stored, live, err)
	}

	// A branch lists the base's values for what it reads through, and its
	// own for what it writes.
	if _, err := e.CreateBranch(ctx, Request{NS: "n", Cred: who.Cred}, BranchRequest{Name: "br", IfNoneMatch: true}); err != nil {
		t.Fatal(err)
	}
	bhead := headOf(t, e, "n", "b")
	r = write("br", Item{Resource: "b", IfMatch: bhead, Steps: []Step{add("/m", 3.0)}},
		Item{Resource: "d", IfNoneMatch: true, Steps: []Step{add("", map[string]any{"d": "own"})}})
	hs := check("br", r.NSID, "a", "b", "c", "d")
	base, _ := headsAt(t, e, "n", at5)
	if hs["a"]["digest"] != base["a"]["digest"] || hs["a"]["created"] != base["a"]["created"] || hs["b"]["digest"] == base["b"]["digest"] {
		t.Fatalf("branch %v, base %v", hs, base)
	}

	// Pruning below a listed head keeps what the page lists, though the
	// document is gone (410).
	clock.Add((48 * time.Hour).Milliseconds())
	ahead := headOf(t, e, "n", "a")
	if pr, err := e.Prune(ctx, Request{NS: "n", Cred: who.Cred}, "a", PruneRequest{Horizon: ahead}); err != nil || pr.Horizon != ahead {
		t.Fatalf("prune %+v %v", pr, err)
	}
	if rev, err := e.ResourceRev(ctx, "n", "a", a1, Credentials{}); err != nil || rev.Status != 410 {
		t.Fatalf("pruned revision %+v %v", rev, err)
	}
	for k, raw := range pages {
		ns, nsID, _ := strings.Cut(k, "@")
		if _, now := headsAt(t, e, ns, nsID); now != raw {
			t.Errorf("%s changed:\n%s\n%s", k, raw, now)
		}
	}

	// A purge lists a purge, with neither, and clears the stored values.
	purge(t, e, "n", "a")
	hs, _ = headsAt(t, e, "n", at1)
	if it := hs["a"]; it["kind"] != "purge" || it["created"] != nil || it["size"] != nil || it["digest"] != nil {
		t.Fatalf("purged %v", it)
	}
	var left int
	if err := e.read(ctx, func(t *tx) error {
		t.must(t.QueryRow(`SELECT COUNT(*) FROM revisions WHERE (size IS NOT NULL OR digest IS NOT NULL) AND res IN (SELECT res FROM resources WHERE name = 'a')`).Scan(&left))
		return nil
	}); err != nil || left != 0 {
		t.Fatalf("a purged resource's rows keep %d sizes or digests (%v)", left, err)
	}
}

// Rev.Created and Rev.Digest (Last-Modified, Repr-Digest) are the same
// whether a revision is read in a transaction, from the read cache after
// a read check (revFor), or without a transaction (a public namespace).
func TestRevMetaCached(t *testing.T) {
	t.Parallel()
	e := openInstance(t, pgtest.DB(t), t.TempDir())
	ctx := context.Background()
	for _, ns := range []string{"pub", "priv"} {
		doc := map[string]any{}
		if ns == "pub" {
			doc["read"] = "public"
		}
		mkNS(t, e, ns, doc)
		id, err := put(e, ns, "a", "", 7)
		if err != nil {
			t.Fatal(err)
		}
		lg, err := e.ResourceLog(ctx, ns, "a", id, "", 0, Credentials{})
		if err != nil {
			t.Fatal(err)
		}
		created := lg.Entries[0]["created"]
		for i := 0; i < 3; i++ {
			rev, err := e.ResourceRev(ctx, ns, "a", id, Credentials{})
			if err != nil || rev.Status != 200 {
				t.Fatalf("%s read %d: %+v %v", ns, i, rev, err)
			}
			sum := sha256.Sum256(rev.Doc)
			if string(rev.Digest) != string(sum[:]) || formatTime(rev.Created.UnixMilli()) != created {
				t.Fatalf("%s read %d: digest %x created %v, want %x %v", ns, i, rev.Digest, rev.Created, sum, created)
			}
		}
	}
}

// A group commit's writes store their heads' sizes and digests as single
// writes do (insertItemsBy).
func TestPGGroupCommitHeadMeta(t *testing.T) {
	t.Parallel()
	e := groupEngine(t)
	mkNS(t, e, "n", map[string]any{"read": "public"})
	sizes := groupSizes(e)
	holdChecked(t, e, 3, nil)
	res, errs := concurrently(3, func(i int) (*WriteResult, error) { return write(e, "n", string(rune('a'+i)), "", i) })
	for i, err := range errs {
		if err != nil {
			t.Fatal(i, err)
		}
	}
	if s := sizes(); len(s) != 1 || s[0] != 3 {
		t.Fatalf("groups %v", s)
	}
	h, err := e.NamespaceHead(context.Background(), "n", Credentials{})
	if err != nil {
		t.Fatal(err)
	}
	hs, _ := headsAt(t, e, "n", h.Head)
	for i, name := range []string{"a", "b", "c"} {
		if hs[name]["target"] != res[i].Items[0].IDs[0] {
			t.Fatalf("%s: %v", name, hs[name])
		}
		checkHeadMeta(t, e, "n", hs[name])
	}
}
