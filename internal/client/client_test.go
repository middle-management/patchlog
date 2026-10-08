package client_test

import (
	"context"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
)

func ops(o ...map[string]any) []any {
	out := make([]any, len(o))
	for i, x := range o {
		out[i] = x
	}
	return out
}

func op(o, path string, v any) map[string]any {
	return map[string]any{"op": o, "path": path, "value": v}
}

// must panics on error; the test fails with the error and stack.
func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

func TestResourceLifecycle(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{})
	c := s.Client(t, client.WithAuthor("alice"))

	if o := must(c.Origin(ctx)); o != clienttest.Origin {
		t.Fatalf("origin %q", o)
	}
	cr := must(c.CreateNamespace(ctx, "main", map[string]any{"read": "public"}))
	if cr.Status != 201 || cr.Config == "" || cr.NSID == "" {
		t.Fatalf("create ns %+v", cr)
	}
	if want := must(client.ExpectedConfigGenesis(map[string]any{"read": "public"})); want != cr.Config {
		t.Fatalf("config genesis %s want %s", cr.Config, want)
	}

	h := must(c.Head(ctx, "main", "a"))
	if h.State != client.NotFound {
		t.Fatalf("head %+v", h)
	}

	genesis := client.GenesisPatches(map[string]any{"n": 0})
	want := must(client.ExpectedRevision("", genesis))
	w := must(c.Create(ctx, "main", "a", genesis))
	if w.ID != want || w.NSID == "" || w.Status != 201 || w.Entry == nil || w.Entry.ID != want {
		t.Fatalf("create %+v want %s", w, want)
	}
	// Idempotent retry: 200 with the same id.
	w2 := must(c.Create(ctx, "main", "a", genesis))
	if !w2.Replayed() || w2.ID != want {
		t.Fatalf("retry %+v", w2)
	}
	// A different create is stale, naming the head.
	_, err := c.Create(ctx, "main", "a", client.GenesisPatches(map[string]any{"n": 9}))
	if !client.IsStale(err) {
		t.Fatalf("want stale, got %v", err)
	}
	if ae, _ := client.AsAPIError(err); ae.Head() != want || ae.Code != "stale" {
		t.Fatalf("stale body %+v", ae)
	}

	p1 := ops(op("replace", "/n", 1))
	r1 := must(client.ExpectedRevision(w.ID, p1))
	a1 := must(c.Append(ctx, "main", "a", w.ID, p1))
	if a1.ID != r1 {
		t.Fatalf("append id %s want %s", a1.ID, r1)
	}
	h = must(c.Head(ctx, "main", "a"))
	if h.State != client.Live || h.ID != r1 {
		t.Fatalf("head %+v", h)
	}
	d := must(c.Doc(ctx, "main", "a", r1))
	if string(d.Raw) != `{"n":1}` || d.Value.(map[string]any)["n"] != 1.0 {
		t.Fatalf("doc %s", d.Raw)
	}
	lg := must(c.Log(ctx, "main", "a", "", ""))
	if len(lg) != 2 || lg[0].ID != w.ID || lg[1].Parent != w.ID || !lg[1].HasPatches || lg[1].Author != "alice" {
		t.Fatalf("log %+v", lg)
	}
	lg = must(c.Log(ctx, "main", "a", r1, w.ID))
	if len(lg) != 1 || lg[0].ID != r1 {
		t.Fatalf("log since %+v", lg)
	}

	// Delete, restore, purge.
	tomb := must(client.ExpectedTombstone(r1))
	del := must(c.Delete(ctx, "main", "a", r1))
	if del.ID != tomb || del.NSID == "" {
		t.Fatalf("delete %+v want %s", del, tomb)
	}
	h = must(c.Head(ctx, "main", "a"))
	if h.State != client.Tombstoned || h.ID != tomb || h.Last != r1 {
		t.Fatalf("tombstoned head %+v", h)
	}
	if _, err := c.Doc(ctx, "main", "a", tomb); !client.IsGone(err) {
		t.Fatalf("doc at tombstone: %v", err)
	}
	rs := must(c.Restore(ctx, "main", "a", tomb, []any{}))
	h = must(c.Head(ctx, "main", "a"))
	if h.State != client.Live || h.ID != rs.ID {
		t.Fatalf("restored head %+v", h)
	}
	nsID := must(c.Purge(ctx, "main", "a", rs.ID, false))
	if nsID == "" {
		t.Fatal("purge without ns_id")
	}
	h = must(c.Head(ctx, "main", "a"))
	if h.State != client.Purged {
		t.Fatalf("purged head %+v", h)
	}
	if _, err := c.Log(ctx, "main", "a", "", ""); !client.IsGone(err) {
		t.Fatalf("log of purged: %v", err)
	}
}

func TestNamespaceAPI(t *testing.T) { t.Parallel(); testNamespaceAPI(t) }

func testNamespaceAPI(t *testing.T) {
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{})
	c := s.Client(t, client.WithAuthor("admin"))
	must(c.CreateNamespace(ctx, "main", map[string]any{"read": "public"}))
	a := must(c.CreateDoc(ctx, "main", "a", map[string]any{"v": 1}))
	must(c.CreateDoc(ctx, "main", "b", map[string]any{"v": 2}))

	// Batch: chain two steps on a (ids computed in advance), create c, delete b.
	bHead := must(c.Head(ctx, "main", "b"))
	p1, p2 := ops(op("replace", "/v", 10)), ops(op("replace", "/v", 11))
	id1 := must(client.ExpectedRevision(a.ID, p1))
	id2 := must(client.ExpectedRevision(id1, p2))
	req := client.BatchRequest{
		Items: []client.BatchItem{
			{Resource: "a", IfMatch: a.ID, Steps: []client.Step{client.PatchStep(p1), client.PatchStep(p2)}},
			{Resource: "c", IfNoneMatch: true, Steps: []client.Step{client.PatchStep(client.GenesisPatches(map[string]any{"v": 3}))}},
			{Resource: "b", IfMatch: bHead.ID, Steps: []client.Step{client.DeleteStep()}},
		},
		Source: map[string]any{"ns": "main", "at": a.NSID},
	}
	dry := must(c.Batch(ctx, "main", req, true))
	if dry.Status != 200 || dry.NSID != "" {
		t.Fatalf("dry run %+v", dry)
	}
	br := must(c.Batch(ctx, "main", req, false))
	if br.Status != 201 || br.NSID == "" || len(br.Items) != 3 || br.Items[0].IDs[1] != id2 {
		t.Fatalf("batch %+v want %s", br, id2)
	}
	// A failing batch is a typed error with items.
	_, err := c.Batch(ctx, "main", client.BatchRequest{Items: []client.BatchItem{{Resource: "a", IfMatch: a.ID, Steps: []client.Step{client.PatchStep(p1)}}}}, false)
	ae, ok := client.AsAPIError(err)
	if !ok || ae.Code != "batch" || ae.Status != 412 || len(ae.Items()) != 1 {
		t.Fatalf("batch failure %v", err)
	}

	head := must(c.NSHead(ctx, "main"))
	if head.ID != br.NSID || head.Config == "" {
		t.Fatalf("ns head %+v", head)
	}
	doc := must(c.NSDoc(ctx, "main", head.ID))
	if doc.Value["read"] != "public" || doc.Config != head.Config {
		t.Fatalf("ns doc %+v", doc)
	}
	lg := must(c.NSLog(ctx, "main", head.ID, ""))
	if len(lg) != 4 || lg[0].Kind != "config" || lg[1].Kind != "head" || lg[1].Resource != "a" || lg[3].Kind != "batch" {
		t.Fatalf("ns log %+v", lg)
	}
	b := lg[3]
	if len(b.Entries) != 3 || b.Entries[0].Target != id2 || b.Entries[2].Kind != "tombstone" || !b.HasSource || b.Source["ns"] != "main" || b.Prev != lg[2].ID {
		t.Fatalf("batch entry %+v", b)
	}

	// Config change with the config id.
	cr := must(c.PatchConfig(ctx, "main", head.Config, ops(op("add", "/x-note", "hi"))))
	if cr.Config == head.Config || cr.NSID == "" {
		t.Fatalf("patch config %+v", cr)
	}
	if _, err := c.PatchConfig(ctx, "main", head.Config, ops(op("add", "/x-other", 1))); !client.IsStale(err) {
		t.Fatalf("stale config: %v", err)
	} else if ae, _ := client.AsAPIError(err); ae.Config() != cr.Config {
		t.Fatalf("stale config body %v", ae.Body)
	}

	// Heads (with pagination through all pages).
	heads := must(c.Heads(ctx, "main", cr.NSID))
	if len(heads) != 3 || heads[0].Resource != "a" || heads[0].Target != id2 || heads[1].Kind != "tombstone" {
		t.Fatalf("heads %+v", heads)
	}

	// Branches.
	bres := must(c.CreateBranch(ctx, "main", client.BranchRequest{Name: "rel", At: br.NSID}))
	if bres.Status != 201 || bres.NSID == "" || bres.Config == "" {
		t.Fatalf("branch %+v", bres)
	}
	bl := must(c.Branches(ctx, "main"))
	if len(bl) != 1 || bl[0].Name != "rel" || bl[0].At != br.NSID || bl[0].Frozen || bl[0].Purged {
		t.Fatalf("branches %+v", bl)
	}
	first := must(client.FirstBranchEntry(bres.Config))
	bh := must(c.NSHead(ctx, "rel"))
	if bh.ID != first {
		t.Fatalf("branch first entry %s, computed %s", bh.ID, first)
	}
	// Read-through heads at the branch's first ns_id.
	bheads := must(c.Heads(ctx, "rel", first))
	if len(bheads) != 3 {
		t.Fatalf("branch heads %+v", bheads)
	}

	// Freeze and purge the branch.
	must(c.PatchConfig(ctx, "rel", bh.Config, ops(op("add", "/frozen", true))))
	if _, err := c.CreateDoc(ctx, "rel", "z", map[string]any{}); !client.IsFrozen(err) {
		t.Fatalf("frozen write: %v", err)
	}
	bh = must(c.NSHead(ctx, "rel"))
	pid := must(c.PurgeNamespace(ctx, "rel", bh.ID))
	if pid == "" {
		t.Fatal("purge-ns without ns_id")
	}
	bl = must(c.Branches(ctx, "main"))
	if !bl[0].Purged || !bl[0].Frozen {
		t.Fatalf("branches after purge %+v", bl)
	}
}

func TestLongPollAndEvents(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{LongPoll: 200 * time.Millisecond})
	c := s.Client(t, client.WithAuthor("admin"))
	cr := must(c.CreateNamespace(ctx, "main", map[string]any{"read": "public"}))

	// Entries after since: answered at once.
	lp := must(c.LongPoll(ctx, "main", "", ""))
	if lp.Timeout || len(lp.Entries) != 1 || lp.Since != cr.NSID || lp.Cursor == "" {
		t.Fatalf("long-poll %+v", lp)
	}
	// Nothing new: timeout at the interval boundary, same since.
	lp2 := must(c.LongPoll(ctx, "main", lp.Since, lp.Cursor))
	if !lp2.Timeout || lp2.Since != cr.NSID || lp2.Cursor == "" {
		t.Fatalf("timeout %+v", lp2)
	}
	// A write while waiting wakes the poll.
	go func() {
		time.Sleep(20 * time.Millisecond)
		c.CreateDoc(ctx, "main", "a", map[string]any{"v": 1})
	}()
	var got *client.LongPollResult
	for got == nil || got.Timeout {
		got = must(c.LongPoll(ctx, "main", lp.Since, lp2.Cursor))
	}
	if len(got.Entries) != 1 || got.Entries[0].Resource != "a" || got.Since != got.Entries[0].ID {
		t.Fatalf("woken %+v", got)
	}
	// Resource long-poll.
	rl := must(c.ResourceLongPoll(ctx, "main", "a", "", ""))
	if len(rl.Entries) != 1 || rl.Since != rl.Entries[0].ID {
		t.Fatalf("resource long-poll %+v", rl)
	}
	// Unknown since: 404.
	if _, err := c.LongPoll(ctx, "main", rl.Since, ""); !client.IsNotFound(err) {
		t.Fatalf("since not in chain: %v", err)
	}

	// SSE: replay then stop.
	sctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var kinds []string
	errStop := context.Canceled
	err := c.NSEvents(sctx, "main", "", func(e client.NSEntry) error {
		kinds = append(kinds, e.Kind)
		if len(kinds) == 2 {
			return errStop
		}
		return nil
	})
	if err != errStop || kinds[0] != "config" || kinds[1] != "head" {
		t.Fatalf("events %v %v", err, kinds)
	}
}

func TestErrorsAndAuth(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{Auth: true})
	anon := s.Client(t)
	admin := clienttest.NewKey("admin")
	op := s.Client(t, client.WithBearer(s.OperatorGrant(t, "sec")))
	must(op.CreateNamespace(ctx, "sec", map[string]any{"read": "grant", "keys": []any{admin.Entry("*")}}))

	if _, err := anon.NSHead(ctx, "sec"); !client.IsAuth(err) {
		t.Fatalf("anonymous: %v", err)
	}
	g := admin.Grant(t, s.Now(), "user:root", []string{"sec"}, []string{"read", "create", "prune"})
	c := anon.With(client.WithBearer(g))
	must(c.NSHead(ctx, "sec"))
	w := must(c.CreateDoc(ctx, "sec", "a", map[string]any{"n": 0}))
	if _, err := c.Append(ctx, "sec", "a", w.ID, ops(op2("replace", "/n", 1))); !client.IsAuth(err) {
		t.Fatalf("append without verb: %v", err)
	}
	if _, err := c.Head(ctx, "bad name", "a"); err == nil {
		t.Fatal("invalid name accepted")
	}

	// Pruning: 410 pruned carries the horizon.
	cfull := anon.With(client.WithBearer(admin.Grant(t, s.Now(), "user:root", []string{"sec"}, []string{"read", "append", "prune"})))
	head := w.ID
	var revs []string
	revs = append(revs, head)
	for i := 1; i <= 3; i++ {
		r := must(cfull.Append(ctx, "sec", "a", head, ops(op2("replace", "/n", i))))
		head = r.ID
		revs = append(revs, head)
	}
	s.Clock.Advance(10 * time.Minute)
	cfull = anon.With(client.WithBearer(admin.Grant(t, s.Now(), "user:root", []string{"sec"}, []string{"read", "append", "prune"})))
	pr := must(cfull.Prune(ctx, "sec", "a", client.PruneRequest{Horizon: revs[2]}))
	if pr.Horizon != revs[2] || pr.NSID == "" {
		t.Fatalf("prune %+v", pr)
	}
	_, err := cfull.Doc(ctx, "sec", "a", revs[1])
	if !client.IsPruned(err) || client.IsGone(err) || client.Horizon(err) != revs[2] {
		t.Fatalf("pruned doc: %v", err)
	}
	if _, err := cfull.Log(ctx, "sec", "a", "", ""); !client.IsPruned(err) {
		t.Fatalf("pruned log: %v", err)
	}
}

func op2(o, path string, v any) map[string]any { return op(o, path, v) }

// Principal is the bearer's root sub and kid, or with authentication
// disabled the X-Author name and no kid (§6.6).
func TestPrincipal(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	dev := clienttest.New(t, clienttest.Options{})
	s := clienttest.New(t, clienttest.Options{Auth: true})
	g := clienttest.NewKey("ops-2026").Grant(t, s.Now(), "svc:importer", []string{"data"}, []string{"read"})
	for _, tc := range []struct {
		c        *client.Client
		sub, kid string
	}{
		{dev.Client(t, client.WithAuthor("bob"), client.WithBearer(g)), "bob", ""},
		{dev.Client(t), "anonymous", ""},
		{s.Client(t, client.WithBearer(g), client.WithAuthor("bob")), "svc:importer", "ops-2026"},
		{s.Client(t, client.WithAuthor("bob")), "", ""},
	} {
		if sub, kid, err := tc.c.Principal(ctx); err != nil || sub != tc.sub || kid != tc.kid {
			t.Fatalf("principal %q %q %v, want %q %q", sub, kid, err, tc.sub, tc.kid)
		}
	}
	if _, _, err := s.Client(t, client.WithBearer("not-a-grant")).Principal(ctx); err == nil {
		t.Fatal("a malformed bearer has a principal")
	}
}

func TestRateLimitRetryAfter(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{})
	c := s.Client(t, client.WithAuthor("admin"))
	must(c.CreateNamespace(ctx, "main", map[string]any{"read": "public",
		"limits": map[string]any{"ratePerResource": map[string]any{"rate": 0.1, "burst": 1}}}))
	w := must(c.CreateDoc(ctx, "main", "a", map[string]any{"n": 0}))
	_, err := c.Append(ctx, "main", "a", w.ID, ops(op("replace", "/n", 1)))
	ae, ok := client.AsAPIError(err)
	if !client.IsRateLimited(err) || !ok || ae.RetryAfter < time.Second || !client.Retryable(err) {
		t.Fatalf("rate limit: %v", err)
	}
}
