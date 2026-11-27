package core

import (
	"context"
	"database/sql/driver"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/keystore"
	"github.com/middle-management/patchlog/internal/pgtest"
	"github.com/middle-management/patchlog/internal/seal"
)

// Spec v0.91: a purged namespace keeps only its name and the id of its
// purge-ns entry (§5, §8.5), and every request to it answers 410 purged
// before any of §7's steps, whatever the grant.

// v091Rows counts the rows namespace ns has left in every table that
// holds a namespace's content, by table.
func v091Rows(t *testing.T, e *Engine, ns string) map[string]int {
	t.Helper()
	out := map[string]int{}
	var id int64
	q := `SELECT ns FROM namespaces WHERE name = ?`
	if e.pg {
		q = rebind(q)
	}
	if err := e.db.QueryRow(q, ns).Scan(&id); err != nil {
		t.Fatal(err)
	}
	for table, where := range map[string]string{
		"ns_log":        `ns = ?`,
		"ns_config":     `ns = ?`,
		"ns_grants":     `ns = ?`,
		"resources":     `ns = ?`,
		"revisions":     `res IN (SELECT res FROM resources WHERE ns = ?)`,
		"head_history":  `res IN (SELECT res FROM resources WHERE ns = ?)`,
		"heads":         `res IN (SELECT res FROM resources WHERE ns = ?)`,
		"blobs":         `res IN (SELECT res FROM resources WHERE ns = ?)`,
		"blob_refs":     `res IN (SELECT res FROM resources WHERE ns = ?)`,
		"epoch_keys":    `ns = ?`,
		"e2e_epochs":    `ns = ?`,
		"rev_epochs":    `seq IN (SELECT v.seq FROM revisions v JOIN resources r ON r.res = v.res WHERE r.ns = ?)`,
		"sealed":        `ns = ?`,
		"rotations_due": `ns = ?`,
	} {
		q := `SELECT COUNT(*) FROM ` + table + ` WHERE ` + where
		if e.pg {
			q = rebind(q)
		}
		var n int
		if err := e.db.QueryRow(q, id).Scan(&n); err != nil {
			t.Fatalf("%s: %v", table, err)
		}
		out[table] = n
	}
	return out
}

// v091Gone checks that err is the 410 purged of a namespace whose purge-ns
// entry is head.
func v091Gone(t *testing.T, what string, err error, head string) {
	t.Helper()
	var e *Error
	if !errors.As(err, &e) || e.Status != 410 || e.Body["code"] != "purged" || e.Body["head"] != head {
		t.Errorf("%s: %v, want 410 purged with head %s", what, err, head)
	}
}

func v091Freeze(t *testing.T, e *Engine, ns string) {
	t.Helper()
	r := who
	r.NS = ns
	info, err := e.NamespaceHead(context.Background(), ns, Credentials{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.WriteConfig(context.Background(), r, ConfigChange{IfMatch: info.Config, Patches: []any{map[string]any{"op": "add", "path": "/frozen", "value": true}}}); err != nil {
		t.Fatal(err)
	}
}

func v091PurgeNS(t *testing.T, e *Engine, ns string) string {
	t.Helper()
	v091Freeze(t, e, ns)
	info, err := e.NamespaceHead(context.Background(), ns, Credentials{})
	if err != nil {
		t.Fatal(err)
	}
	r := who
	r.NS = ns
	id, err := e.PurgeNamespace(context.Background(), r, info.Head, false)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// §5, §8.5: after a namespace purge nothing of it is left but its name
// and its purge-ns id; every request to it is 410 with that id, which a
// creation under its name doesn't get (412); its GET /ns row has only
// name, frozen and purged.
func TestV091PurgedNamespaceKeepsNameAndPurgeID(t *testing.T) {
	t.Parallel()
	e := openInstance(t, pgtest.DB(t), t.TempDir())
	ctx := context.Background()
	mkNS(t, e, "old", map[string]any{"read": "public"})
	v1, err := put(e, "old", "derby", "", 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := put(e, "old", "derby", v1, 2); err != nil {
		t.Fatal(err)
	}
	if _, err := put(e, "old", "cup", "", 1); err != nil {
		t.Fatal(err)
	}
	head := v091PurgeNS(t, e, "old")
	for table, n := range v091Rows(t, e, "old") {
		if n != 0 {
			t.Errorf("%s keeps %d rows of the purged namespace", table, n)
		}
	}
	_, err = e.NamespaceHead(ctx, "old", Credentials{})
	v091Gone(t, "GET /ns/old", err, head)
	_, err = e.NamespaceLog(ctx, "old", head, "", 10, Credentials{})
	v091Gone(t, "its log at the purge-ns id", err, head)
	_, err = e.NamespaceEvents(ctx, "old", "", 10, Credentials{})
	v091Gone(t, "its events", err, head)
	_, err = e.ResourceHead(ctx, "old", "derby", Credentials{})
	v091Gone(t, "GET /r/old/derby", err, head)
	_, err = e.ResourceRev(ctx, "old", "derby", v1, Credentials{})
	v091Gone(t, "a revision", err, head)
	_, err = e.ResourceLog(ctx, "old", "derby", v1, "", 10, Credentials{})
	v091Gone(t, "a revision's log", err, head)
	_, err = e.NamespaceHeads(ctx, "old", head, "", Credentials{})
	v091Gone(t, "/heads", err, head)
	_, err = e.BranchList(ctx, "old", "", Credentials{})
	v091Gone(t, "/branches", err, head)
	_, err = put(e, "old", "new", "", 1)
	v091Gone(t, "a write", err, head)
	r := who
	r.NS = "old"
	_, err = e.PurgeNamespace(ctx, r, head, false)
	v091Gone(t, "a purge again", err, head)
	_, err = e.WriteConfig(ctx, r, ConfigChange{IfMatch: "x", Patches: []any{}})
	v091Gone(t, "a config write", err, head)
	_, err = e.CreateBranch(ctx, r, BranchRequest{Name: "old-b", IfNoneMatch: true})
	v091Gone(t, "branching from it", err, head)
	// Creating it again is 412, the name staying reserved (§7.6).
	_, err = e.WriteConfig(ctx, r, ConfigChange{IfNoneMatch: true, Patches: []any{map[string]any{"op": "add", "path": "", "value": map[string]any{}}}})
	if status(err) != 412 {
		t.Errorf("creating old again: %v, want 412", err)
	}
	page, err := e.Namespaces(ctx, "", "", Credentials{})
	if err != nil {
		t.Fatal(err)
	}
	var row map[string]any
	for _, m := range page.Items {
		if m["name"] == "old" {
			row = m
		}
	}
	if len(row) != 3 || row["frozen"] != true || row["purged"] != true {
		t.Errorf("GET /ns row of old: %v, want only name, frozen true and purged true", row)
	}
}

// §7.4, §5: a purged branch's row in its base's /branches has only name,
// at (the base's branch entry), frozen and purged; the base, still live,
// serves its own content, a purge propagated into the branch from it
// included.
func TestV091PurgedBranchRow(t *testing.T) {
	t.Parallel()
	e := openInstance(t, pgtest.DB(t), t.TempDir())
	ctx := context.Background()
	mkNS(t, e, "docs", map[string]any{})
	x, err := put(e, "docs", "x", "", 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := put(e, "docs", "y", "", 1); err != nil {
		t.Fatal(err)
	}
	r := who
	r.NS = "docs"
	br, err := e.CreateBranch(ctx, r, BranchRequest{Name: "d-1", IfNoneMatch: true})
	if err != nil {
		t.Fatal(err)
	}
	// A purge in the base reaches the branch, whose row then points at
	// the base's revision (head_history, resources).
	if _, err := e.Purge(ctx, r, "x", x, false); err != nil {
		t.Fatal(err)
	}
	head := v091PurgeNS(t, e, "d-1")
	for table, n := range v091Rows(t, e, "d-1") {
		if n != 0 {
			t.Errorf("%s keeps %d rows of the purged branch", table, n)
		}
	}
	bl, err := e.BranchList(ctx, "docs", "", Credentials{})
	if err != nil || len(bl.List) != 1 {
		t.Fatalf("/ns/docs/branches: %+v %v", bl, err)
	}
	want := map[string]any{"name": "d-1", "at": br.NSID, "frozen": true, "purged": true}
	if got := bl.List[0]; len(got) != len(want) || got["name"] != want["name"] || got["frozen"] != true || got["purged"] != true || got["at"] == "" {
		t.Errorf("the purged branch's row: %v, want %v's members", got, want)
	}
	_, err = e.ResourceHead(ctx, "d-1", "y", Credentials{})
	v091Gone(t, "the branch's read-through", err, head)
	if h, err := e.ResourceHead(ctx, "docs", "y", Credentials{}); err != nil || h.State != Live {
		t.Fatalf("docs/y: %+v %v", h, err)
	}
	if h, err := e.ResourceHead(ctx, "docs", "x", Credentials{}); err != nil || h.State != Purged {
		t.Fatalf("docs/x: %+v %v", h, err)
	}
	// The base can be purged once its branch is (§8.5 dependents).
	head = v091PurgeNS(t, e, "docs")
	_, err = e.BranchList(ctx, "docs", "", Credentials{})
	v091Gone(t, "the purged base's /branches", err, head)
}

// §7.5 (v0.91): a batch whose local source names a purged namespace is
// 410 purged, with ns and head, for any caller and under dry run, at step
// 4; its idempotent retry, first recorded before the purge, is 200, the
// retry lookup coming first.
func TestV091BatchSourcePurged(t *testing.T) {
	t.Parallel()
	e := openInstance(t, pgtest.DB(t), t.TempDir())
	ctx := context.Background()
	mkNS(t, e, "docs", map[string]any{})
	mkNS(t, e, "old", map[string]any{})
	if _, err := put(e, "old", "a", "", 1); err != nil {
		t.Fatal(err)
	}
	at, err := e.NamespaceHead(ctx, "old", Credentials{})
	if err != nil {
		t.Fatal(err)
	}
	r := who
	r.NS = "docs"
	item := func(name string) []Item {
		return []Item{{Resource: name, IfNoneMatch: true, Steps: []Step{{Patches: []any{map[string]any{"op": "add", "path": "", "value": map[string]any{"n": 1.0}}}}}}}
	}
	src := map[string]any{"ns": "old", "at": at.Head}
	first, err := e.Batch(ctx, r, item("before"), nil, src, false)
	if err != nil {
		t.Fatal(err)
	}
	purge := v091PurgeNS(t, e, "old")
	for _, dry := range []bool{false, true} {
		_, err := e.Batch(ctx, r, item("after"), nil, src, dry)
		var ae *Error
		if !errors.As(err, &ae) || ae.Status != 410 || ae.Body["code"] != "purged" || ae.Body["ns"] != "old" || ae.Body["head"] != purge {
			t.Errorf("a batch naming purged old (dry run %v): %v, want 410 purged with ns old and head %s", dry, err, purge)
		}
	}
	again, err := e.Batch(ctx, r, item("before"), nil, src, false)
	if err != nil || again.NSID != first.NSID {
		t.Fatalf("the retry of a batch recorded before the purge: %+v %v, want its entry %s", again, err, first.NSID)
	}
}

// §8.5 (v0.91): a grant presented at a purged namespace, valid or not, gets
// its 410: no key is left to verify it with. The edge exchange gives it too
// for a grant whose only refused namespaces are purged, whether or not it
// would verify there (§C.5.2, Access scenario 63).
func TestV091PurgedWhateverTheGrant(t *testing.T) {
	t.Parallel()
	w := newV75World(t, v75Opts{})
	w.seed()
	ctx := context.Background()
	head := v077Purge(t, w, "matches")
	other := w.catPriv
	for name, c := range map[string]Credentials{
		"none":        {},
		"garbage":     {Bearer: "not-a-grant"},
		"unknown key": w.cred(other, map[string]any{"kid": "nobody", "sub": "user:x", "ns": []any{"matches"}, "can": []any{"read"}}),
		"other ns":    w.cred(w.kPriv, map[string]any{"kid": "k", "sub": "user:x", "ns": []any{"cat-season"}, "can": []any{"read"}}),
		"a reader":    w.li(),
	} {
		_, err := w.e.NamespaceHead(ctx, "matches", c)
		v091Gone(t, name+" at /ns/matches", err, head)
		_, err = w.e.ResourceHead(ctx, "matches", "derby", c)
		v091Gone(t, name+" at /r/matches/derby", err, head)
		_, err = w.e.Principal(ctx, "matches", c)
		v091Gone(t, name+" at /principal", err, head)
		_, err = w.e.Keys(ctx, "matches", c, KeysRequest{})
		v091Gone(t, name+" at /keys", err, head)
	}
	g := w.cred(w.catPriv, map[string]any{"kid": "nobody", "sub": "user:x", "ns": []any{"matches"}, "can": []any{"read"}})
	_, err := w.e.IssueEdgeGrants(ctx, []string{g.Bearer})
	var ae *Error
	if !errors.As(err, &ae) || ae.Status != 410 || ae.Body["ns"] != "matches" || ae.Body["head"] != head {
		t.Errorf("an exchange of a grant an unknown key signed, naming only purged matches: %v, want 410 with ns and head", err)
	}
}

// §5, §12.1 (v0.91; CONFORMANCE scenario 111): storage that can't be
// reached answers 503 unavailable, Retry-After set and no-store, never
// a 404 or an internal error. Not parallel: it sets testStorageFault.
func TestV091StorageUnavailable(t *testing.T) {
	e := openInstance(t, pgtest.DB(t), t.TempDir())
	ctx := context.Background()
	mkNS(t, e, "docs", map[string]any{})
	v, err := put(e, "docs", "derby", "", 1)
	if err != nil {
		t.Fatal(err)
	}
	testStorageFault = func() error { return driver.ErrBadConn }
	t.Cleanup(func() { testStorageFault = nil })
	_, err = e.ResourceLog(ctx, "docs", "derby", v, "", 10, Credentials{})
	var ae *Error
	if !errors.As(err, &ae) || ae.Status != 503 || ae.Body["code"] != "unavailable" || ae.Header.Get("Retry-After") == "" || ae.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("a log range with storage unreachable: %v, want 503 unavailable with Retry-After and no-store", err)
	}
	_, err = e.ResourceRev(ctx, "docs", "derby", v, Credentials{})
	if !errors.As(err, &ae) || ae.Status != 503 {
		t.Fatalf("a revision with storage unreachable: %v, want 503", err)
	}
	testStorageFault = nil
	if _, err := e.ResourceLog(ctx, "docs", "derby", v, "", 10, Credentials{}); err != nil {
		t.Fatalf("once reachable again: %v", err)
	}
}

// Migration 035_purged_namespaces_keep_name_and_purge_id (Postgres; 033_…
// on SQLite): the namespaces purged before it, which kept their log,
// document chain and resources' ids, keep only their name and purge-ns id
// afterwards, a purged branch whose rows point at its live base's included,
// and answer as any purged namespace does; the base is untouched.
func TestV091PurgedNamespacesTrimmedOnUpgrade(t *testing.T) {
	path := pgtest.FreshDB(t)
	before := 34 // Postgres: 034_ns_log_first_entries_by_grant_and_config
	if !pgtest.Enabled() {
		path = filepath.Join(t.TempDir(), "old.db")
		before = 32 // SQLite: 032_…
	}
	blobs := t.TempDir()
	ks, err := keystore.New(keystore.Generate())
	if err != nil {
		t.Fatal(err)
	}
	opts := func() Options {
		lim := DefaultLimits()
		fast := Rate{1e9, 1e9}
		lim.RatePerResource, lim.RatePerPrincipal, lim.RatePerNamespace = fast, fast, fast
		return Options{Path: path, BlobDir: blobs, AuthDisabled: true, RetentionInterval: -1, BlobSweepInterval: -1, Limits: lim, Purger: discardPurger{}, KeyStore: ks}
	}
	ctx := context.Background()
	o := opts()
	o.migrations = migrationsUpTo(t, before)
	old, err := Open(o)
	if err != nil {
		t.Fatal(err)
	}
	testLegacyNSPurge = true
	t.Cleanup(func() { testLegacyNSPurge = false })
	// A sealed namespace, whose read seals its revision (rev_epochs,
	// sealed), as an old purge left them.
	mkNS(t, old, "sec", map[string]any{"encryption": map[string]any{"level": "sealed"}})
	r := who
	r.NS = "sec"
	sres, err := old.WriteResource(ctx, r, Item{Resource: "a", IfNoneMatch: true, Steps: []Step{{Patches: []any{map[string]any{"op": "add", "path": "", "value": map[string]any{"n": 1.0}}, map[string]any{"op": "add", "path": "/$nonce", "value": seal.NewNonce()}}}}})
	if err != nil {
		t.Fatal(err)
	}
	if rev, err := old.ResourceRev(ctx, "sec", "a", sres.Items[0].IDs[0], Credentials{}); err != nil || rev.Status != 200 || rev.JWE == "" {
		t.Fatalf("sec/a sealed: %+v %v", rev, err)
	}
	mkNS(t, old, "old", map[string]any{})
	if _, err := put(old, "old", "a", "", 1); err != nil {
		t.Fatal(err)
	}
	mkNS(t, old, "docs", map[string]any{})
	x, err := put(old, "docs", "x", "", 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := put(old, "docs", "y", "", 1); err != nil {
		t.Fatal(err)
	}
	r.NS = "docs"
	if _, err := old.CreateBranch(ctx, r, BranchRequest{Name: "d-1", IfNoneMatch: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := put(old, "d-1", "z", "", 1); err != nil {
		t.Fatal(err)
	}
	if _, err := old.Purge(ctx, r, "x", x, false); err != nil {
		t.Fatal(err)
	}
	heads := map[string]string{"d-1": v091PurgeNS(t, old, "d-1"), "old": v091PurgeNS(t, old, "old"), "sec": v091PurgeNS(t, old, "sec")}
	testLegacyNSPurge = false
	// Before the migration the rows are there.
	if n := v091Rows(t, old, "d-1"); n["ns_log"] == 0 || n["revisions"] == 0 || n["head_history"] == 0 {
		t.Fatalf("the legacy purge kept no rows: %v", n)
	}
	if n := v091Rows(t, old, "sec"); n["rev_epochs"] == 0 || n["ns_config"] == 0 {
		t.Fatalf("the legacy purge of sec kept no rows: %v", n)
	}
	if err := old.Close(); err != nil {
		t.Fatal(err)
	}

	e, err := Open(opts())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close() })
	for ns, head := range heads {
		for table, n := range v091Rows(t, e, ns) {
			if n != 0 {
				t.Errorf("%s keeps %d rows of purged %s after the upgrade", table, n, ns)
			}
		}
		_, err := e.NamespaceHead(ctx, ns, Credentials{})
		v091Gone(t, ns+" after the upgrade", err, head)
		_, err = e.ResourceHead(ctx, ns, "a", Credentials{})
		v091Gone(t, ns+"'s resource after the upgrade", err, head)
	}
	if h, err := e.ResourceHead(ctx, "docs", "y", Credentials{}); err != nil || h.State != Live {
		t.Fatalf("docs/y after the upgrade: %+v %v", h, err)
	}
	if h, err := e.ResourceHead(ctx, "docs", "x", Credentials{}); err != nil || h.State != Purged {
		t.Fatalf("docs/x after the upgrade: %+v %v", h, err)
	}
	bl, err := e.BranchList(ctx, "docs", "", Credentials{})
	if err != nil || len(bl.List) != 1 || bl.List[0]["purged"] != true || bl.List[0]["frozen"] != true || len(bl.List[0]) != 4 {
		t.Fatalf("docs' branches after the upgrade: %+v %v", bl, err)
	}
	// The base still works: writes, and its log.
	if _, err := put(e, "docs", "w", "", 1); err != nil {
		t.Fatal(err)
	}
	info, err := e.NamespaceHead(ctx, "docs", Credentials{})
	if err != nil {
		t.Fatal(err)
	}
	if lg, err := e.NamespaceLog(ctx, "docs", info.Head, "", 100, Credentials{}); err != nil || lg.Status != 200 {
		t.Fatalf("docs' log: %+v %v", lg, err)
	}
	r.NS = "old"
	_, err = e.WriteConfig(ctx, r, ConfigChange{IfNoneMatch: true, Patches: []any{map[string]any{"op": "add", "path": "", "value": map[string]any{}}}})
	if status(err) != 412 {
		t.Errorf("creating old again after the upgrade: %v, want 412", err)
	}
}

// §8.5, D.8 (v0.91): a namespace purge deletes its log, the purge-ns entry
// included, so the other instances' tailers learn of it from the
// namespace's row (purged_xid): a live reader of the namespace on another
// instance is woken, and its next read is the 410.
func TestPGPurgeNSWakesOtherInstance(t *testing.T) {
	a, b := twoInstances(t)
	mkNS(t, a, "n", map[string]any{"read": "public"})
	if _, err := put(a, "n", "r", "", 0); err != nil {
		t.Fatal(err)
	}
	v091Freeze(t, a, "n")
	time.Sleep(3 * tailEvery) // the writes' own wake-ups
	wait := b.Wait("n")
	info, err := a.NamespaceHead(context.Background(), "n", Credentials{})
	if err != nil {
		t.Fatal(err)
	}
	r := who
	r.NS = "n"
	head, err := a.PurgeNamespace(context.Background(), r, info.Head, false)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-wait:
	case <-time.After(5 * time.Second):
		t.Fatal("the other instance's live reader wasn't woken by the purge")
	}
	_, err = b.NamespaceEvents(context.Background(), "n", "", 10, Credentials{})
	v091Gone(t, "the other instance's read", err, head)
}

// §8.5, §7.7 (v0.91): a long-poll's kept answers and its pass don't outlive
// a namespace purge: the same since with the same pass, which before the
// purge shared a kept page, is 410 after it.
func TestV091LongPollPassAfterPurge(t *testing.T) {
	t.Parallel()
	e := openInstance(t, pgtest.DB(t), t.TempDir())
	ctx := context.Background()
	mkNS(t, e, "n", map[string]any{"read": "public"})
	before, err := e.NamespaceHead(ctx, "n", Credentials{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := put(e, "n", "r", "", 0); err != nil {
		t.Fatal(err)
	}
	lg, pass, err := e.NamespaceLiveLog(ctx, "n", before.Head, 10, Credentials{}, nil)
	if err != nil || len(lg.Entries) != 1 {
		t.Fatalf("first poll: %+v %v", lg, err)
	}
	if lg, _, err = e.NamespaceLiveLog(ctx, "n", before.Head, 10, Credentials{}, pass); err != nil || len(lg.Entries) != 1 {
		t.Fatalf("with its pass: %+v %v", lg, err)
	}
	head := v091PurgeNS(t, e, "n")
	_, _, err = e.NamespaceLiveLog(ctx, "n", before.Head, 10, Credentials{}, pass)
	v091Gone(t, "the same poll with its pass after the purge", err, head)
}
