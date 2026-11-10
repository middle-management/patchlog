package server

import (
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/core"
	"github.com/middle-management/patchlog/internal/pgtest"
)

// E2E-2 (Addendum E Levels Invariant, v0.78; stored.md item 2): a remote
// branch whose shadow a pre-v0.78 deployment marked raised to e2e (its
// source was raised before at) is refused at Open, named as the remote
// branch, not its shadow. With PurgeRaisedE2E it is purged and answers 410
// purged, its local branch too; another remote branch is kept. Here the
// marker is put back by hand in a database at the current schema, as one
// a v0.26.1 deployment left would hold it.
func TestV081OpenRefusesRaisedRemoteBranch(t *testing.T) {
	t.Parallel()
	ks := newKeyStore(t)
	var path string
	// A database of its own: the test puts a table back (pgtest.FreshDB).
	fresh := func(o *core.Options) {
		if pgtest.Enabled() {
			o.Path = pgtest.FreshDB(t)
		} else {
			o.Path = filepath.Join(t.TempDir(), "b.db")
		}
		path = o.Path
	}
	a, b, _ := pair(t, nil, []envOpt{fresh, withKeyStore(ks), withEncTuning})
	a.mkNS("m", map[string]any{"read": "public"})
	x := a.create("m", "x", map[string]any{"v": 1.0})
	expect(t, b.mkRemote("r", remoteGenesis("m", a.nsHead("m"), nil)), 201)
	expect(t, b.mkRemote("ok", remoteGenesis("m", a.nsHead("m"), nil)), 201)
	expect(t, b.branch("r", map[string]any{"name": "rb"}, "alice"), 201)
	b.srv.Close()
	b.e.Close()

	db, _ := v0261DB(t, path)
	for _, q := range []string{
		`CREATE TABLE e2e_raises (ns bigint PRIMARY KEY, config_seq bigint NOT NULL, level bigint NOT NULL, epoch bigint NOT NULL, pad bigint NOT NULL, created bigint NOT NULL)`,
		`INSERT INTO e2e_raises (ns, config_seq, level, epoch, pad, created) SELECT ns, config_seq, 2, 1, 0, 0 FROM namespaces WHERE name = '~r'`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	opts := core.Options{Path: path, Origin: originB, AuthDisabled: true, KeyStore: ks, RetentionInterval: -1, BlobSweepInterval: -1, Purger: nopPurger{},
		Remote: core.RemoteOptions{FollowInterval: -1}}
	if pgtestBlobDir := t.TempDir(); strings.HasPrefix(path, "postgres") {
		opts.BlobDir = pgtestBlobDir
	}
	_, err := core.Open(opts)
	if err == nil || !strings.Contains(err.Error(), "remote branch r") || strings.Contains(err.Error(), "~r") {
		t.Fatalf("Open with a remote branch of a raised source: %v", err)
	}
	opts.PurgeRaisedE2E = true
	e, err := core.Open(opts)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(New(e))
	t.Cleanup(func() { srv.Close(); e.Close() })
	b2 := &tenv{t: t, e: e, srv: srv, clock: b.clock}
	for _, ns := range []string{"r", "rb"} {
		if r := b2.get("/r/" + ns + "/x/rev/" + x); r.Code != 410 {
			t.Fatalf("%s after -purge-raised-e2e: %d %s, want 410", ns, r.Code, r.Body)
		}
	}
	expect(t, b2.get("/r/ok/x/rev/"+x), 200)
}
