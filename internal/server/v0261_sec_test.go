package server

import (
	"crypto/ed25519"
	"database/sql"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/pgtest"
	"github.com/middle-management/patchlog/internal/sqlitedsn"
)

// v0.26.1: a remote branch against a hostile remote base A (security
// review of v0.26.0, C1-C5, C-M, C-B, C-E). v0.78 cut the pending
// pre-raise sealings these were first found through; the rules that
// remain are held here on a source that is e2e from its creation
// (v081Source), and the snapshot-mirroring tests of v081_enc_remote_test.go.

// v0261DB opens the database at path (withFileDB), and says whether it is
// Postgres, whose placeholders are $n.
func v0261DB(t *testing.T, path string) (*sql.DB, bool) {
	t.Helper()
	driver, dsn := "sqlite", sqlitedsn.DSN(path, "_pragma=busy_timeout(10000)")
	if pgtest.IsURL(path) {
		driver, dsn = "pgx", pgtest.DSN(path)
	}
	db, err := sql.Open(driver, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db, driver == "pgx"
}

func v0261Count(t *testing.T, db *sql.DB, pg bool, q string, args ...any) int {
	t.Helper()
	if pg {
		for i := 1; strings.Contains(q, "?"); i++ {
			q = strings.Replace(q, "?", "$"+strconv.Itoa(i), 1)
		}
	}
	var n int
	if err := db.QueryRow(q, args...).Scan(&n); err != nil {
		t.Fatalf("%s: %v", q, err)
	}
	return n
}

// newFCSameEpoch is A's sealed namespace m with z's blob referenced by two
// revisions under the same epoch 1, z1 and z2 (and z3 after).
func newFCSameEpoch(t *testing.T) (a *tenv, root func() string, bid, z1, z2, z3 string) {
	t.Helper()
	var aPriv ed25519.PrivateKey
	a = newEnv(t, withAuth(&aPriv), withKeyStore(newKeyStore(t)), withEncTuning, withBlobTuning)
	a.opPriv = aPriv
	kA := newKey("admin")
	a.mkNS("m", sealedDoc(map[string]any{"read": "grant", "keys": []any{kA.entry("*")}}))
	root = func() string { return a.grant(kA, "user:root", []string{"m"}, allVerbs) }
	data := []byte("z's blob, referenced twice under epoch 1")
	bid = a.upload("m", "z", "text/plain", data, root())
	z1 = a.wr("m", "z", "", withNonce(addRoot(map[string]any{"b": ref(bid, "text/plain", len(data), ""), "v": 1.0})), root())
	z2 = a.wr("m", "z", z1, withNonce([]any{op("replace", "/v", 2.0)}), root())
	z3 = a.wr("m", "z", z2, withNonce([]any{op("replace", "/v", 3.0)}), root())
	a.clock.Advance(time.Hour)
	return a, root, bid, z1, z2, z3
}

// v0.26.1 final review (C-I3, "410 pruned only where owed"): §E.2.2
// ("Epochs": "An epoch whose referencing revisions were all pruned answers
// 410") owes that 410 only once EVERY revision of e referencing a blob is
// below the horizon, and §8.6 keeps the horizon's own document. Here z1,
// z2 and z3 all reference the blob under epoch 1; A pruned at z2 (and even
// at z3) still serves …/e/1. (v0.78 cut the remote branches' pending
// pre-raise sealings that took A's 410 for it as final.)
func TestV0261BlobPrunedHorizonBeforeLastReference(t *testing.T) {
	t.Parallel()
	a, root, bid, z1, z2, z3 := newFCSameEpoch(t)
	e1 := blobPath("m", "z", bid) + "/e/1"
	expect(t, a.get(e1, root()), 200)
	for _, hz := range []string{z2, z3} {
		expect(t, a.prune("m", "z", map[string]any{"horizon": hz}, root()), 200)
		expect(t, a.get("/r/m/z/rev/"+z1, root()), 410)
		if res := a.get(e1, root()); res.Code != 200 {
			t.Fatalf("pruned at %s: …/e/1 %d %s", hz, res.Code, res.Body)
		}
	}
}

// v0.26.1 final review (C-I3, same class): §8.6 keeps, when the horizon H
// is a tombstone, "the last live document". A that deleted x (tombstone
// x2) and pruned at x2 still serves x1's document; x1's own log range is
// 410. (v0.78 cut the remote branches' pending pre-raise sealings that took
// A's 410 for it as final.)
func TestV0261DocPrunedAtTombstone(t *testing.T) {
	t.Parallel()
	var aPriv ed25519.PrivateKey
	a := newEnv(t, withAuth(&aPriv), withKeyStore(newKeyStore(t)), withEncTuning, withBlobTuning)
	a.opPriv = aPriv
	kA := newKey("admin")
	a.mkNS("m", sealedDoc(map[string]any{"read": "grant", "keys": []any{kA.entry("*")}}))
	root := func() string { return a.grant(kA, "user:root", []string{"m"}, allVerbs) }
	x1 := a.wr("m", "x", "", withNonce(addRoot(map[string]any{"v": 1.0})), root())
	del := a.write("DELETE", "m", "x", x1, nil, root())
	expect(t, del, 200)
	a.clock.Advance(time.Hour)
	expect(t, a.prune("m", "x", map[string]any{"horizon": del.Str("tombstone")}, root()), 200)
	expect(t, a.get("/r/m/x/rev/"+x1+"/log", root()), 410)
	expect(t, a.get("/r/m/x/rev/"+x1, root()), 200)
}

// v0.26.1 review (horizonIn takes rv.seq >= the sealing's revision): a
// real A, sealed, pruned at H, still serves H's document and H's own log
// entry (§8.6 keeps H's document and drops only the patch sets before H),
// so an honest 410 pruned for a sealing of revision R never names R
// itself: its horizon is strictly after R. horizonIn accepts R, so A can
// get B to answer 410 for good for the branch's head as of at, content an
// honest A never answers 410 for with that horizon.
func TestV0261PrunedHorizonStrictlyAfter(t *testing.T) {
	t.Parallel()
	var aPriv ed25519.PrivateKey
	a := newEnv(t, withAuth(&aPriv), withKeyStore(newKeyStore(t)), withEncTuning, withBlobTuning)
	a.opPriv = aPriv
	kA := newKey("admin")
	a.mkNS("m", sealedDoc(map[string]any{"read": "grant", "keys": []any{kA.entry("*")}}))
	root := func() string { return a.grant(kA, "user:root", []string{"m"}, allVerbs) }
	x1 := a.wr("m", "x", "", withNonce(addRoot(map[string]any{"v": 1.0})), root())
	x2 := a.wr("m", "x", x1, withNonce([]any{op("replace", "/v", 2.0)}), root())
	x3 := a.wr("m", "x", x2, withNonce([]any{op("replace", "/v", 3.0)}), root())
	a.clock.Advance(time.Hour) // past the retry window
	res := a.prune("m", "x", map[string]any{"horizon": x2}, root())
	t.Logf("prune at x2: %d %s", res.Code, res.Body)
	expect(t, res, 200)
	for _, c := range []struct {
		path string
		want int
	}{
		{"/r/m/x/rev/" + x1, 410},
		{"/r/m/x/rev/" + x2, 200},
		{"/r/m/x/rev/" + x2 + "/log?since=" + x1, 200},
		{"/r/m/x/rev/" + x3 + "/log?since=" + x2, 200},
	} {
		r := a.get(c.path, root())
		t.Logf("%s: %d %.120s", c.path, r.Code, r.Body)
		if r.Code != c.want {
			t.Errorf("%s: %d, want %d", c.path, r.Code, c.want)
		}
	}
}
