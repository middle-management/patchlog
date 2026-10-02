package server

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/archive"
	"github.com/middle-management/patchlog/internal/bundle"
	"github.com/middle-management/patchlog/internal/core"
	"github.com/middle-management/patchlog/internal/keystore"
)

// Encryption at rest (Addendum E.1).

const encMarker = "zqx-marker-7f3a" // appears only in content, never in names

func newKeyStore(t *testing.T) *keystore.Local {
	t.Helper()
	ks, err := keystore.New(keystore.Generate())
	if err != nil {
		t.Fatal(err)
	}
	return ks
}

func withKeyStore(ks core.KeyStore) envOpt {
	return func(o *core.Options) { o.KeyStore = ks }
}

func withPath(p string) envOpt {
	return func(o *core.Options) { o.Path = p }
}

// withEncTuning makes small documents fold from intermediate snapshots
// (every 3 revisions, no head snapshots over 200 bytes) and lifts the rate
// limits a frozen clock would otherwise exhaust.
func withEncTuning(o *core.Options) {
	o.SnapshotEveryRevisions = 3
	o.HeadSnapshotMax = 200
	l := core.DefaultLimits()
	l.RatePerResource = core.Rate{Rate: 1000, Burst: 1000}
	l.RatePerPrincipal = core.Rate{Rate: 1000, Burst: 1000}
	l.RatePerNamespace = core.Rate{Rate: 1000, Burst: 1000}
	o.Limits, o.Maximums = l, l
}

func atRest(doc map[string]any) map[string]any {
	doc["encryption"] = map[string]any{"level": "at-rest"}
	return doc
}

// checkpoint moves the WAL into the database file and truncates it, from a
// connection of its own.
func checkpoint(t *testing.T, path string) {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(10000)")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var busy, logN, done int
	if err := db.QueryRow(`PRAGMA wal_checkpoint(TRUNCATE)`).Scan(&busy, &logN, &done); err != nil || busy != 0 {
		t.Fatalf("checkpoint: busy %d, %v", busy, err)
	}
}

// storedAnywhere reports whether s occurs in the database file, its WAL or
// a file of its blob directory.
func storedAnywhere(t *testing.T, path, s string) bool {
	t.Helper()
	files := []string{path, path + "-wal"}
	filepath.WalkDir(path+".blobs", func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			files = append(files, p)
		}
		return nil
	})
	for _, p := range files {
		b, err := os.ReadFile(p)
		if err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
		if bytes.Contains(b, []byte(s)) {
			return true
		}
	}
	return false
}

func assertNoPlaintext(t *testing.T, path string) {
	t.Helper()
	if storedAnywhere(t, path, encMarker) {
		t.Fatal("plaintext content found in the database or its WAL")
	}
	checkpoint(t, path)
	if storedAnywhere(t, path, encMarker) {
		t.Fatal("plaintext content found in the database after a checkpoint")
	}
}

func queryInt(t *testing.T, path, q string, args ...any) int {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(10000)")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var n int
	if err := db.QueryRow(q, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func (e *tenv) close() {
	e.srv.CloseClientConnections()
	e.srv.Close()
	e.e.Close()
}

// encScenario runs the same writes and reads in namespace m, encrypted or
// not, and returns everything observable (ids, documents, logs) in order.
func encScenario(t *testing.T, e *tenv, dir string, enc bool) []string {
	var out []string
	rec := func(s ...string) { out = append(out, s...) }
	recBody := func(r *resp) { rec(string(canonical(r.JSON()))) }
	doc := map[string]any{"read": "public"}
	if enc {
		atRest(doc)
	}
	e.mkNS("m", doc)
	a := []string{e.create("m", "a", map[string]any{"title": encMarker + "-a", "n": 0.0})}
	for i := 1; i < 8; i++ {
		a = append(a, e.appendRev("m", "a", a[i-1], ops(op("replace", "/n", float64(i)), op("add", fmt.Sprintf("/p%d", i), encMarker+"-p"))))
	}
	rec(a...)
	tomb := e.del("m", "a", a[7])
	a8 := e.appendRev("m", "a", tomb, []any{}) // restore (§8.2)
	rec(tomb, a8)
	r := e.do(req{method: "POST", path: "/ns/m/batch", author: "alice", body: map[string]any{"items": []any{
		map[string]any{"resource": "b1", "ifNoneMatch": "*", "steps": []any{addRoot(map[string]any{"s": encMarker + "-b1"})}},
		map[string]any{"resource": "b2", "ifNoneMatch": "*", "steps": []any{addRoot(map[string]any{"s": encMarker + "-b2"}), ops(op("add", "/t", encMarker+"-b2t"))}},
	}}})
	expect(t, r, 201)
	rec(string(canonical(r.Obj()["items"])))
	b2 := e.head("m", "b2")

	// A branch reads through the (encrypted) base, then writes its own.
	expect(t, e.branch("m", map[string]any{"name": "br"}, "alice"), 201)
	rec(string(canonical(e.doc("br", "a"))), string(canonical(e.doc("br", "b1"))))
	br1 := e.appendRev("br", "a", a8, ops(op("add", "/branch", encMarker+"-br")))
	br2 := e.appendRev("br", "a", br1, ops(op("replace", "/n", 99.0)))
	rec(br1, br2, string(canonical(e.doc("br", "a"))))
	recBody(e.get("/r/br/a/rev/" + br2 + "/log"))

	// History and logs, after dropping the document cache.
	e.e.FlushCaches()
	for _, id := range append(append([]string{}, a...), a8) {
		g := e.get("/r/m/a/rev/" + id)
		expect(t, g, 200)
		recBody(g)
	}
	lg := e.get("/r/m/a/rev/" + a8 + "/log")
	expect(t, lg, 200)
	recBody(lg)

	// Prune with an archive, then restore it.
	e.clock.Advance(time.Hour)
	pr := e.prune("m", "a", map[string]any{"horizon": a[5]}, "admin")
	expect(t, pr, 200)
	rec(pr.Str("horizon"))
	expectCode(t, e.get("/r/m/a/rev/"+a[1]), 410, "pruned")
	e.e.FlushCaches()
	rec(string(canonical(e.doc("m", "a"))))
	p := filepath.Join(dir, "m", "a", a[5]+".jsonl")
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if enc == bytes.Contains(raw, []byte(encMarker)) {
		t.Fatalf("archive plaintext: %v, want %v", bytes.Contains(raw, []byte(encMarker)), !enc)
	}
	f, _ := os.Open(p)
	plain, err := e.e.OpenArchive(context.Background(), "m", "a", f)
	if err != nil {
		t.Fatal(err)
	}
	s, err := bundle.Verify(plain)
	f.Close()
	if err != nil || s.Lines != 5 {
		t.Fatalf("archive: %v %+v", err, s)
	}
	reps, err := archive.Restore(context.Background(), e.e, archive.RestoreOptions{NS: "m", Name: "a"})
	if err != nil || len(reps) != 1 || !reps[0].Cleared || reps[0].Restored != 5 || len(reps[0].Failed) != 0 {
		t.Fatalf("restore %+v %v", reps, err)
	}
	for _, id := range a[:5] {
		g := e.get("/r/m/a/rev/" + id)
		expect(t, g, 200)
		recBody(g)
	}
	recBody(e.get("/r/m/a/rev/" + a8 + "/log"))

	// Prune b2 (an archive), keep a copy of the archive, purge b2.
	pr = e.prune("m", "b2", map[string]any{"horizon": b2}, "admin")
	expect(t, pr, 200)
	pb := filepath.Join(dir, "m", "b2", b2+".jsonl")
	kept := filepath.Join(t.TempDir(), "kept.jsonl")
	if b, err := os.ReadFile(pb); err != nil {
		t.Fatal(err)
	} else if err := os.WriteFile(kept, b, 0o600); err != nil {
		t.Fatal(err)
	}
	expect(t, e.purge("m", "b2", b2, "admin"), 204)
	expectCode(t, e.get("/r/br/b2"), 410, "gone")
	f, _ = os.Open(kept)
	defer f.Close()
	rd, err := e.e.OpenArchive(context.Background(), "m", "b2", f)
	if enc {
		if !errors.Is(err, core.ErrArchiveKeyDestroyed) {
			t.Fatalf("purged archive opened: %v", err)
		}
	} else if err != nil {
		t.Fatal(err)
	} else if b, _ := io.ReadAll(rd); !bytes.Contains(b, []byte(encMarker)) {
		t.Fatal("plaintext archive unreadable")
	}
	return out
}

// A namespace encrypted at rest stores no plaintext content anywhere in the
// database, and behaves exactly like an unencrypted one: same ids,
// documents, logs, history, branches, batches, restores and archives.
func TestEncryptionAtRestNoPlaintext(t *testing.T) {
	plainDir, encDir := t.TempDir(), t.TempDir()
	plainPath := filepath.Join(t.TempDir(), "plain.db")
	pe := newEnv(t, withArchive(t, plainDir), withoutRetentionLoop, withEncTuning, withPath(plainPath))
	want := encScenario(t, pe, plainDir, false)

	path := filepath.Join(t.TempDir(), "enc.db")
	e := newEnv(t, withArchive(t, encDir), withoutRetentionLoop, withEncTuning, withPath(path), withKeyStore(newKeyStore(t)))
	got := encScenario(t, e, encDir, true)
	if len(got) != len(want) {
		t.Fatalf("%d observations, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("observation %d differs:\n got %s\nwant %s", i, got[i], want[i])
		}
	}
	assertNoPlaintext(t, path)
	// The purged resource's data key is gone, its archive with it.
	if n := queryInt(t, path, `SELECT COUNT(*) FROM deks WHERE res IN (SELECT r.res FROM resources r JOIN namespaces n ON n.ns = r.ns WHERE r.name = 'b2')`); n != 0 {
		t.Fatalf("%d data keys left for purged b2", n)
	}
	if n := queryInt(t, path, `SELECT COUNT(*) FROM deks WHERE res IN (SELECT r.res FROM resources r JOIN namespaces n ON n.ns = r.ns WHERE n.name = 'br')`); n != 1 {
		t.Fatalf("%d data keys for the branch's own rows, want 1", n)
	}
	// And the unencrypted run did store plaintext, so the scan means
	// something.
	checkpoint(t, plainPath)
	if !storedAnywhere(t, plainPath, encMarker) {
		t.Fatal("the plaintext run left no marker to find")
	}
	// Purge the whole namespace family: every data key goes.
	expect(t, e.patchNS("br", ops(op("add", "/frozen", true)), ""), 201)
	expect(t, e.do(req{method: "POST", path: "/ns/br/purge", ifMatch: e.nsHead("br"), author: "admin"}), 204)
	expect(t, e.patchNS("m", ops(op("add", "/frozen", true)), ""), 201)
	expect(t, e.do(req{method: "POST", path: "/ns/m/purge", ifMatch: e.nsHead("m"), author: "admin"}), 204)
	if n := queryInt(t, path, `SELECT COUNT(*) FROM deks WHERE res != 0`); n != 0 {
		t.Fatalf("%d data keys left after namespace purges", n)
	}
}

// Grants used in an encrypted namespace are stored encrypted: the
// writer's, and the operator's, which the namespace's first entry records
// (§7.4). The log still serves their root sub and kid.
func TestEncryptionGrants(t *testing.T) {
	path := filepath.Join(t.TempDir(), "g.db")
	e := newAuthEnv(t, withPath(path), withKeyStore(newKeyStore(t)))
	w := newKey("w")
	e.mkNS("s", atRest(map[string]any{"read": "grant", "keys": []any{w.entry("read", "create", "append")}}))
	g := e.grant(w, "user:ann", []string{"s"}, []string{"read", "create"}, map[string]any{"attrs": map[string]any{"region": encMarker}})
	e.create("s", "x", map[string]any{"v": encMarker}, g)
	if d := e.doc("s", "x", g); d["v"] != encMarker {
		t.Fatalf("doc %v", d)
	}
	assertNoPlaintext(t, path)
	if n := queryInt(t, path, `SELECT COUNT(*) FROM grants WHERE substr(blocks, 1, 1) = x'01'`); n != 2 {
		t.Fatalf("%d encrypted grants, want 2", n)
	}
	lg := e.get("/ns/s/rev/"+e.nsHead("s", g)+"/log", g).Arr()
	if len(lg) != 2 {
		t.Fatalf("log %v", lg)
	}
	for i, want := range []string{"op:root operator", "user:ann w"} {
		gr, _ := lg[i].(map[string]any)["grant"].(map[string]any)
		if fmt.Sprint(gr["sub"], " ", gr["kid"]) != want {
			t.Fatalf("entry %d grant %v, want %s", i, gr, want)
		}
	}
}

// Turning at-rest on for an existing namespace encrypts what it stores,
// grants included, and everything still reads. Lowering it is refused.
func TestEncryptionTurnOn(t *testing.T) {
	path := filepath.Join(t.TempDir(), "on.db")
	dir := t.TempDir()
	e := newAuthEnv(t, withPath(path), withKeyStore(newKeyStore(t)), withEncTuning, withArchive(t, dir), withoutRetentionLoop)
	admin, w := newKey("admin"), newKey("w")
	e.mkNS("s", map[string]any{"read": "grant", "keys": []any{admin.entry("*"), w.entry("read", "create", "append", "delete", "prune", "branch")}})
	ga := e.grant(admin, "user:root", []string{"s", "sb"}, allVerbs)
	g := e.grant(w, "user:ann", []string{"s"}, []string{"read", "create", "append", "prune"}, map[string]any{"attrs": map[string]any{"region": encMarker}})
	x := []string{e.create("s", "x", map[string]any{"v": encMarker + "-0"}, g)}
	for i := 1; i < 7; i++ {
		x = append(x, e.appendRev("s", "x", x[i-1], ops(op("add", fmt.Sprintf("/k%d", i), encMarker)), g))
	}
	e.create("s", "y", map[string]any{"v": encMarker + "-y"}, g)
	expect(t, e.branch("s", map[string]any{"name": "sb"}, ga), 201)
	before := e.get("/r/s/x/rev/"+x[6]+"/log", g)
	expect(t, before, 200)
	checkpoint(t, path)
	if !storedAnywhere(t, path, encMarker) {
		t.Fatal("no plaintext before encryption was turned on")
	}

	// The plaintext branch must be raised first (§7.4: no branch below
	// its base).
	on := ops(op("add", "/encryption", map[string]any{"level": "at-rest"}))
	r := e.patchNS("s", on, ga)
	expectCode(t, r, 409, "in_use")
	expect(t, e.patchNS("sb", on, ga), 201)
	expect(t, e.patchNS("s", on, ga), 201)
	// The database file keeps the old pages until the WAL, which holds the
	// encrypted ones (and secure_delete's zeroed free space), is
	// checkpointed.
	checkpoint(t, path)
	assertNoPlaintext(t, path)

	e.e.FlushCaches()
	after := e.get("/r/s/x/rev/"+x[6]+"/log", g)
	expect(t, after, 200)
	if string(canonical(after.JSON())) != string(canonical(before.JSON())) {
		t.Fatalf("log changed:\n%s\n%s", after.Body, before.Body)
	}
	for i, id := range x {
		d := e.get("/r/s/x/rev/"+id, g)
		expect(t, d, 200)
		if d.Obj()["v"] != encMarker+"-0" || (i > 0 && d.Obj()[fmt.Sprintf("k%d", i)] != encMarker) {
			t.Fatalf("rev %d: %s", i, d.Body)
		}
	}
	if d := e.doc("sb", "y", ga); d["v"] != encMarker+"-y" {
		t.Fatalf("read-through %v", d)
	}
	// New writes, and a prune whose archive is now encrypted.
	x = append(x, e.appendRev("s", "x", x[6], ops(op("add", "/new", encMarker)), g))
	e.clock.Advance(10 * time.Minute) // past the retry window, before the grants expire
	expect(t, e.prune("s", "x", map[string]any{"horizon": x[4]}, g), 200)
	if b, _ := os.ReadFile(filepath.Join(dir, "s", "x", x[4]+".jsonl")); !bytes.HasPrefix(b, []byte("PLAR")) || bytes.Contains(b, []byte(encMarker)) {
		t.Fatal("archive of an encrypted namespace is not encrypted")
	}
	assertNoPlaintext(t, path)

	// Downgrades are refused.
	expectCode(t, e.patchNS("s", ops(op("remove", "/encryption")), ga), 422, "invalid")
	expectCode(t, e.patchNS("sb", ops(op("remove", "/encryption")), ga), 422, "invalid")
	// Raising s to sealed while its branch stays at rest is 409 (§7.4).
	expectCode(t, e.patchNS("s", ops(op("replace", "/encryption/level", "sealed")), ga), 409, "in_use")
}

// Configuration errors: no key store, unknown levels and members, a branch
// below its base.
func TestEncryptionConfigErrors(t *testing.T) {
	e := newEnv(t)
	r := e.do(req{method: "PATCH", path: "/ns/s", ifNoneMatch: "*", body: addRoot(atRest(map[string]any{"read": "public"})), author: "admin"})
	expectCode(t, r, 422, "invalid")
	if !strings.Contains(r.Str("message"), "no key store") {
		t.Fatalf("message %s", r.Body)
	}
	e.mkNS("p", map[string]any{"read": "public"})
	expectCode(t, e.patchNS("p", ops(op("add", "/encryption", map[string]any{"level": "at-rest"})), ""), 422, "invalid")

	k := newEnv(t, withKeyStore(newKeyStore(t)))
	for _, bad := range []any{"at-rest", map[string]any{"level": "sealed", "epoch": 0.0}, map[string]any{"level": "at-rest", "epoch": 1.0}, map[string]any{"level": "sealed", "historyEpochs": 1.5}, map[string]any{"level": "e2e", "epoch": 0.0}, map[string]any{"level": "x"}, map[string]any{"level": "at-rest", "keys": []any{}}} {
		r := k.do(req{method: "PATCH", path: "/ns/bad", ifNoneMatch: "*", body: addRoot(map[string]any{"read": "public", "encryption": bad}), author: "admin"})
		expectCode(t, r, 422, "invalid")
	}
	k.mkNS("s", atRest(map[string]any{"read": "public"}))
	k.create("s", "a", map[string]any{"v": 1.0})
	// A branch inherits the level and can't drop it.
	expectCode(t, k.branch("s", map[string]any{"name": "low", "patches": ops(op("remove", "/encryption"))}, "admin"), 422, "invalid")
	expect(t, k.branch("s", map[string]any{"name": "ok"}, "admin"), 201)
	expectCode(t, k.patchNS("ok", ops(op("remove", "/encryption")), ""), 422, "invalid")
	if d := k.doc("ok", "a"); d["v"] != 1.0 {
		t.Fatalf("read-through %v", d)
	}
	// A branch may be encrypted above a plaintext base.
	k.mkNS("p", map[string]any{"read": "public"})
	k.create("p", "a", map[string]any{"v": 2.0})
	expect(t, k.branch("p", map[string]any{"name": "hi", "patches": ops(op("add", "/encryption", map[string]any{"level": "at-rest"}))}, "admin"), 201)
	h := k.appendRev("hi", "a", k.head("p", "a"), ops(op("replace", "/v", 3.0)))
	if d := k.doc("hi", "a"); d["v"] != 3.0 || h == "" {
		t.Fatalf("branch write %v", d)
	}
}

// A wrong master key fails at startup; no key store serves plaintext
// namespaces and answers 500 for encrypted ones.
func TestEncryptionWrongMasterKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "k.db")
	e := newEnv(t, withPath(path), withKeyStore(newKeyStore(t)))
	e.mkNS("s", atRest(map[string]any{"read": "public"}))
	e.mkNS("p", map[string]any{"read": "public"})
	e.create("s", "a", map[string]any{"v": encMarker})
	e.create("p", "a", map[string]any{"v": 1.0})
	e.close()

	_, err := core.Open(core.Options{Path: path, KeyStore: newKeyStore(t), RetentionInterval: -1})
	if err == nil || !strings.Contains(err.Error(), "master key") {
		t.Fatalf("open with a wrong master key: %v", err)
	}

	n := newEnv(t, withPath(path))
	if d := n.doc("p", "a"); d["v"] != 1.0 {
		t.Fatalf("plaintext namespace %v", d)
	}
	r := n.get("/r/s/a")
	expect(t, r, 302)
	r = n.get(r.H.Get("Location"))
	expectCode(t, r, 500, "encryption_unavailable")
	if !strings.Contains(r.Str("message"), "no key store") {
		t.Fatalf("message %s", r.Body)
	}
	// Writes don't fall back to plaintext either.
	expectCode(t, n.write("PATCH", "s", "b", "", addRoot(map[string]any{"v": encMarker})), 500, "encryption_unavailable")
	n.close()
	if storedAnywhere(t, path, encMarker) {
		t.Fatal("a write without a key store stored plaintext")
	}
}

// A remote branch's mirrored shadow rows follow the branch's level (§G.3),
// from creation or once it is raised; a remote base's level binds too.
func TestEncryptionRemoteBranch(t *testing.T) {
	path := filepath.Join(t.TempDir(), "b.db")
	a, b, _ := pair(t, []envOpt{withKeyStore(newKeyStore(t)), withEncTuning}, []envOpt{withPath(path), withKeyStore(newKeyStore(t)), withEncTuning})
	a.mkNS("m", map[string]any{"read": "public"})
	x := []string{a.create("m", "x", map[string]any{"v": encMarker})}
	for i := 1; i < 5; i++ {
		x = append(x, a.appendRev("m", "x", x[i-1], ops(op("add", fmt.Sprintf("/k%d", i), encMarker))))
	}
	at := a.nsHead("m")
	enc := map[string]any{"encryption": map[string]any{"level": "at-rest"}}
	expect(t, b.mkRemote("rb", remoteGenesis("m", at, enc)), 201)
	if d := b.doc("rb", "x"); d["k4"] != encMarker {
		t.Fatalf("read-through %v", d)
	}
	y := b.appendRev("rb", "x", x[4], ops(op("add", "/own", encMarker)))
	if l := b.get("/r/rb/x/rev/" + y + "/log"); l.Code != 200 || len(l.Arr()) != 6 {
		t.Fatalf("log %d %s", l.Code, l.Body)
	}
	assertNoPlaintext(t, path)

	// A plaintext remote branch, encrypted later: the shadow goes too.
	expect(t, b.mkRemote("rb2", remoteGenesis("m", at, nil)), 201)
	checkpoint(t, path)
	if !storedAnywhere(t, path, encMarker) {
		t.Fatal("no plaintext in a plaintext remote branch")
	}
	expect(t, b.patchNS("rb2", ops(op("add", "/encryption", map[string]any{"level": "at-rest"})), ""), 201)
	checkpoint(t, path)
	assertNoPlaintext(t, path)
	b.e.FlushCaches()
	if d := b.doc("rb2", "x"); d["k4"] != encMarker {
		t.Fatalf("read-through after encryption %v", d)
	}

	// An encrypted base's remote branch can't be plaintext.
	a.mkNS("s", atRest(map[string]any{"read": "public"}))
	a.create("s", "z", map[string]any{"v": 1.0})
	expectCode(t, b.mkRemote("rb3", remoteGenesis("s", a.nsHead("s"), nil)), 422, "invalid")
	expect(t, b.mkRemote("rb3", remoteGenesis("s", a.nsHead("s"), enc)), 201)
}
