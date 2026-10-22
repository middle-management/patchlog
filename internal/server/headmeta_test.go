package server

import (
	"context"
	"crypto/ecdh"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/core"
	"github.com/middle-management/patchlog/internal/pgtest"
	"github.com/middle-management/patchlog/internal/seal"
	"github.com/middle-management/patchlog/internal/sqlitedsn"
)

// §7.1 and §7.4 outside sealed and e2e namespaces: Last-Modified and
// Repr-Digest on GET and HEAD …/rev/{id}, created on /heads entries, and
// size and digest on live heads; none of them at E2 and E3.

func reprDigest(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha-256=:" + base64.StdEncoding.EncodeToString(sum[:]) + ":"
}

// headItems returns ns's /heads page at nsID by resource.
func (e *tenv) headItems(ns, nsID string, bearer ...string) map[string]map[string]any {
	e.t.Helper()
	r := e.get("/ns/"+ns+"/rev/"+nsID+"/heads", bearer...)
	expect(e.t, r, 200)
	out := map[string]map[string]any{}
	for _, x := range r.Obj()["heads"].([]any) {
		m := x.(map[string]any)
		out[m["resource"].(string)] = m
	}
	return out
}

// logCreated is the created time of the entry id of ns/name's log; in a
// sealed namespace, whose log is served sealed, as the engine has it.
func (e *tenv) logCreated(ns, name, id string, bearer ...string) string {
	e.t.Helper()
	r := e.get("/r/"+ns+"/"+name+"/rev/"+id+"/log", bearer...)
	expect(e.t, r, 200)
	entries := r.Arr()
	if len(entries) > 0 {
		if _, sealed := entries[0].(string); sealed {
			lg, err := e.e.ResourceLog(context.Background(), ns, name, id, "", 0, core.Credentials{})
			if err != nil {
				e.t.Fatal(err)
			}
			entries = nil
			for _, m := range lg.Entries {
				entries = append(entries, m)
			}
		}
	}
	var out string
	for _, x := range entries {
		if m := x.(map[string]any); m["id"] == id {
			out, _ = m["created"].(string)
		}
	}
	if out == "" {
		e.t.Fatalf("%s/%s: no entry %s in %s", ns, name, id, r.Body)
	}
	return out
}

// httpDate is a log entry's created time as an HTTP-date.
func httpDate(t *testing.T, created string) string {
	t.Helper()
	tm, err := time.Parse(time.RFC3339Nano, created)
	if err != nil {
		t.Fatal(err)
	}
	return tm.UTC().Format(http.TimeFormat)
}

// checkLiveHead checks a live head entry of a plain namespace against the
// document its target serves, and that document's headers: GET and HEAD
// carry Last-Modified, the target's created time, and Repr-Digest, the
// digest of the bytes GET serves, which is the entry's digest.
func (e *tenv) checkLiveHead(ns string, it map[string]any, bearer ...string) {
	e.t.Helper()
	name, target := it["resource"].(string), it["target"].(string)
	created := e.logCreated(ns, name, target, bearer...)
	path := "/r/" + ns + "/" + name + "/rev/" + target
	for i := 0; i < 2; i++ { // the second from the read cache
		g := e.get(path, bearer...)
		expect(e.t, g, 200)
		if it["kind"] != "head" || it["created"] != created || it["size"] != float64(len(g.Body)) || it["digest"] != reprDigest(g.Body) {
			e.t.Fatalf("%s/%s: entry %v, served %d bytes %s created %s", ns, name, it, len(g.Body), reprDigest(g.Body), created)
		}
		if g.H.Get("Repr-Digest") != reprDigest(g.Body) || g.H.Get("Last-Modified") != httpDate(e.t, created) {
			e.t.Fatalf("%s: Repr-Digest %q Last-Modified %q, want %q %q", path, g.H.Get("Repr-Digest"), g.H.Get("Last-Modified"), reprDigest(g.Body), httpDate(e.t, created))
		}
		q := req{method: "HEAD", path: path}
		if len(bearer) > 0 {
			q.bearer = bearer[0]
		}
		h := e.do(q)
		if h.Code != 200 || len(h.Body) != 0 || h.H.Get("Repr-Digest") != g.H.Get("Repr-Digest") || h.H.Get("Last-Modified") != g.H.Get("Last-Modified") {
			e.t.Fatalf("HEAD %s: %d %v", path, h.Code, h.H)
		}
	}
}

// A plain namespace's revisions carry Last-Modified and Repr-Digest, and
// its /heads entries created, and for live heads size and digest, after
// every kind of write: a create, an append, a tombstone (created only), a
// restore and a batch. A private namespace's too, and a branch's: its own
// heads and those it reads through, which are its base's.
func TestHeadMetaPlain(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.mkNS("n", map[string]any{"read": "public"})
	tick := func() { e.clock.Advance(time.Hour + 123*time.Millisecond) }
	a0 := e.create("n", "a", map[string]any{"x": "naïve"})
	tick()
	e.checkLiveHead("n", e.headItems("n", e.nsHead("n"))["a"])
	a1 := e.appendRev("n", "a", a0, ops(op("add", "/y", []any{1.0, "z"})))
	tick()
	e.checkLiveHead("n", e.headItems("n", e.nsHead("n"))["a"])
	tomb := e.del("n", "a", a1)
	tick()
	if it := e.headItems("n", e.nsHead("n"))["a"]; it["kind"] != "tombstone" || it["target"] != tomb || it["created"] != e.logCreated("n", "a", tomb) || it["size"] != nil || it["digest"] != nil {
		t.Fatalf("tombstone %v", it)
	}
	e.appendRev("n", "a", tomb, ops(op("add", "/restored", true)))
	tick()
	e.checkLiveHead("n", e.headItems("n", e.nsHead("n"))["a"])
	r := e.do(req{method: "POST", path: "/ns/n/batch", author: "alice", body: map[string]any{"items": []any{
		map[string]any{"resource": "b", "ifNoneMatch": "*", "steps": []any{addRoot(map[string]any{}), ops(op("add", "/k", 1.5))}},
		map[string]any{"resource": "c", "ifNoneMatch": "*", "steps": []any{addRoot("c")}},
	}}})
	expect(t, r, 201)
	tick()
	// A document over the head snapshot size (D.4), served by folding,
	// with numbers JCS reformats.
	big := e.create("n", "big", map[string]any{"s": strings.Repeat("x", 40<<10), "f": 1.50, "e": 1e21, "z": 0.000001})
	for i := 0; i < 3; i++ {
		big = e.appendRev("n", "big", big, ops(op("add", "/n"+string(rune('0'+i)), float64(i)+0.25)))
	}
	hs := e.headItems("n", e.nsHead("n"))
	for _, name := range []string{"a", "b", "c", "big"} {
		e.checkLiveHead("n", hs[name])
	}

	// A branch: read-through entries are the base's, its own its own.
	expect(t, e.branch("n", map[string]any{"name": "br", "at": e.nsHead("n"), "patches": []any{}}, "alice"), 201)
	e.appendRev("br", "b", hs["b"]["target"].(string), ops(op("add", "/m", "own")))
	bh := e.headItems("br", e.nsHead("br"))
	for _, name := range []string{"a", "b", "c"} {
		e.checkLiveHead("br", bh[name])
	}
	if bh["a"]["digest"] != hs["a"]["digest"] || bh["a"]["created"] != hs["a"]["created"] || bh["b"]["digest"] == hs["b"]["digest"] {
		t.Fatalf("branch %v, base %v", bh, hs)
	}

	// A private namespace's, read with a grant.
	p := newAuthEnv(t)
	k := newKey("k")
	p.mkNS("priv", map[string]any{"keys": []any{k.entry("*")}})
	g := p.grant(k, "user:a", []string{"priv"}, allVerbs)
	p.create("priv", "d", map[string]any{"secret": "no"}, g)
	p.checkLiveHead("priv", p.headItems("priv", p.nsHead("priv", g), g)["d"], g)
}

// noRevMeta checks that a 200 of path carries neither Last-Modified nor
// Repr-Digest, and that If-Modified-Since, however late, is ignored: no
// 304 lets a reader probe for the created time the level hides (§7.1,
// §E.2.2). GET and HEAD, twice each (the second from the read cache).
func (e *tenv) noRevMeta(path string, bearer ...string) {
	e.t.Helper()
	late := e.clock.Now().Add(24 * time.Hour).UTC().Format(http.TimeFormat)
	for i := 0; i < 2; i++ {
		for _, method := range []string{"GET", "HEAD"} {
			for _, hdr := range []map[string]string{nil, {"If-Modified-Since": late}} {
				q := req{method: method, path: path, hdr: hdr}
				if len(bearer) > 0 {
					q.bearer = bearer[0]
				}
				r := e.do(q)
				if r.Code != 200 || r.H.Get("Last-Modified") != "" || r.H.Get("Repr-Digest") != "" {
					e.t.Fatalf("%s %s %v: %d %v", method, path, hdr, r.Code, r.H)
				}
			}
		}
	}
}

// noHeadMeta checks that a /heads entry lists none of created, size and
// digest (§7.4: absent at E2 and E3).
func noHeadMeta(t *testing.T, it map[string]any) {
	t.Helper()
	for _, k := range []string{"created", "size", "digest"} {
		if _, ok := it[k]; ok {
			t.Fatalf("%s listed: %v", k, it)
		}
	}
}

// Sealed (E2) and e2e (E3) namespaces: revisions carry neither
// Last-Modified nor Repr-Digest, and If-Modified-Since gets no 304, but
// If-None-Match still does; /heads entries list none of created, size and
// digest (§7.1, §7.4, §E.2.2). The e2e keyring, plain as it is, carries
// none either, nor does a prune's sealed snapshot. Sealed revisions store
// no size or digest, and e2e content has no document here (§E.3).
func TestHeadMetaEncrypted(t *testing.T) {
	t.Parallel()
	path := headMetaDB(t)
	e := newSealedEnv(t, withPath(path))
	e.mkNS("s", sealedDoc(map[string]any{"read": "public"}))
	s0 := e.wr("s", "x", "", withNonce(addRoot(map[string]any{"v": 1.0})))
	at0 := e.nsHead("s")
	e.clock.Advance(time.Hour)
	s1 := e.wr("s", "x", s0, withNonce(ops(op("add", "/w", 2.0))))
	for _, id := range []string{s0, s1} {
		r := e.get("/r/s/x/rev/" + id)
		expect(t, r, 200)
		if !isJOSE(r) {
			t.Fatalf("sealed revision %s: %v", id, r.H)
		}
		e.noRevMeta("/r/s/x/rev/" + id)
		if c := e.do(req{method: "GET", path: "/r/s/x/rev/" + id, hdr: map[string]string{"If-None-Match": quote(id + ".1")}}); c.Code != 304 {
			t.Fatalf("sealed If-None-Match: %d", c.Code)
		}
	}
	for nsID, target := range map[string]string{at0: s0, e.nsHead("s"): s1} {
		it := e.headItems("s", nsID)["x"]
		if it["target"] != target {
			t.Fatalf("sealed heads at %s: %v", nsID, it)
		}
		noHeadMeta(t, it)
	}
	// Nor are they stored: nothing could list them, as a level can't be
	// lowered.
	if n := storedMeta(t, path); n != 0 {
		t.Fatalf("%d sealed revisions store a size or digest", n)
	}

	// A public e2e namespace's keyring, served in the clear and from the
	// transaction-free read cache.
	_, pubPriv, _ := seal.GenerateRecipient()
	kr, err := seal.BuildKeyringV2(pubPriv, "pe", 1, seal.NewKey(), []*ecdh.PublicKey{pubPriv.PublicKey()})
	if err != nil {
		t.Fatal(err)
	}
	e.mkNS("pe", e2eDoc(map[string]any{"read": "public"}))
	kid := e.create("pe", core.KeyringName, kr.Value())
	e.clock.Advance(time.Minute)
	e.noRevMeta("/r/pe/" + core.KeyringName + "/rev/" + kid)
	noHeadMeta(t, e.headItems("pe", e.nsHead("pe"))[core.KeyringName])

	f := newE2E(t, withArchive(t, t.TempDir()))
	k := seal.NewKey()
	readerPub, _ := seal.ParseRecipientJWK(f.readerJWK)
	fkr, err := seal.BuildKeyringV2(f.readerPriv, "e", 1, k, []*ecdh.PublicKey{readerPub})
	if err != nil {
		t.Fatal(err)
	}
	fkid := f.create("e", core.KeyringName, fkr.Value(), f.adminG)
	f.noRevMeta("/r/e/"+core.KeyringName+"/rev/"+fkid, f.readerG)
	ids := []string{etagOf(f.writeRaw("e", "p", "", sealed(t, k, "e#1", "e", "p", "", addRoot(map[string]any{"n": 0.0})), f.writerG))}
	for i := 1; i < 3; i++ {
		ids = append(ids, etagOf(f.writeRaw("e", "p", ids[i-1], sealed(t, k, "e#1", "e", "p", ids[i-1], ops(op("replace", "/n", float64(i)))), f.writerG)))
	}
	hs := f.headItems("e", f.nsHead("e", f.readerG), f.readerG)
	if it := hs["p"]; it["target"] != ids[2] {
		t.Fatalf("e2e heads %v", it)
	}
	noHeadMeta(t, hs["p"])
	noHeadMeta(t, hs[core.KeyringName])
	if n := queryInt(t, f.path, `SELECT COUNT(*) FROM revisions WHERE size IS NOT NULL OR digest IS NOT NULL`); n != 0 {
		t.Fatalf("%d e2e revisions store a size or digest", n)
	}
	// A prune's sealed snapshot is served as the horizon's revision.
	f.clock.Advance(10 * time.Minute)
	snap, err := seal.SealSnapshot(k, "e#1", "e", "p", ids[1], map[string]any{"n": 1.0})
	if err != nil {
		t.Fatal(err)
	}
	expect(t, f.prune("e", "p", map[string]any{"horizon": ids[1], "snapshot": snap}, f.writerG), 200)
	r := f.get("/r/e/p/rev/"+ids[1], f.readerG)
	expect(t, r, 200)
	if r.H.Get("X-E2E") != "snapshot" {
		t.Fatalf("e2e snapshot %v", r.H)
	}
	f.noRevMeta("/r/e/p/rev/"+ids[1], f.readerG)
	if c := f.do(req{method: "GET", path: "/r/e/p/rev/" + ids[1], bearer: f.readerG, hdr: map[string]string{"If-None-Match": quote(ids[1])}}); c.Code != 304 || len(c.Body) != 0 {
		t.Fatalf("e2e snapshot If-None-Match: %d %v", c.Code, c.H)
	}
}

// A namespace raised to sealed lists none of created, size and digest
// from then on, on earlier pages too (the level decides when listing),
// and its revisions carry no Last-Modified or Repr-Digest. The raise
// purges ns:{ns}, which the pages and revisions cached with them carry
// (§9), whether the namespace was public or private; raising to at-rest
// purges nothing, and drops the stored size and digest, which would sit in
// plaintext beside the encrypted content (§E.1 Stored digests, v0.56).
func TestHeadMetaSealedLater(t *testing.T) {
	t.Parallel()
	rec := &recPurger{}
	e := newSealedEnv(t, func(o *core.Options) { o.Purger = rec })
	for _, read := range []string{"public", "grant"} {
		ns := "n-" + read
		e.mkNS(ns, map[string]any{"read": read})
		a := e.create(ns, "a", map[string]any{"a": 1.0})
		at := e.nsHead(ns)
		if it := e.headItems(ns, at)["a"]; it["created"] == nil || it["digest"] == nil || it["size"] == nil {
			t.Fatalf("plain %v", it)
		}
		if r := e.get("/r/" + ns + "/a/rev/" + a); r.H.Get("Last-Modified") == "" || r.H.Get("Repr-Digest") == "" {
			t.Fatalf("plain revision %v", r.H)
		}
		rec.take()
		expect(t, e.patchNS(ns, ops(op("add", "/encryption", map[string]any{"level": "at-rest"})), ""), 201)
		if calls := rec.take(); purged(calls, "ns:"+ns) {
			t.Fatalf("%s: a raise to at-rest purged %v", ns, calls)
		}
		if it := e.headItems(ns, at)["a"]; it["created"] == nil || it["digest"] != nil || it["size"] != nil {
			t.Fatalf("at-rest %v", it)
		}
		expect(t, e.patchNS(ns, ops(op("replace", "/encryption", map[string]any{"level": "sealed"})), ""), 201)
		if calls := rec.take(); !purged(calls, "ns:"+ns) {
			t.Fatalf("%s: the raise to sealed purges %v", ns, calls)
		}
		for _, nsID := range []string{at, e.nsHead(ns)} {
			noHeadMeta(t, e.headItems(ns, nsID)["a"])
		}
		e.noRevMeta("/r/" + ns + "/a/rev/" + a)
		// Later config writes don't purge again.
		expect(t, e.patchNS(ns, ops(op("add", "/maxLag", "PT1H")), ""), 201)
		if calls := rec.take(); purged(calls, "ns:"+ns) {
			t.Fatalf("%s: a sealed config write purged %v", ns, calls)
		}
	}
	// The raise purges when a batch's config makes it, too.
	e.mkNS("b", map[string]any{"read": "public"})
	rec.take()
	expect(t, e.do(req{method: "POST", path: "/ns/b/batch", author: "admin", body: map[string]any{
		"config": map[string]any{"ifMatch": e.configID("b"), "patches": ops(op("add", "/encryption", map[string]any{"level": "sealed"}))},
		"items":  []any{map[string]any{"resource": "x", "ifNoneMatch": "*", "steps": []any{withNonce(addRoot(map[string]any{}))}}},
	}}), 201)
	if calls := rec.take(); !purged(calls, "ns:b") {
		t.Fatalf("a raise to sealed in a batch: purges %v", calls)
	}
}

// headMetaDB is a database for a test that inspects what revisions store
// (storedMeta): a SQLite file, or a Postgres database.
func headMetaDB(t *testing.T) string {
	t.Helper()
	if pgtest.Enabled() {
		return pgtest.NewDB(t)
	}
	return filepath.Join(t.TempDir(), "meta.db")
}

// storedMeta counts the revisions of the database at path that store a
// size or digest (headMeta).
func storedMeta(t *testing.T, path string) int {
	t.Helper()
	driver, dsn := "sqlite", sqlitedsn.DSN(path, "_pragma=busy_timeout(10000)")
	if strings.HasPrefix(path, "postgres") {
		driver, dsn = "pgx", path
	}
	db, err := sql.Open(driver, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM revisions WHERE size IS NOT NULL OR digest IS NOT NULL`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// A revision's 200 is a 304 for If-Modified-Since no earlier than its
// Last-Modified, the created time to the second (§7.1, RFC 9110 §13.1.3):
// it never changes. If-None-Match decides when sent (§13.2.2), an
// unparseable date is ignored, and a 410 never is a 304. Last-Modified is
// never later than now (§8.8.2.1): an instance whose clock is behind the
// writer's sends its own time, and so for a remote base's created times
// (§G.3), which nothing checks. A sealed namespace sends no Last-Modified,
// so If-Modified-Since never makes a 304 there (TestHeadMetaEncrypted).
func TestRevIfModifiedSince(t *testing.T) {
	t.Parallel()
	e := newSealedEnv(t)
	e.mkNS("n", map[string]any{"read": "public"})
	e.mkNS("p", map[string]any{"read": "public", "encryption": map[string]any{"level": "at-rest"}})
	e.mkNS("s", sealedDoc(map[string]any{"read": "public"}))
	e.clock.Advance(1500 * time.Millisecond)
	a := e.create("n", "a", map[string]any{"x": 1.0})
	ar := e.create("p", "a", map[string]any{"x": 1.0})
	s := e.wr("s", "x", "", withNonce(addRoot(map[string]any{"v": 1.0})))
	e.clock.Advance(time.Hour)
	for _, path := range []string{"/r/n/a/rev/" + a, "/r/p/a/rev/" + ar} {
		id := path[strings.LastIndex(path, "/")+1:]
		lm := e.get(path).H.Get("Last-Modified")
		at, err := http.ParseTime(lm)
		if err != nil || at.Nanosecond() != 0 || !at.Equal(t0.Add(time.Second)) {
			t.Fatalf("%s: Last-Modified %q", path, lm)
		}
		for _, method := range []string{"GET", "HEAD"} {
			for _, ims := range []string{lm, at.Add(time.Hour).Format(http.TimeFormat)} {
				r := e.do(req{method: method, path: path, hdr: map[string]string{"If-Modified-Since": ims}})
				if r.Code != 304 || len(r.Body) != 0 || r.H.Get("ETag") != quote(id) || r.H.Get("Cache-Control") != ccImmutable ||
					r.H.Get("Last-Modified") != "" || r.H.Get("Repr-Digest") != "" {
					t.Fatalf("%s %s since %s: %d %v", method, path, ims, r.Code, r.H)
				}
			}
			for _, h := range []map[string]string{
				{"If-Modified-Since": at.Add(-time.Second).Format(http.TimeFormat)},
				{"If-Modified-Since": "yesterday"},
				{"If-Modified-Since": lm, "If-None-Match": `"other"`},
			} {
				if r := e.do(req{method: method, path: path, hdr: h}); r.Code != 200 || r.H.Get("Last-Modified") != lm {
					t.Fatalf("%s %s %v: %d %v", method, path, h, r.Code, r.H)
				}
			}
		}
	}
	e.noRevMeta("/r/s/x/rev/" + s)
	tomb := e.del("n", "a", a)
	if r := e.do(req{method: "GET", path: "/r/n/a/rev/" + tomb, hdr: map[string]string{"If-Modified-Since": e.clock.Now().Add(time.Hour).Format(http.TimeFormat)}}); r.Code != 410 {
		t.Fatalf("tombstone: %d", r.Code)
	}

	// The reading instance's clock is behind the writer's.
	e.clock.Advance(-48 * time.Hour)
	now := e.clock.Now().UTC().Format(http.TimeFormat)
	for i := 0; i < 2; i++ { // the second from the read cache
		if r := e.get("/r/n/a/rev/" + a); r.H.Get("Last-Modified") != now {
			t.Fatalf("Last-Modified %q at %s", r.H.Get("Last-Modified"), now)
		}
	}
	if r := e.do(req{method: "GET", path: "/r/n/a/rev/" + a, hdr: map[string]string{"If-Modified-Since": now}}); r.Code != 304 {
		t.Fatalf("since now: %d", r.Code)
	}
}

// A resource purge purges the /heads pages of its namespace and of every
// branch it reaches (heads:{ns}, which they carry with ns:{ns}): cached
// copies would keep listing the purged head's size and digest, which the
// origin no longer lists. Other writes don't purge them.
func TestHeadMetaPurgeTags(t *testing.T) {
	t.Parallel()
	rec := &recPurger{}
	e := newEnv(t, func(o *core.Options) { o.Purger = rec })
	e.mkNS("n", map[string]any{"read": "public"})
	a := e.create("n", "a", map[string]any{"x": 1.0})
	b := e.create("n", "b", map[string]any{"y": 1.0})
	at := e.nsHead("n")
	if h := e.get("/ns/n/rev/" + at + "/heads"); h.H.Get("Cache-Tag") != "ns:n,heads:n" || h.H.Get("Surrogate-Key") != "ns:n heads:n" {
		t.Fatalf("heads tags %v", h.H)
	}
	if e.headItems("n", at)["a"]["digest"] == nil {
		t.Fatal("no digest")
	}
	expect(t, e.branch("n", map[string]any{"name": "br", "at": at, "patches": []any{}}, "alice"), 201)
	e.appendRev("n", "b", b, ops(op("add", "/z", 2.0)))
	if calls := rec.take(); purged(calls, "heads:n") || purged(calls, "heads:br") {
		t.Fatalf("a write purged %v", calls)
	}
	expect(t, e.purge("n", "a", a, "admin"), 204)
	calls := rec.take()
	for _, tag := range []string{"r:n/a", "heads:n", "r:br/a", "heads:br"} {
		if !purged(calls, tag) {
			t.Errorf("purge: no %s in %v", tag, calls)
		}
	}
	if it := e.headItems("n", at)["a"]; it["kind"] != "purge" || it["digest"] != nil {
		t.Fatalf("purged %v", it)
	}
}

// A database from before the extension (the columns dropped) is migrated:
// heads written before list created but no size or digest until the next
// write, and the pages that list them don't change; reads of their
// revisions carry Last-Modified and Repr-Digest all the same, computed
// from what they serve.
func TestHeadMetaMigration(t *testing.T) {
	t.Parallel()
	path, driver := filepath.Join(t.TempDir(), "old.db"), "sqlite"
	if pgtest.Enabled() {
		path, driver = pgtest.FreshDB(t), "pgx"
	}
	e := newEnv(t, withPath(path))
	e.mkNS("main", map[string]any{"read": "public"})
	a := e.create("main", "a", map[string]any{"a": 1.0})
	e.create("main", "b", map[string]any{"b": 1.0})
	e.close()

	dsn := path
	if driver == "sqlite" {
		dsn = sqlitedsn.DSN(path, "")
	}
	db, err := sql.Open(driver, dsn)
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{`ALTER TABLE revisions DROP COLUMN size`, `ALTER TABLE revisions DROP COLUMN digest`} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(q, err)
		}
	}
	db.Close()

	e2 := newEnv(t, withPath(path))
	old := e2.nsHead("main")
	page := e2.get("/ns/main/rev/" + old + "/heads").Body
	hs := e2.headItems("main", old)
	for _, name := range []string{"a", "b"} {
		it := hs[name]
		if it["created"] != e2.logCreated("main", name, it["target"].(string)) || it["size"] != nil || it["digest"] != nil {
			t.Fatalf("%s from before: %v", name, it)
		}
	}
	g := e2.get("/r/main/a/rev/" + a)
	if g.H.Get("Repr-Digest") != reprDigest(g.Body) || g.H.Get("Last-Modified") == "" {
		t.Fatalf("revision from before: %v", g.H)
	}
	e2.appendRev("main", "a", a, ops(op("add", "/x", 2.0)))
	hs = e2.headItems("main", e2.nsHead("main"))
	e2.checkLiveHead("main", hs["a"])
	if hs["b"]["size"] != nil {
		t.Fatalf("b, not written since: %v", hs["b"])
	}
	if now := e2.get("/ns/main/rev/" + old + "/heads").Body; string(now) != string(page) {
		t.Fatalf("page changed:\n%s\n%s", page, now)
	}
}

// A remote branch lists the base's heads as the base does, sizes and
// digests included, from the chains it mirrors; so does a namespace its
// schemas are mirrored into (§G.3, insertChain).
func TestHeadMetaRemote(t *testing.T) {
	t.Parallel()
	a, b, _ := pair(t, nil, nil)
	f := populateA(t, a)
	expect(t, b.mkRemote("rel", remoteGenesis("main", f.at, nil)), 201)
	ha, hb := a.headItems("main", f.at), b.headItems("rel", b.nsHead("rel"))
	for _, name := range []string{"derby", "old", "e", "f"} {
		if hb[name]["digest"] == nil || hb[name]["digest"] != ha[name]["digest"] || hb[name]["size"] != ha[name]["size"] || hb[name]["created"] != ha[name]["created"] {
			t.Fatalf("%s: B %v, A %v", name, hb[name], ha[name])
		}
		b.checkLiveHead("rel", hb[name])
	}
	if it := hb["b"]; it["kind"] != "tombstone" || it["created"] != ha["b"]["created"] || it["size"] != nil {
		t.Fatalf("tombstone %v", it)
	}
	if it := hb["c"]; it["kind"] != "purge" || it["created"] != nil || it["size"] != nil {
		t.Fatalf("purged %v", it)
	}
	s := b.headItems("schemas", b.nsHead("schemas"))["match"]
	if s["target"] != f.s2 || s["digest"] != a.headItems("schemas", a.nsHead("schemas"))["match"]["digest"] {
		t.Fatalf("mirrored schema %v", s)
	}
	b.checkLiveHead("schemas", s)
}
