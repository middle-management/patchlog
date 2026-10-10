package core

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	mrand "math/rand"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/klauspost/compress/zstd"
	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/keystore"
	"github.com/middle-management/patchlog/internal/pgtest"
)

// PATCHLOG_TEST_STORE_COMPRESSION (and _MIN) open this package's SQLite
// engines with stored patch sets compressed, as internal/testenv does for
// the packages it serves (which this one can't import).
func init() {
	v := os.Getenv("PATCHLOG_TEST_STORE_COMPRESSION")
	if v == "" {
		return
	}
	min, _ := strconv.Atoi(os.Getenv("PATCHLOG_TEST_STORE_COMPRESS_MIN"))
	testOptions = func(o *Options) {
		if o.StoreCompression == "" && !isPostgresURL(o.Path) {
			o.StoreCompression, o.StoreCompressMin = v, min
		}
	}
}

var compressLorem = strings.Fields("lorem ipsum dolor sit amet consectetur adipiscing elit sed do eiusmod tempor incididunt ut labore et dolore magna aliqua enim ad minim veniam quis nostrud exercitation ullamco laboris nisi aliquip ex ea commodo consequat")

// loremNotes is a document value of about size bytes as JSON: notes of
// lorem text, each with a random hex id, compressing about as the synthetic
// Demo Play bundle does.
func loremNotes(r *mrand.Rand, size int) []any {
	var notes []any
	for have := 0; have < size; {
		var sb strings.Builder
		fmt.Fprintf(&sb, "%08x ", r.Uint32())
		for sb.Len() < 300 {
			sb.WriteString(compressLorem[r.Intn(len(compressLorem))])
			sb.WriteByte(' ')
		}
		notes = append(notes, sb.String())
		have += sb.Len() + 3
	}
	return notes
}

func testCodec(t testing.TB, min int) *storeCodec {
	enc, err := zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.SpeedFastest))
	if err != nil {
		t.Fatal(err)
	}
	c := &storeCodec{enc: enc, min: min, maxDecoded: 64 << 20}
	t.Cleanup(c.close)
	return c
}

// Compressed values round-trip at every size, small frames without a
// content size included; values under the threshold, or that don't shrink
// by an eighth, stay canonical.
func TestPackRoundTrip(t *testing.T) {
	t.Parallel()
	c := testCodec(t, 1)
	r := mrand.New(mrand.NewSource(1))
	for _, n := range []int{1, 64, 255, 256, 1023, 1024, 64 << 10, 4 << 20} {
		canon := jsonv.Canonical(map[string]any{"notes": loremNotes(r, n)})
		if n < 1024 {
			canon = []byte(strings.Repeat(`{"a":"lorem ipsum"},`, n/20+1))
		}
		canon = canon[:min(len(canon), n)] // the codec takes any bytes
		packed := c.pack(canon)
		if n < 32 {
			if packed != nil {
				t.Fatalf("%d bytes: compressed (%d) though it can't shrink by an eighth", n, len(packed))
			}
			continue
		}
		if !isPacked(packed) || isSealed(string(packed)) || len(packed) > len(canon)-len(canon)/8 {
			t.Fatalf("%d bytes: packed %d bytes, %x", n, len(packed), packed[:min(len(packed), 4)])
		}
		got, err := c.unpack(packed)
		if err != nil || !bytes.Equal(got, canon) {
			t.Fatalf("%d bytes: round trip %v", n, err)
		}
		// The encoder records the content size from 256 bytes only.
		if l := packedLen(packed[:min(len(packed), 19)]); (n < 256 && l != -1) || (n >= 256 && l != int64(len(canon))) {
			t.Fatalf("%d bytes: frame content size %d", n, l)
		}
	}
	// Under the threshold, and incompressible.
	big := testCodec(t, 1024)
	if big.pack(bytes.Repeat([]byte("a"), 1023)) != nil || big.pack(bytes.Repeat([]byte("a"), 1024)) == nil {
		t.Fatal("threshold")
	}
	noise := make([]byte, 8<<10)
	rand.Read(noise)
	if c.pack(noise) != nil {
		t.Fatal("random bytes kept compressed")
	}
	// A negative threshold (tests) keeps everything compressed.
	always := testCodec(t, -1)
	for _, b := range [][]byte{noise, []byte("[]")} {
		p := always.pack(b)
		if got, err := always.unpack(p); err != nil || !bytes.Equal(got, b) {
			t.Fatalf("always: %d bytes: %v", len(b), err)
		}
	}
}

// No canonical JSON value starts like a compressed or an encrypted row.
func TestPackedFormsDisjoint(t *testing.T) {
	t.Parallel()
	for _, v := range []any{map[string]any{}, []any{}, "s", 1.5, -2.0, true, false, nil} {
		b := jsonv.Canonical(v)
		if isPacked(b) || isSealed(string(b)) {
			t.Fatalf("%s reads as a stored form", b)
		}
	}
	if isPacked([]byte{rowVersion}) || isSealed(string([]byte{rowZstd})) {
		t.Fatal("compressed and encrypted rows overlap")
	}
}

// A damaged compressed row fails to decompress, and one claiming more than
// the deployment accepts is refused before it allocates it.
func TestUnpackDamaged(t *testing.T) {
	t.Parallel()
	c := testCodec(t, 1)
	canon := bytes.Repeat([]byte(`{"a":"lorem ipsum"},`), 4000)
	packed := c.pack(canon)
	for _, bad := range [][]byte{{rowZstd}, {rowZstd, 1, 2, 3}, packed[:len(packed)/2], flip(packed, len(packed)-6)} {
		if _, err := c.unpack(bad); err == nil {
			t.Fatalf("damaged row %x… decompressed", bad[:min(len(bad), 8)])
		}
	}
	small := &storeCodec{maxDecoded: 16 << 10}
	t.Cleanup(small.close)
	if _, err := small.unpack(packed); err == nil {
		t.Fatalf("a %d-byte value decompressed under a 16 KiB bound", len(canon))
	}
}

// The policy: compression on, and a namespace without encryption.
func TestCompressesPolicy(t *testing.T) {
	t.Parallel()
	on := &Engine{comp: *testCodec(t, 1)}
	off := &Engine{}
	for level := levelNone; level <= levelE2E; level++ {
		if on.compresses(level) != (level == levelNone) || off.compresses(level) {
			t.Fatalf("level %s: on %v, off %v", levelNames[level], on.compresses(level), off.compresses(level))
		}
	}
}

func TestStoreCompressionOptions(t *testing.T) {
	t.Parallel()
	for _, o := range []Options{
		{Path: ":memory:", StoreCompression: "gzip"},
		{Path: "postgres://nobody@127.0.0.1:1/none", StoreCompression: "zstd"},
	} {
		if e, err := Open(o); err == nil {
			e.Close()
			t.Fatalf("%+v opened", o)
		}
	}
	if !pgtest.Enabled() {
		return
	}
	if e, err := Open(Options{Path: pgtest.NewDB(t), StoreCompression: "zstd"}); err == nil || !strings.Contains(err.Error(), "SQLite only") {
		if e != nil {
			e.Close()
		}
		t.Fatalf("Postgres: %v", err)
	}
}

// compressEngine opens an engine on path with compression as given
// ("off" or "zstd" from min bytes).
func compressEngine(t testing.TB, path, mode string, min int, opts ...func(*Options)) *Engine {
	t.Helper()
	lim := DefaultLimits()
	fast := Rate{1e9, 1e9}
	lim.RatePerResource, lim.RatePerPrincipal, lim.RatePerNamespace = fast, fast, fast
	o := Options{Path: path, BlobDir: t.TempDir(), AuthDisabled: true, RetentionInterval: -1, BlobSweepInterval: -1, Remote: RemoteOptions{FollowInterval: -1},
		Limits: lim, Purger: discardPurger{}, StoreCompression: mode, StoreCompressMin: min}
	for _, f := range opts {
		f(&o)
	}
	e, err := Open(o)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close() })
	return e
}

func skipOnPostgres(t testing.TB) {
	if pgtest.Enabled() {
		t.Skip("store compression is SQLite only")
	}
}

// storedForms counts the stored values of namespace ns by form: canonical
// JSON, compressed, encrypted (sealed) and encrypted around a compressed
// value, which must never exist.
type storedForms struct{ canonical, packed, sealed, sealedPacked int }

func formsOf(t testing.TB, e *Engine, ns string) (patches, docs storedForms) {
	t.Helper()
	err := e.read(context.Background(), func(tx *tx) error {
		count := func(f *storedForms, res int64, raw []byte, aad []byte) {
			switch {
			case isSealed(string(raw)):
				plain, err := openRow(tx.dek(res, false), aad, raw)
				tx.must(err)
				if isPacked(plain) {
					f.sealedPacked++
				} else {
					f.sealed++
				}
			case isPacked(raw):
				f.packed++
			default:
				f.canonical++
			}
		}
		rows, err := tx.Query(`SELECT r.res, r.id, r.patches FROM revisions r JOIN resources s ON s.res = r.res JOIN namespaces n ON n.ns = s.ns
			WHERE n.name = ? AND r.patches IS NOT NULL`, ns)
		tx.must(err)
		for rows.Next() {
			var res int64
			var id, raw []byte
			tx.must(rows.Scan(&res, &id, &raw))
			count(&patches, res, raw, revAAD(res, ids.FromBytes(id)))
		}
		rows.Close()
		for _, table := range []string{"heads", "snapshots"} {
			rows, err := tx.Query(`SELECT h.res, h.seq, h.doc FROM `+table+` h JOIN resources s ON s.res = h.res JOIN namespaces n ON n.ns = s.ns WHERE n.name = ?`, ns)
			tx.must(err)
			for rows.Next() {
				var res, seq int64
				var raw []byte
				tx.must(rows.Scan(&res, &seq, &raw))
				count(&docs, res, raw, docAAD(table, res, seq))
			}
			rows.Close()
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return patches, docs
}

// writeChain creates ns/name with a genesis of about 5 KB and appends n
// patch sets of about 2.6 KB, then a few small ones, returning the ids and
// the canonical document at each.
func writeChain(t testing.TB, e *Engine, ns, name string, n int) ([]string, [][]byte) {
	t.Helper()
	ctx := context.Background()
	r := who
	r.NS = ns
	rnd := mrand.New(mrand.NewSource(7))
	cur := map[string]any{"title": "t", "notes": loremNotes(rnd, 5000)}
	res, err := e.WriteResource(ctx, r, Item{Resource: name, IfNoneMatch: true, Steps: []Step{{Patches: []any{map[string]any{"op": "add", "path": "", "value": jsonv.Clone(cur)}}}}})
	if err != nil {
		t.Fatal(err)
	}
	revs, docs := []string{res.Items[0].IDs[0]}, [][]byte{jsonv.Canonical(cur)}
	for i := 1; i <= n+4; i++ {
		key := fmt.Sprint("p", i)
		var v any = loremNotes(rnd, 2600)
		if i > n {
			v = strings.Repeat("ab", 60+i) // small: under 256 bytes compressed or not
		}
		cur[key] = v
		res, err = e.WriteResource(ctx, r, Item{Resource: name, IfMatch: revs[len(revs)-1], Steps: []Step{{Patches: []any{map[string]any{"op": "add", "path": "/" + key, "value": jsonv.Clone(v)}}}}})
		if err != nil {
			t.Fatal(err)
		}
		revs, docs = append(revs, res.Items[0].IDs[0]), append(docs, jsonv.Canonical(cur))
	}
	return revs, docs
}

// readChain reads every revision of ns/name uncached, and its log.
func readChain(t testing.TB, e *Engine, ns, name string, revs []string, docs [][]byte) {
	t.Helper()
	ctx := context.Background()
	for i, id := range revs {
		e.FlushCaches()
		rev, err := e.ResourceRev(ctx, ns, name, id, who.Cred)
		if err != nil || rev.Status != 200 || !bytes.Equal(rev.Doc, docs[i]) {
			t.Fatalf("%s/%s rev %d: %v, status %d, same doc %v", ns, name, i, err, rev.Status, rev != nil && bytes.Equal(rev.Doc, docs[i]))
		}
	}
	lg, err := e.ResourceLog(ctx, ns, name, revs[len(revs)-1], "", 0, who.Cred)
	if err != nil || len(lg.Entries) != len(revs) {
		t.Fatalf("%s/%s log: %v", ns, name, err)
	}
	for i, en := range lg.Entries {
		if en["id"] != revs[i] {
			t.Fatalf("%s/%s log entry %d: %v", ns, name, i, en["id"])
		}
	}
}

// snapshotted lists the ids of ns's revisions that have an intermediate
// snapshot, and for each of its resources the counts since the last one,
// as step 7 kept them and as the fallback counts them from the rows (which
// also counts a whole-document genesis, snapCounts).
func snapshotted(t testing.TB, e *Engine, ns string) (snaps []string, counts [][2]int64) {
	t.Helper()
	err := e.read(context.Background(), func(tx *tx) error {
		rows, err := tx.Query(`SELECT r.id FROM snapshots x JOIN revisions r ON r.seq = x.seq JOIN resources s ON s.res = r.res JOIN namespaces n ON n.ns = s.ns WHERE n.name = ? ORDER BY r.seq`, ns)
		tx.must(err)
		for rows.Next() {
			var id []byte
			tx.must(rows.Scan(&id))
			snaps = append(snaps, ids.FromBytes(id).String())
		}
		rows.Close()
		rows, err = tx.Query(`SELECT s.res, s.snap_revs, s.snap_bytes FROM resources s JOIN namespaces n ON n.ns = s.ns WHERE n.name = ? ORDER BY s.name`, ns)
		tx.must(err)
		var res []int64
		for rows.Next() {
			var r, revs, size int64
			tx.must(rows.Scan(&r, &revs, &size))
			res, counts = append(res, r), append(counts, [2]int64{revs, size})
		}
		rows.Close()
		for _, r := range res {
			revs, size := tx.snapCounts(&resRow{id: r})
			counts = append(counts, [2]int64{revs, size})
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return snaps, counts
}

// Writes into a namespace without encryption store their patch sets
// compressed, and one encrypted at rest stores them encrypted as canonical
// JSON; every read is the same as with compression off, ids, intermediate
// snapshots (at 64 KiB of canonical patch sets, D.4) and their counts
// included.
func TestStoreCompressionRows(t *testing.T) {
	t.Parallel()
	skipOnPostgres(t)
	ks, err := keystore.New(keystore.Generate())
	if err != nil {
		t.Fatal(err)
	}
	withKS := func(o *Options) { o.KeyStore = ks }
	on := compressEngine(t, ":memory:", "zstd", 64, withKS)
	off := compressEngine(t, ":memory:", "off", 0, withKS)
	type result struct {
		revs   []string
		snaps  []string
		counts [][2]int64
	}
	results := map[string][2]result{}
	for i, e := range []*Engine{off, on} {
		for _, ns := range []string{"plain", "enc"} {
			doc := map[string]any{"read": "public"}
			if ns == "enc" {
				doc["encryption"] = map[string]any{"level": "at-rest"}
			}
			mkNS(t, e, ns, doc)
			revs, docs := writeChain(t, e, ns, "d", 30) // 30 × 2.6 KB: an intermediate snapshot
			readChain(t, e, ns, "d", revs, docs)
			snaps, counts := snapshotted(t, e, ns)
			rs := results[ns]
			rs[i] = result{revs, snaps, counts}
			results[ns] = rs
			patches, heads := formsOf(t, e, ns)
			t.Logf("compression %s, %s: patch sets %+v, heads and snapshots %+v", e.opt.StoreCompression, ns, patches, heads)
			switch {
			case patches.sealedPacked+heads.sealedPacked+heads.packed > 0:
				t.Fatalf("%s: compressed rows where there must be none: %+v %+v", ns, patches, heads)
			case ns == "enc" && patches.canonical+patches.packed > 0:
				t.Fatalf("%s: rows not encrypted: %+v", ns, patches)
			case ns == "plain" && e == on && patches.packed < 31:
				t.Fatalf("%s: want compressed patch sets: %+v", ns, patches)
			case e == off && patches.packed > 0:
				t.Fatalf("%s: compressed with compression off: %+v", ns, patches)
			}
		}
	}
	for ns, rs := range results {
		if fmt.Sprintf("%v", rs[0]) != fmt.Sprintf("%v", rs[1]) {
			t.Fatalf("%s: off and on differ:\n%+v\n%+v", ns, rs[0], rs[1])
		}
		if len(rs[1].snaps) == 0 {
			t.Fatalf("%s: no intermediate snapshot", ns)
		}
	}
}

// The count of patch set bytes since the last snapshot, for a resource row
// that doesn't keep it (D.4 fallback), is of decompressed bytes, from the
// frame's content size or, for a small frame without one, decompressing.
func TestStoreCompressionSnapshotCount(t *testing.T) {
	t.Parallel()
	skipOnPostgres(t)
	e := compressEngine(t, ":memory:", "zstd", 1)
	mkNS(t, e, "m", map[string]any{"read": "public"})
	revs, _ := writeChain(t, e, "m", "d", 8)
	var res, keptRevs, keptBytes int64
	var canon, genesis, small int64
	err := e.read(context.Background(), func(tx *tx) error {
		tx.must(tx.QueryRow(`SELECT s.res, s.snap_revs, s.snap_bytes FROM resources s JOIN namespaces n ON n.ns = s.ns WHERE n.name = 'm' AND s.name = 'd'`).Scan(&res, &keptRevs, &keptBytes))
		rows, err := tx.Query(`SELECT seq FROM revisions WHERE res = ? ORDER BY seq`, res)
		tx.must(err)
		var seqs []int64
		for rows.Next() {
			var s int64
			tx.must(rows.Scan(&s))
			seqs = append(seqs, s)
		}
		rows.Close()
		for _, s := range seqs {
			r := tx.rev(s)
			n := int64(len(tx.patchesOf(r)))
			canon += n
			if !r.parentSeq.Valid {
				genesis = n
			}
			if raw := []byte(r.patches.String); isPacked(raw) && packedLen(raw) < 0 {
				small++
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// Step 7 counts from after the whole-document genesis, the fallback
	// from the resource's first revision.
	if keptRevs != int64(len(revs)-1) || keptBytes != canon-genesis || small == 0 {
		t.Fatalf("kept %d revisions, %d bytes; want %d, %d (small frames %d)", keptRevs, keptBytes, len(revs)-1, canon-genesis, small)
	}
	_, err = e.db.Exec(`UPDATE resources SET snap_revs = NULL, snap_bytes = NULL WHERE res = ?`, res)
	if err != nil {
		t.Fatal(err)
	}
	err = e.read(context.Background(), func(tx *tx) error {
		if n, size := tx.snapCounts(&resRow{id: res}); n != int64(len(revs)) || size != canon {
			return fmt.Errorf("counted %d revisions, %d bytes; want %d, %d", n, size, len(revs), canon)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// Compression happens in the check phase, outside the write lock, and
// only there: writes that run their whole gate in the lock (a batch with a
// config change, writeLocked) store canonical JSON.
func TestStoreCompressionOffLock(t *testing.T) {
	t.Parallel()
	skipOnPostgres(t)
	var packs, atLock atomic.Int32
	e := compressEngine(t, ":memory:", "zstd", 64, func(o *Options) { o.BeforeWriteLock = func() { atLock.Store(packs.Load()) } })
	e.comp.onPack = func() {
		if !e.mu.TryLock() {
			t.Error("compressing in the write lock")
			return
		}
		e.mu.Unlock()
		packs.Add(1)
	}
	ctx := context.Background()
	cfg := mkNS(t, e, "m", map[string]any{"read": "public"})
	r := who
	r.NS = "m"
	rnd := mrand.New(mrand.NewSource(3))
	create := func(name string) Item {
		return Item{Resource: name, IfNoneMatch: true, Steps: []Step{{Patches: []any{map[string]any{"op": "add", "path": "", "value": map[string]any{"notes": loremNotes(rnd, 4000)}}}}}}
	}
	if _, err := e.WriteResource(ctx, r, create("a")); err != nil {
		t.Fatal(err)
	}
	if packs.Load() != 1 || atLock.Load() != 1 {
		t.Fatalf("write: %d compressions, %d before the lock", packs.Load(), atLock.Load())
	}
	if _, err := e.Batch(ctx, r, []Item{create("b"), create("c")}, nil, nil, false); err != nil {
		t.Fatal(err)
	}
	if packs.Load() != 2 || atLock.Load() != 2 {
		t.Fatalf("batch: %d compressions, %d before the lock", packs.Load(), atLock.Load())
	}
	if p, _ := formsOf(t, e, "m"); p.packed != 3 || p.canonical != 0 {
		t.Fatalf("checked outside the lock: %+v", p)
	}
	// In the lock: a batch with a config change, and the whole gate.
	cc := &ConfigChange{IfMatch: cfg, Patches: []any{map[string]any{"op": "add", "path": "/limits", "value": map[string]any{"keepPerResource": 50.0}}}}
	if _, err := e.Batch(ctx, r, []Item{create("d")}, cc, nil, false); err != nil {
		t.Fatal(err)
	}
	if _, err := e.writeLocked(ctx, r, []Item{create("e")}, nil, false, false); err != nil {
		t.Fatal(err)
	}
	if p, _ := formsOf(t, e, "m"); packs.Load() != 2 || p.packed != 3 || p.canonical != 2 {
		t.Fatalf("checked in the lock: %d compressions, %+v", packs.Load(), p)
	}
}

// Rows written with compression off, on and off again read the same, the
// database records that it holds compressed rows, and raising the
// namespace to at-rest encrypts them all as canonical JSON.
func TestStoreCompressionMixedRows(t *testing.T) {
	t.Parallel()
	skipOnPostgres(t)
	path := filepath.Join(t.TempDir(), "mixed.db")
	ks, err := keystore.New(keystore.Generate())
	if err != nil {
		t.Fatal(err)
	}
	withKS := func(o *Options) { o.KeyStore = ks }
	ctx := context.Background()
	r := who
	r.NS = "m"
	rnd := mrand.New(mrand.NewSource(5))
	var revs []string
	var docs [][]byte
	cur := map[string]any{}
	write := func(e *Engine, n int) {
		for i := 0; i < n; i++ {
			key := fmt.Sprint("k", len(revs))
			v := loremNotes(rnd, 1500)
			cur[key] = v
			it := Item{Resource: "d", Steps: []Step{{Patches: []any{map[string]any{"op": "add", "path": "/" + key, "value": jsonv.Clone(v)}}}}}
			if len(revs) == 0 {
				it.IfNoneMatch = true
				it.Steps[0].Patches = []any{map[string]any{"op": "add", "path": "", "value": jsonv.Clone(cur)}}
			} else {
				it.IfMatch = revs[len(revs)-1]
			}
			res, err := e.WriteResource(ctx, r, it)
			if err != nil {
				t.Fatal(err)
			}
			revs, docs = append(revs, res.Items[0].IDs[0]), append(docs, jsonv.Canonical(cur))
		}
	}
	marker := func(e *Engine) string {
		var v string
		e.db.QueryRow(`SELECT value FROM meta WHERE key = ?`, metaStoreCompression).Scan(&v)
		return v
	}

	e := compressEngine(t, path, "off", 0, withKS)
	cfg := mkNS(t, e, "m", map[string]any{"read": "public"})
	write(e, 4)
	var hasMeta bool
	if e.db.QueryRow(`SELECT EXISTS (SELECT 1 FROM sqlite_master WHERE name = 'meta')`).Scan(&hasMeta); hasMeta || e.comp.mayHold {
		t.Fatal("compression off changed the database")
	}
	e.Close()
	e = compressEngine(t, path, "zstd", 0, withKS)
	write(e, 4)
	since := marker(e)
	if !strings.HasPrefix(since, "zstd since ") {
		t.Fatalf("marker %q", since)
	}
	e.Close()
	e = compressEngine(t, path, "off", 0, withKS)
	write(e, 4)
	if marker(e) != since || !e.comp.mayHold {
		t.Fatalf("marker %q after reopening off", marker(e))
	}
	if p, _ := formsOf(t, e, "m"); p.packed != 4 || p.canonical != 8 {
		t.Fatalf("mixed rows %+v", p)
	}
	readChain(t, e, "m", "d", revs, docs)

	// Encryption at rest, then reads and a write.
	if _, err := e.WriteConfig(ctx, r, ConfigChange{IfMatch: cfg, Patches: []any{map[string]any{"op": "add", "path": "/encryption", "value": map[string]any{"level": "at-rest"}}}}); err != nil {
		t.Fatal(err)
	}
	if p, d := formsOf(t, e, "m"); p.sealed != 12 || p.packed+p.canonical+p.sealedPacked+d.packed+d.sealedPacked > 0 {
		t.Fatalf("after encryption: %+v %+v", p, d)
	}
	readChain(t, e, "m", "d", revs, docs)
	e.Close()
	e = compressEngine(t, path, "zstd", 0, withKS)
	write(e, 2)
	readChain(t, e, "m", "d", revs, docs)
	if p, _ := formsOf(t, e, "m"); p.sealed != 14 {
		t.Fatalf("encrypted namespace with compression on: %+v", p)
	}
}

// A damaged compressed row answers an error, not a crash.
func TestStoreCompressionDamagedRow(t *testing.T) {
	t.Parallel()
	skipOnPostgres(t)
	e := compressEngine(t, ":memory:", "zstd", 64)
	mkNS(t, e, "m", map[string]any{"read": "public"})
	revs, _ := writeChain(t, e, "m", "d", 0)
	if _, err := e.db.Exec(`UPDATE revisions SET patches = ? WHERE id = ?`, []byte{rowZstd, 0x28, 0xb5, 0x2f, 0xfd, 1, 2, 3}, idBytes(revs[0])); err != nil {
		t.Fatal(err)
	}
	e.FlushCaches()
	if _, err := e.ResourceRev(context.Background(), "m", "d", revs[0], who.Cred); err == nil || !strings.Contains(err.Error(), "does not decompress") {
		t.Fatalf("read of a damaged row: %v", err)
	}
}

func idBytes(s string) []byte {
	id, err := ids.Parse(s)
	if err != nil {
		panic(err)
	}
	return id[:]
}

// BenchmarkReadUncached reads a document's bytes past every in-memory
// cache, with compression off and on: a created document of about 15 and
// 100 KiB (its genesis patch set, compressed when on), an edited one of 15
// KiB (its heads row, never compressed) and an edited one of 100 KiB
// (folded from its genesis and five patch sets).
func BenchmarkReadUncached(b *testing.B) {
	skipOnPostgres(b)
	for _, c := range []struct {
		name    string
		size    int
		appends int
	}{{"created-15K", 15 << 10, 0}, {"created-100K", 100 << 10, 0}, {"edited-15K", 15 << 10, 1}, {"edited-100K", 100 << 10, 5}} {
		for _, mode := range []string{"off", "zstd"} {
			b.Run(c.name+"/"+mode, func(b *testing.B) {
				e := compressEngine(b, filepath.Join(b.TempDir(), "read.db"), mode, 0)
				r := who
				r.NS = "b"
				if _, err := e.WriteConfig(context.Background(), r, ConfigChange{IfNoneMatch: true, Patches: []any{map[string]any{"op": "add", "path": "", "value": map[string]any{"read": "public"}}}}); err != nil {
					b.Fatal(err)
				}
				rnd := mrand.New(mrand.NewSource(1))
				var heads []string
				for i := 0; i < 20; i++ {
					size := c.size - 500*c.appends
					res, err := e.WriteResource(context.Background(), r, Item{Resource: fmt.Sprint("d", i), IfNoneMatch: true,
						Steps: []Step{{Patches: []any{map[string]any{"op": "add", "path": "", "value": map[string]any{"title": "t", "notes": loremNotes(rnd, size)}}}}}})
					if err != nil {
						b.Fatal(err)
					}
					head := res.Items[0].IDs[0]
					for k := 0; k < c.appends; k++ {
						res, err = e.WriteResource(context.Background(), r, Item{Resource: fmt.Sprint("d", i), IfMatch: head,
							Steps: []Step{{Patches: []any{map[string]any{"op": "add", "path": fmt.Sprint("/x", k), "value": loremNotes(rnd, 400)}}}}})
						if err != nil {
							b.Fatal(err)
						}
						head = res.Items[0].IDs[0]
					}
					heads = append(heads, head)
				}
				var seqs []int64
				err := e.read(context.Background(), func(tx *tx) error {
					for _, h := range heads {
						var s int64
						if err := tx.QueryRow(`SELECT seq FROM revisions WHERE id = ?`, idBytes(h)).Scan(&s); err != nil {
							return err
						}
						seqs = append(seqs, s)
					}
					return nil
				})
				if err != nil {
					b.Fatal(err)
				}
				var n int64
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					e.docs.flush()
					err := e.read(context.Background(), func(tx *tx) error {
						d, err := tx.docBytesAt(tx.rev(seqs[i%len(seqs)]))
						n += int64(len(d))
						return err
					})
					if err != nil {
						b.Fatal(err)
					}
				}
				b.SetBytes(n / int64(b.N))
			})
		}
	}
}
