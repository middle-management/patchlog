package server

import (
	"bytes"
	"compress/flate"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/core"
	"github.com/middle-management/patchlog/internal/seal"
)

// zipJWE seals plaintext as versions before v0.65 did by default: raw
// DEFLATE under zip "DEF" (RFC 7516 §4.1.3), which v0.81 readers refuse
// (seal.Open: ErrFormat). It follows RFC 7516 §5.1 by hand, as package
// seal no longer compresses.
func zipJWE(t *testing.T, k []byte, kid string, pl seal.PL, plaintext []byte) string {
	t.Helper()
	plj, err := json.Marshal(pl)
	if err != nil {
		t.Fatal(err)
	}
	header := `{"alg":"dir","enc":"A256GCM","kid":` + quote(kid) + `,"pl":` + string(plj) + `,"zip":"DEF"}`
	var buf bytes.Buffer
	w, _ := flate.NewWriter(&buf, flate.DefaultCompression)
	w.Write(plaintext)
	w.Close()
	enc := base64.RawURLEncoding
	protected := enc.EncodeToString([]byte(header))
	iv := []byte("0123456789ab")
	block, err := aes.NewCipher(k)
	if err != nil {
		t.Fatal(err)
	}
	gcm, _ := cipher.NewGCM(block)
	out := gcm.Seal(nil, iv, buf.Bytes(), []byte(protected))
	ct, tag := out[:len(out)-16], out[len(out)-16:]
	return protected + ".." + enc.EncodeToString(iv) + "." + enc.EncodeToString(ct) + "." + enc.EncodeToString(tag)
}

// E2E-10, KEYS-9 (§E.2.2, §E.2.1; stored.md item 5): a document or log
// entry a sealed namespace stored before v0.65 was compressed (zip
// "DEF"), which no v0.81 reader opens. The origin holds the key, so at
// first serve it seals the plaintext again, uncompressed, under the same
// key, kid and pl, and replaces the row: the compressed bytes are never
// served, the ETag "{id}.{e}" is unchanged, and the sealing is counted
// against the bound. A row whose epoch's key is gone answers 500, never
// its compressed bytes. Run on SQLite and, with PATCHLOG_TEST_PG, on
// Postgres.
func TestV081ZipSealingResealed(t *testing.T) {
	t.Parallel()
	var path string
	e := newSealedEnv(t, withFileDB(t), func(o *core.Options) { path = o.Path })
	e.mkNS("s", sealedDoc(map[string]any{"read": "public"}))
	g1 := e.wr("s", "derby", "", withNonce(addRoot(map[string]any{"v": 1.0})))
	g2 := e.wr("s", "derby", g1, withNonce(ops(op("replace", "/v", 2.0))))
	keys, kr := e.keysOf("s", nil, "")
	expect(t, kr, 200)
	k := resKey(t, keys["s#1"], "s", "derby")
	docPL := seal.ResourcePL("s", "derby", g2, seal.KindDoc)
	entryPL := seal.ResourcePL("s", "derby", g2, seal.KindRev)

	// What v0.81 stores, read once, then put back as v0.26.1 stored it
	// before v0.65: compressed, kver 0.
	d := e.get("/r/s/derby/rev/" + g2)
	expect(t, d, 200)
	doc := open(t, string(d.Body), k, "s#1", docPL)
	lg := e.get("/r/s/derby/rev/" + g2 + "/log")
	expect(t, lg, 200)
	entryAt := func(r *resp) string {
		t.Helper()
		for _, x := range r.Arr() {
			if h, err := seal.ParseHeader(x.(string)); err == nil && h.PL["id"] == g2 {
				return x.(string)
			}
		}
		t.Fatalf("no entry of %s in %s", g2, r.Body)
		return ""
	}
	entry := open(t, entryAt(lg), k, "s#1", entryPL)
	zDoc, zEntry := zipJWE(t, k, "s#1", docPL, doc), zipJWE(t, k, "s#1", entryPL, entry)
	if _, _, err := seal.Open(zDoc, k); err == nil {
		t.Fatal("a v0.81 reader opens the compressed sealing")
	}
	db, pg := v0261DB(t, path)
	q := func(s string) string {
		if !pg {
			return s
		}
		for i := 1; strings.Contains(s, "?"); i++ {
			s = strings.Replace(s, "?", "$"+strconv.Itoa(i), 1)
		}
		return s
	}
	for kind, jwe := range map[string]string{"doc": zDoc, "entry": zEntry} {
		res, err := db.Exec(q(`UPDATE sealed SET jwe = ?, kver = 0 WHERE kind = ? AND key = ?`), jwe, kind, "derby/"+g2)
		if err != nil {
			t.Fatal(err)
		}
		if n, _ := res.RowsAffected(); n != 1 {
			t.Fatalf("%s rows %d", kind, n)
		}
	}
	// A rotation since: the sealing keeps the epoch its row fixed.
	expect(t, e.patchNS("s", ops(op("add", "/encryption/epoch", 2.0)), ""), 201)
	e.e.FlushCaches()
	counted := func() int {
		return v0261Count(t, db, pg, `SELECT sealed FROM seal_counts WHERE epoch = 1 AND name = 'derby' AND ns IN (SELECT ns FROM namespaces WHERE name = 's')`)
	}
	before := counted()

	row := func(kind string) (string, int) {
		t.Helper()
		var jwe string
		var kver int
		if err := db.QueryRow(q(`SELECT jwe, kver FROM sealed WHERE kind = ? AND key = ?`), kind, "derby/"+g2).Scan(&jwe, &kver); err != nil {
			t.Fatal(err)
		}
		return jwe, kver
	}
	resealed := func(what, got, zipped string, pl seal.PL, plain []byte) {
		t.Helper()
		if got == zipped {
			t.Fatalf("%s: the compressed sealing is served", what)
		}
		h, err := seal.ParseHeader(got)
		if err != nil || h.Zip != "" || bytes.Contains(h.Raw, []byte(`"zip"`)) {
			t.Fatalf("%s: header %s, %v", what, h.Raw, err)
		}
		if pt := open(t, got, k, "s#1", pl); !bytes.Equal(pt, plain) {
			t.Fatalf("%s: resealed %s, want %s", what, pt, plain)
		}
		if stored, kver := row(what); stored != got || kver != 1 {
			t.Fatalf("%s: the row holds %.40s… kver %d, not what was served", what, stored, kver)
		}
	}

	r := e.get("/r/s/derby/rev/" + g2)
	expect(t, r, 200)
	if r.H.Get("ETag") != quote(g2+".1") {
		t.Fatalf("ETag %q, want %q", r.H.Get("ETag"), quote(g2+".1"))
	}
	resealed("doc", string(r.Body), zDoc, docPL, doc)
	l := e.get("/r/s/derby/rev/" + g2 + "/log")
	expect(t, l, 200)
	resealed("entry", entryAt(l), zEntry, entryPL, entry)
	if n := counted(); n != before+2 {
		t.Fatalf("sealings counted under K_r of epoch 1: %d, want %d", n, before+2)
	}
	if n := v0261Count(t, db, pg, `SELECT COUNT(*) FROM sealed WHERE key = ?`, "derby/"+g2); n != 2 {
		t.Fatalf("%d rows for %s, want its document's and entry's", n, g2)
	}
	if again := e.get("/r/s/derby/rev/" + g2); string(again.Body) != string(r.Body) || again.H.Get("ETag") != r.H.Get("ETag") {
		t.Fatal("the resealed bytes change between reads")
	}
	if n := counted(); n != before+2 {
		t.Fatalf("a read of the stored sealing counted again: %d", n)
	}

	// A compressed row whose epoch's key is gone (here, never existed)
	// is 500, never its compressed bytes.
	gone := zipJWE(t, k, "s#9", seal.ResourcePL("s", "derby", g1, seal.KindDoc), []byte(`{"v":1}`))
	expect(t, e.get("/r/s/derby/rev/"+g1), 200)
	if _, err := db.Exec(q(`UPDATE sealed SET jwe = ?, kver = 0 WHERE kind = 'doc' AND key = ?`), gone, "derby/"+g1); err != nil {
		t.Fatal(err)
	}
	e.e.FlushCaches()
	g := e.get("/r/s/derby/rev/" + g1)
	if g.Code != 500 || strings.Contains(string(g.Body), gone) || !strings.Contains(string(g.Body), "earlier draft") {
		t.Fatalf("a compressed row whose key is gone: %d %s", g.Code, g.Body)
	}
}
