package server

import (
	"encoding/base64"
	"strconv"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/core"
	"github.com/middle-management/patchlog/internal/seal"
)

// xrev2-leaks, target 4: a compressed kver-0 row whose kid names another
// namespace (whose epoch key exists) is 500, never its bytes and never
// resealed under the other namespace's key; one whose header doesn't parse
// as a JWE header but whose kid reads is resealed under this resource's
// K_r and pl, never served as stored.
func TestV081XLZipKidOtherNS(t *testing.T) {
	t.Parallel()
	var path string
	e := newSealedEnv(t, withFileDB(t), func(o *core.Options) { path = o.Path })
	e.mkNS("s", sealedDoc(map[string]any{"read": "public"}))
	e.mkNS("t", sealedDoc(map[string]any{"read": "public"}))
	g1 := e.wr("s", "derby", "", withNonce(addRoot(map[string]any{"v": 1.0})))
	e.wr("t", "derby", "", withNonce(addRoot(map[string]any{"v": 7.0})))
	keys, kr := e.keysOf("t", nil, "")
	expect(t, kr, 200)
	kt := resKey(t, keys["t#1"], "t", "derby")
	skeys, kr := e.keysOf("s", nil, "")
	expect(t, kr, 200)
	ks := resKey(t, skeys["s#1"], "s", "derby")
	expect(t, e.get("/r/s/derby/rev/"+g1), 200)
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
	other := zipJWE(t, kt, "t#1", seal.ResourcePL("t", "derby", g1, seal.KindDoc), []byte(`{"v":1,"secret":"x9q"}`))
	if _, err := db.Exec(q(`UPDATE sealed SET jwe = ?, kver = 0 WHERE kind = 'doc' AND key = ?`), other, "derby/"+g1); err != nil {
		t.Fatal(err)
	}
	e.e.FlushCaches()
	g := e.get("/r/s/derby/rev/" + g1)
	t.Logf("kid of another namespace: %d %.120s", g.Code, g.Body)
	if g.Code != 500 || strings.Contains(string(g.Body), other) {
		t.Errorf("a compressed row whose kid names another namespace: %d %.200s", g.Code, g.Body)
	}

	// A header with "zip":"DEF" that seal.ParseHeader refuses (an unknown
	// member), kid this namespace's: resealed, the stored bytes never served.
	hdr := `{"alg":"none","kid":"s#1"}`
	bad := base64.RawURLEncoding.EncodeToString([]byte(hdr)) + "..AAAAAAAAAAAAAAAA.AA.AAAAAAAAAAAAAAAAAAAAAA"
	if _, err := seal.ParseHeader(bad); err == nil {
		t.Fatal("header parses: the arm is not exercised")
	}
	if _, err := db.Exec(q(`UPDATE sealed SET jwe = ?, kver = 0 WHERE kind = 'doc' AND key = ?`), bad, "derby/"+g1); err != nil {
		t.Fatal(err)
	}
	e.e.FlushCaches()
	g = e.get("/r/s/derby/rev/" + g1)
	t.Logf("unparsable header: %d %.120s", g.Code, g.Body)
	if g.Code == 200 {
		if string(g.Body) == bad {
			t.Fatalf("served the stored bytes")
		}
		pt := open(t, string(g.Body), ks, "s#1", seal.ResourcePL("s", "derby", g1, seal.KindDoc))
		t.Logf("resealed: %s", pt)
	} else if strings.Contains(string(g.Body), bad) {
		t.Fatalf("served the stored bytes in an error")
	}
}
