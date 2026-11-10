package server

import (
	"fmt"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/core"

	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/seal"
)

// ACCESS-9 (v0.78; §B.11.9 Answers, CONFORMANCE TDA 68): filtered reads
// cover no branch, so a partial reader's /branches is 403, whatever
// branches its grant names; an unrestricted reader's is unchanged.
func TestV081BranchesPartial403(t *testing.T) {
	t.Parallel()
	w := newV75s(t, v75sOpts{})
	w.seed([]string{"derby"}, nil, []string{"derby"})
	expect(t, w.do(req{method: "POST", path: "/ns/matches/branches", ifNoneMatch: "*", bearer: w.admin,
		body: map[string]any{"name": "matches-r7", "at": w.nsHead("matches", w.admin), "patches": []any{}}}), 201)
	expect(t, w.get("/ns/matches/branches", w.li()), 403)
	r := w.get("/ns/matches/branches", w.admin)
	expect(t, r, 200)
	if len(r.Arr()) != 1 {
		t.Fatalf("admin %s", r.Body)
	}
}

// BYTES-1 (§7.1, §E.2.2, HTTP-20): a genesis's parent is "", served in
// clear log pages and in the sealed entry's plaintext alike.
func TestV081GenesisParentEmpty(t *testing.T) {
	t.Parallel()
	e := newSealedEnv(t)
	e.mkNS("p", map[string]any{"read": "public"})
	g := e.create("p", "derby", map[string]any{"v": 1.0})
	lg := e.get("/r/p/derby/rev/" + g + "/log")
	expect(t, lg, 200)
	m := lg.Arr()[0].(map[string]any)
	if p, ok := m["parent"]; !ok || p != "" {
		t.Fatalf("clear genesis entry %s", lg.Body)
	}
	e.mkNS("s", sealedDoc(map[string]any{"read": "public"}))
	sg := e.wr("s", "derby", "", withNonce(addRoot(map[string]any{"v": 1.0})))
	keys, kr := e.keysOf("s", nil, "")
	expect(t, kr, 200)
	sl := e.get("/r/s/derby/rev/" + sg + "/log")
	expect(t, sl, 200)
	pt := open(t, sl.Arr()[0].(string), resKey(t, keys["s#1"], "s", "derby"), "s#1", seal.ResourcePL("s", "derby", sg, seal.KindRev))
	if v, ok := jsonv.MustParse(pt).(map[string]any)["parent"]; !ok || v != "" {
		t.Fatalf("sealed genesis entry %s", pt)
	}
}

// KEYS-7 (§E.2.1, §E.2.2; stored.md item 7): a namespace document sealed
// before v0.81 was sealed under K_e itself (kver 0). It is sealed again,
// at its first serve, under K_n of the epoch its stored row fixed, epoch 1
// here though the namespace has rotated since, and replaces the row: the
// old bytes are never served again, and the ETag "{id}.{e}" is unchanged.
// A row whose epoch's key is gone answers 500, never its old bytes.
func TestV081LegacySealingResealed(t *testing.T) {
	t.Parallel()
	var path string
	e := newSealedEnv(t, withFileDB(t), func(o *core.Options) { path = o.Path })
	e.mkNS("s", sealedDoc(map[string]any{"read": "public"}))
	e.wr("s", "x", "", withNonce(addRoot(map[string]any{"v": 1.0})))
	h1 := e.nsHead("s")
	keys, kr := e.keysOf("s", nil, "")
	expect(t, kr, 200)
	ke1 := keys["s#1"]
	plain := e.get("/ns/s/rev/" + h1)
	expect(t, plain, 200)
	doc := open(t, string(plain.Body), nsKey(t, ke1, "s"), "s#1", seal.NamespaceDocPL("s", h1))
	legacy, err := seal.SealUncompressed(ke1, "s#1", seal.NamespaceDocPL("s", h1), doc)
	if err != nil {
		t.Fatal(err)
	}
	db, pg := v0261DB(t, path)
	ph := func(i int) string {
		if pg {
			return fmt.Sprintf("$%d", i)
		}
		return "?"
	}
	if _, err := db.Exec(`UPDATE sealed SET jwe = `+ph(1)+`, kver = 0 WHERE kind = 'config' AND key = `+ph(2), legacy, h1); err != nil {
		t.Fatal(err)
	}
	expect(t, e.patchNS("s", ops(op("add", "/encryption/epoch", 2.0)), ""), 201)
	e.e.FlushCaches()
	r := e.get("/ns/s/rev/" + h1)
	expect(t, r, 200)
	if string(r.Body) == legacy {
		t.Fatal("the K_e sealing is served")
	}
	if r.H.Get("ETag") != quote(h1+".1") {
		t.Fatalf("ETag %q, want %q", r.H.Get("ETag"), quote(h1+".1"))
	}
	if got := open(t, string(r.Body), nsKey(t, ke1, "s"), "s#1", seal.NamespaceDocPL("s", h1)); string(got) != string(doc) {
		t.Fatalf("resealed %s, want %s", got, doc)
	}
	var kver int
	if err := db.QueryRow(`SELECT kver FROM sealed WHERE kind = 'config' AND key = `+ph(1), h1).Scan(&kver); err != nil || kver != 1 {
		t.Fatalf("kver %d %v", kver, err)
	}
	if again := e.get("/ns/s/rev/" + h1); string(again.Body) != string(r.Body) {
		t.Fatal("the resealed bytes change between reads")
	}
	// A row whose epoch's key is gone (here, never existed) is 500,
	// never its old bytes.
	h2 := e.nsHead("s")
	expect(t, e.get("/ns/s/rev/"+h2), 200)
	gone, _ := seal.SealUncompressed(ke1, "s#9", seal.NamespaceDocPL("s", h2), doc)
	if _, err := db.Exec(`UPDATE sealed SET jwe = `+ph(1)+`, kver = 0 WHERE kind = 'config' AND key = `+ph(2), gone, h2); err != nil {
		t.Fatal(err)
	}
	e.e.FlushCaches()
	g := e.get("/ns/s/rev/" + h2)
	if g.Code != 500 || string(g.Body) == gone || !strings.Contains(string(g.Body), "earlier draft") {
		t.Fatalf("a K_e row whose key is gone: %d %s", g.Code, g.Body)
	}
}
