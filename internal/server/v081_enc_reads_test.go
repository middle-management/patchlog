package server

import (
	"testing"

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
