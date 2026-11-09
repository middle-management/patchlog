package server

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/ids"
)

// V76-01 (v0.76): origin filtered reads over HTTP (§B.11.9): 401 at an
// uncovered namespace's filtered URLs without a grant that verifies there
// or a cookie, and a branch uncovered once its root stops trusting the
// catalog through the key item 1 counted (conformance 105).

// §B.11.9 Purged namespaces ("403, or 401 as §B.11.5 says"), §B.11.5: a
// public namespace is never covered; its filtered URLs are 401 with no
// credentials or a grant that doesn't verify there, 403 with one that
// does.
func TestV076FilteredUncovered401(t *testing.T) {
	t.Parallel()
	w := newV75s(t, v75sOpts{})
	w.mkNS("pub", map[string]any{"read": "public", "keys": []any{w.k.entry("*")}})
	gs := ids.Of([]byte("any subject set")).String()
	at := w.nsHead("pub", w.admin)
	inPub := w.grant(w.k, "user:r", []string{"pub"}, []string{"read"})
	other := w.grant(w.k, "user:r", []string{"matches"}, []string{"read"})
	for _, path := range []string{"/ns/pub/g/" + gs + "/at/" + at + "/heads", "/ns/pub/g/" + gs + "/heads",
		"/ns/pub/g/" + gs + "/at/" + at + "/log?since=" + at, "/ns/pub/g/" + gs + "/log?since=" + at} {
		for name, c := range map[string]struct {
			bearer string
			want   int
		}{
			"no credentials":                {"", 401},
			"a grant for another namespace": {other, 401},
			"a grant that verifies in pub":  {inPub, 403},
		} {
			r := w.get(path, c.bearer)
			if r.Code != c.want {
				t.Errorf("%s, %s: %d, want %d: %s", path, name, r.Code, c.want, r.Body)
				continue
			}
			if c.want == 401 {
				expectCode(t, r, 401, "unauthenticated")
			}
		}
	}
}

// §B.11.9 Branches, Where, §C.4 (conformance 105): after matches-r7 is
// cut, matches adds catalog-02 (roles scope without reader) and removes
// catalog-01: a partial reader of the branch in fan-club, through another
// key, gets 403 at its filtered /heads and log, and its exchange no
// /ns/matches-r7/g/{gs}; derby is never listed through catalog-01's
// reader.
func TestV076FilteredBranchUncovered(t *testing.T) {
	t.Parallel()
	fan := newKey("fan")
	w := newV75s(t, v75sOpts{matches: func(doc map[string]any) {
		doc["keys"] = append(doc["keys"].([]any), map[string]any{"kid": "fan", "alg": "ed25519", "pub": fan.pub, "can": []any{"read"},
			"rules": []any{map[string]any{"op": "test", "path": "/resource", "schema": map[string]any{"type": "string"}}}})
	}})
	w.seed([]string{"derby"}, nil, []string{"derby"})
	w.put("cat-season", "root", map[string]any{"parents": []any{}, "$access": map[string]any{"group:editors": []any{"reader"},
		"user:li": []any{"reader"}, "group:fan-club": []any{"reader"}}})
	expect(t, w.do(req{method: "POST", path: "/ns/matches/branches", ifNoneMatch: "*", bearer: w.admin,
		body: map[string]any{"name": "matches-r7", "at": w.nsHead("matches", w.admin), "patches": []any{}}}), 201)
	reader := w.grant(fan, "user:fan", []string{"matches-r7"}, []string{"read"}, map[string]any{"groups": []any{"fan-club"},
		"exp": w.clock.Now().Add(10 * time.Minute).Format(time.RFC3339)})
	r := w.get("/ns/matches-r7/rev/"+w.nsHead("matches-r7", w.admin)+"/heads", reader)
	expect(t, r, 302)
	parts := strings.Split(strings.SplitN(r.H.Get("Location"), "?", 2)[0], "/")
	if len(parts) != 8 || parts[3] != "g" {
		t.Fatalf("Location %q", r.H.Get("Location"))
	}
	gs, at := parts[4], parts[6]
	base := "/ns/matches-r7/g/" + gs
	r = w.get(base+"/at/"+at+"/heads", reader)
	expect(t, r, 200)
	if names := headNames(t, r); len(names) != 1 || names[0] != "derby" {
		t.Fatalf("before: %v", names)
	}
	exchangeG := func() bool {
		t.Helper()
		r := w.do(req{method: "POST", path: "/edge-grants", bearer: reader})
		if r.Code != 200 {
			return false
		}
		for p := range edgeCookies(t, r) {
			if strings.HasPrefix(p, "/ns/matches-r7/g/") {
				return true
			}
		}
		return false
	}
	if !exchangeG() {
		t.Fatal("no g prefix before")
	}
	cat2 := newKey("catalog-02")
	expect(t, w.patchNS("matches", ops(
		op("add", "/keys/-", map[string]any{"kid": "catalog-02", "alg": "ed25519", "pub": cat2.pub, "can": []any{"read"},
			"requireAt": "cat-season", "roles": map[string]any{"allow": []any{"editor"}}}),
		op("remove", "/keys/1")), w.admin), 201)
	for _, path := range []string{base + "/at/" + at + "/heads", base + "/heads", base + "/at/" + at + "/log?since=" + at, base + "/log?since=" + at} {
		r := w.get(path, reader)
		if r.Code != http.StatusForbidden || strings.Contains(string(r.Body), "derby") {
			t.Errorf("%s: %d %s, want 403", path, r.Code, r.Body)
		}
	}
	if exchangeG() {
		t.Fatal("the exchange still gives /ns/matches-r7/g/{gs}")
	}
}
