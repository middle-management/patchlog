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

// §B.11.9 Where (v0.78: "Filtered reads cover no branch"; TDA 63): a
// partial reader of matches-r7 in fan-club, through another key, gets 403
// at the branch's unfiltered /heads, with no redirect, and at its filtered
// /heads and log, 401 there without credentials, and its exchange no
// /ns/matches-r7/g/{gs}; derby is never listed. Before v0.78 the branch
// was covered until matches stopped trusting cat-season through
// catalog-01.
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
	head := w.nsHead("matches-r7", w.admin)
	r := w.get("/ns/matches-r7/rev/"+head+"/heads", reader)
	expect(t, r, 403)
	if r.H.Get("Location") != "" {
		t.Fatalf("a redirect to %q", r.H.Get("Location"))
	}
	gs, at := w.filtered(w.li())
	base := "/ns/matches-r7/g/" + gs
	for _, path := range []string{base + "/at/" + at + "/heads", base + "/heads", base + "/at/" + at + "/log?since=" + head, base + "/log?since=" + head} {
		r := w.get(path, reader)
		if r.Code != http.StatusForbidden || strings.Contains(string(r.Body), "derby") {
			t.Errorf("%s: %d %s, want 403", path, r.Code, r.Body)
		}
		if r := w.get(path, ""); r.Code != http.StatusUnauthorized {
			t.Errorf("%s without credentials: %d, want 401", path, r.Code)
		}
	}
	r = w.do(req{method: "POST", path: "/edge-grants", bearer: reader})
	expect(t, r, 403)
	if r.H.Get("Set-Cookie") != "" {
		t.Fatalf("the exchange set %q", r.H.Get("Set-Cookie"))
	}
}
