package index

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/grant"
)

// V77-02 (v0.77): unit tests of the index's own predicates and mappings.

// TestV077LacksKey408 (FSVC-11 / ENC-3; §A.4: "a 4xx other than 408 and
// 429" lacks keys; §A.1: "a schema or key fetch that fails transiently
// (transport error, 5xx, 408, 429) is retried"): a /keys 408 is for now,
// never lacking the key, and a schema revision answering 408 isn't final.
func TestV077LacksKey408(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	for _, st := range []int{408, 429, 500, 503} {
		err := fmt.Errorf("%w: %w", client.ErrKeyFetch, &client.APIError{Status: st, Path: "/ns/x/keys"})
		if lacksKey(ctx, err) {
			t.Errorf("lacksKey of a /keys %d: true, want false (transient)", st)
		}
		if unavailable(&client.APIError{Status: st, Path: "/r/schemas/s/rev/x"}) {
			t.Errorf("a schema %d is final, want retried", st)
		}
	}
	for _, st := range []int{400, 401, 403, 404, 410} {
		err := fmt.Errorf("%w: %w", client.ErrKeyFetch, &client.APIError{Status: st, Path: "/ns/x/keys"})
		if !lacksKey(ctx, err) {
			t.Errorf("lacksKey of a /keys %d: false, want true", st)
		}
		if !unavailable(&client.APIError{Status: st, Path: "/r/schemas/s/rev/x"}) {
			t.Errorf("a schema %d isn't final", st)
		}
	}
}

// fakeChain is grantcheck's chain error as the index sees it, by its
// ChainUnreadable method alone; its Error names the catalog, which no
// answer may.
type fakeChain struct{ transient bool }

func (e fakeChain) Error() string         { return "namespace cat-season: cannot read its chain" }
func (e fakeChain) ChainUnreadable() bool { return e.transient }

// TestV077ChainUnreadable (FSVC-10 / FCORE-3; §C.4 requireAt: "A verifier
// that can't read the chain answers 503 (behind) while the cause is
// transient (§A.1), and 502 (upstream) otherwise, naming no namespace,
// never 403"): a read check failing so is 503 behind with Retry-After, or
// 502 upstream, its body naming no namespace, even where the error is also
// a 403 (a grant check that wrapped it), at a query, at /_refs and at a
// view (writeAccessErr, writeCoverErr, writeUpstreamErr).
func TestV077ChainUnreadable(t *testing.T) {
	t.Parallel()
	ix := &Index{opt: Options{Logf: func(string, ...any) {}}}
	for _, c := range []struct {
		name   string
		err    error
		status int
	}{
		{"transient", fakeChain{true}, 503},
		{"lasting", fakeChain{false}, 502},
		{"transient, also a 403", errors.Join(&grant.AuthError{Status: 403, Msg: "at rejected: namespace cat-season"}, fakeChain{true}), 503},
		{"lasting, also a 403", fmt.Errorf("%w: %w", &grant.AuthError{Status: 403, Msg: "at rejected"}, fakeChain{false}), 502},
	} {
		for what, write := range map[string]func(http.ResponseWriter){
			"access": func(w http.ResponseWriter) {
				ix.writeAccessErr(w, "access check for matches", c.err, "cannot read the namespace configuration")
			},
			"cover": func(w http.ResponseWriter) { ix.writeCoverErr(w, "matches", c.err) },
			"upstream": func(w http.ResponseWriter) {
				ix.writeUpstreamErr(w, "exchange", c.err, "cannot read a namespace configuration")
			},
		} {
			rec := httptest.NewRecorder()
			write(rec)
			code := map[int]string{503: "behind", 502: "upstream"}[c.status]
			body := rec.Body.String()
			if rec.Code != c.status || !strings.Contains(body, `"code":"`+code+`"`) || strings.Contains(body, "cat-season") {
				t.Errorf("%s, %s: %d %s, want %d %s naming no namespace", c.name, what, rec.Code, body, c.status, code)
			}
			if c.status == 503 && rec.Header().Get("Retry-After") == "" {
				t.Errorf("%s, %s: 503 without Retry-After", c.name, what)
			}
		}
	}
}

// TestV077MemberBehindNamesNone (FSVC-12; §A.4 Private namespaces: "503
// (behind, §B.5) until it has reached each"; /principal hides
// catalog.trust, §7.4): a namespace visibility reads whose follower holds
// no checkpoint yet is 503 behind with a fixed body; only the log names
// it.
func TestV077MemberBehindNamesNone(t *testing.T) {
	t.Parallel()
	var logged []string
	ix := &Index{opt: Options{Logf: func(f string, a ...any) { logged = append(logged, fmt.Sprintf(f, a...)) }}}
	rec := httptest.NewRecorder()
	ix.writeCoverErr(rec, "matches", fmt.Errorf("%w: %s (§A.4)", errMemberBehind, "cat-season"))
	if rec.Code != 503 || strings.Contains(rec.Body.String(), "cat-season") || rec.Header().Get("Retry-After") == "" {
		t.Errorf("member behind: %d %s", rec.Code, rec.Body)
	}
	if len(logged) != 1 || !strings.Contains(logged[0], "cat-season") {
		t.Errorf("the log %q doesn't name cat-season", logged)
	}
}
