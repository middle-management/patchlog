package tree_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/grant"
	"github.com/middle-management/patchlog/internal/tree"
)

// v077ChainErr is a verifier's error for a requireAt chain it can't read,
// as grantcheck's is joined (ChainUnreadable): its text names the chain's
// namespace, which no answer may.
type v077ChainErr struct{ transient bool }

func (e v077ChainErr) Error() string         { return "namespace cat-season: cannot read its chain" }
func (e v077ChainErr) ChainUnreadable() bool { return e.transient }

// v077ChainAnswer checks r, the answer to a request whose requireAt chain
// couldn't be read: 503 behind with Retry-After while transient, else 502
// upstream, no-store, naming no namespace, never 403 (§C.4, §12.1).
func v077ChainAnswer(t *testing.T, what string, transient bool, status int, h http.Header, body map[string]any) {
	t.Helper()
	want, code := http.StatusBadGateway, "upstream"
	if transient {
		want, code = http.StatusServiceUnavailable, "behind"
	}
	if status != want || body["code"] != code {
		t.Errorf("%s (transient %v): %d %v, want %d %s", what, transient, status, body, want, code)
	}
	if got := h.Get("Retry-After"); (got != "") != transient {
		t.Errorf("%s (transient %v): Retry-After %q", what, transient, got)
	}
	if cc := h.Get("Cache-Control"); cc != "no-store" {
		t.Errorf("%s: Cache-Control %q", what, cc)
	}
	if msg, _ := body["message"].(string); strings.Contains(msg, "cat-season") || strings.Contains(msg, "matches") {
		t.Errorf("%s: the body names a namespace: %q", what, msg)
	}
	if _, ok := body["ns"]; ok {
		t.Errorf("%s: the body names a namespace: %v", what, body)
	}
}

// §C.4 requireAt, §12.1 (v0.77): WriteAuthError answers a requireAt chain
// that can't be read 503 behind while transient, 502 upstream otherwise,
// however deep it is wrapped, even inside a refusal, and never 403.
func TestV077V04WriteAuthErrorChain(t *testing.T) {
	t.Parallel()
	for _, transient := range []bool{true, false} {
		for name, err := range map[string]error{
			"bare":    v077ChainErr{transient},
			"wrapped": fmt.Errorf("verifying: %w", v077ChainErr{transient}),
			"joined":  errors.Join(&grant.AuthError{Status: 403, Msg: "at rejected: namespace cat-season"}, v077ChainErr{transient}),
		} {
			rec := httptest.NewRecorder()
			tree.WriteAuthError(rec, err, t.Logf)
			var body map[string]any
			_ = json.Unmarshal(rec.Body.Bytes(), &body)
			v077ChainAnswer(t, "WriteAuthError "+name, transient, rec.Code, rec.Header(), body)
		}
	}
	// Other errors answer as before.
	rec := httptest.NewRecorder()
	tree.WriteAuthError(rec, &grant.AuthError{Status: 403, Msg: "no"}, t.Logf)
	if rec.Code != http.StatusForbidden {
		t.Errorf("a refusal: %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	tree.WriteAuthError(rec, errors.New("boom"), t.Logf)
	if rec.Code != http.StatusBadGateway {
		t.Errorf("another error: %d", rec.Code)
	}
}

// §C.4 requireAt (v0.77, scenario 123): a grant whose requireAt chain
// can't be read in a content namespace the catalog trusts makes the
// listing 503 behind or 502 upstream, as in the catalog itself; it is
// never taken as a grant that doesn't verify there (which, on a tree
// service without §B.11, was 403).
func TestV077V04ListingChainUnreadable(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{Auth: true, LongPoll: 150 * time.Millisecond})
	k := clienttest.NewKey("k")
	must(s.Client(t, client.WithBearer(s.OperatorGrant(t, "matches"))).CreateNamespace(ctx, "matches", map[string]any{"read": "grant", "keys": []any{k.Entry("*")}}))
	must(s.Client(t, client.WithBearer(s.OperatorGrant(t, "cat"))).CreateNamespace(ctx, "cat", map[string]any{"read": "grant", "keys": []any{k.Entry("*")},
		"catalog": map[string]any{"trust": []any{"matches"}, "mode": "dag"}}))
	all := []string{"cat", "matches"}
	w := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:w", all, []string{"read", "create"})))
	must(w.CreateDoc(ctx, "cat", "root", map[string]any{"title": "Root", "parents": []any{}}))
	must(w.CreateDoc(ctx, "matches", "derby", map[string]any{"title": "Derby"}))
	must(w.CreateDoc(ctx, "cat", "matches.derby", map[string]any{"parents": parents("root")}))
	x := startSvc(t, s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "svc:tree", all, []string{"read"}))), svcOpts{now: s.Now})
	x.caughtUp(all...)
	reader := k.Grant(t, s.Now(), "user:r", all, []string{"read"})
	if r := x.listingAs("/cat/children?of=root", reader); r.status != http.StatusOK {
		t.Fatalf("children: %d %v", r.status, r.body)
	}
	for _, ns := range all {
		for _, transient := range []bool{true, false} {
			x.s.FailVerify(func(got string) error {
				if got == ns {
					return fmt.Errorf("verifying: %w", v077ChainErr{transient})
				}
				return nil
			})
			r := x.raw("/cat/children?of=root", reader)
			v077ChainAnswer(t, "children, the chain unreadable in "+ns, transient, r.status, r.header, r.body)
		}
	}
	x.s.FailVerify(nil)
	if r := x.listingAs("/cat/children?of=root", reader); r.status != http.StatusOK {
		t.Fatalf("children once the chain reads: %d %v", r.status, r.body)
	}
}
