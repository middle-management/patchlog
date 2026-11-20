package index_test

import (
	"context"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/edge"
	"github.com/middle-management/patchlog/internal/index"
)

// v85Gate holds requests of path, once on, until it is released.
type v85Gate struct {
	on   atomic.Bool
	base http.RoundTripper
	path string
	open chan struct{}
	once sync.Once
}

func (g *v85Gate) release() { g.once.Do(func() { close(g.open) }) }

func (g *v85Gate) RoundTrip(r *http.Request) (*http.Response, error) {
	if g.on.Load() && r.URL.Path == g.path {
		select {
		case <-g.open:
		case <-r.Context().Done():
			return nil, r.Context().Err()
		}
	}
	return g.base.RoundTrip(r)
}

// Scenario 134 (SERVICES §A.4 view, v0.85: "An exchange whose cookie would
// be 403 at once, as a key or role its marker draws on has changed since
// the checkpoint the marker is judged at, answers 503 (behind) with
// Retry-After";
// §12.1). li is a partial reader of covered matches, so her marker there
// is judged at the index's checkpoint. While the index is behind a change
// to the key that verified her grant, or to the role she reads through,
// her exchange is 503 behind with Retry-After and no cookie, alone and
// beside a grant that would get one; a grant refused 403 beside it still
// answers 403. Once the index has applied the change, she gets her
// cookie and reads under it. Before v0.85 the exchange minted a cookie
// that was 403 at its first use.
func TestV085ExchangeBehindKeyChange(t *testing.T) {
	t.Parallel()
	for name, op := range map[string]map[string]any{
		"her key":  {"op": "replace", "path": "/keys/1/maxTtl", "value": "PT14M"},
		"her role": {"op": "add", "path": "/roles/reader/x-note", "value": "changed"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			w := newV75XOn(t, clienttest.New(t, clienttest.Options{Auth: true, LongPoll: 150 * time.Millisecond}))
			hold := &v85Gate{base: http.DefaultTransport, path: "/ns/matches/log", open: make(chan struct{})}
			x := v06Start(t, w, filepath.Join(t.TempDir(), "i.db"), &http.Client{Transport: hold}, false)
			t.Cleanup(hold.release)
			w.x = x
			z := x.caughtUp("matches")
			li := w.reader("user:li", []any{"fans"})
			if r := p37Do(t, x, "POST", "/edge-grants", li, "", nil, ""); r.status != 200 {
				t.Fatalf("her exchange before the change: %d %v", r.status, r.body)
			}

			hold.on.Store(true)
			time.Sleep(500 * time.Millisecond) // the long-poll in flight returns; the next one is held
			ctx := context.Background()
			must(w.admin.PatchConfig(ctx, "matches", must(w.admin.NSHead(ctx, "matches")).Config, []any{op}))
			x.ix.ExpireGrantChecks()
			if got := x.ix.Checkpoint("matches"); got != z {
				t.Fatalf("matches' follower moved to %s; the test needs it at %s", got, z)
			}
			behind := func(what string, r p37Resp) {
				t.Helper()
				if r.status != 503 || r.body["code"] != "behind" || r.header.Get("Retry-After") == "" || len(r.cookies) != 0 || r.header.Get("Cache-Control") != "no-store" {
					t.Errorf("%s while the index is behind the change: %d %v, %d cookies, want 503 behind", what, r.status, r.body, len(r.cookies))
				}
				for _, word := range []string{"matches", "reader-01", "reader"} {
					if msg, _ := r.body["message"].(string); strings.Contains(msg, word) {
						t.Errorf("%s: the 503 names %q: %s", what, word, msg)
					}
				}
			}
			behind("her exchange", p37Do(t, x, "POST", "/edge-grants", li, "", nil, ""))
			stranger := clienttest.NewKey("stranger").Grant(t, w.s.Now(), "user:eve", []string{"matches"}, []string{"read"})
			both := `{"grants":["` + li + `","` + stranger + `"]}`
			if r := p37Do(t, x, "POST", "/edge-grants", "", both, nil, ""); r.status != 401 && r.status != 403 {
				t.Errorf("beside a grant that is refused: %d %v, want its refusal first (§C.5.2)", r.status, r.body)
			}

			hold.release()
			waitFor(t, "the index applies the change", func() bool { return x.ix.Checkpoint("matches") != z })
			x.ix.ExpireGrantChecks()
			r := p37Do(t, x, "POST", "/edge-grants", li, "", nil, "")
			if r.status != 200 || len(r.cookies) == 0 {
				t.Fatalf("her exchange once the index caught up: %d %v", r.status, r.body)
			}
			for _, p := range r.body["prefixes"].([]any) {
				if strings.HasPrefix(p.(string), "/matches/view/") {
					if got, _ := p37Follow(t, x, p.(string)+"?q=derby", r.cookies, ""); got.status != 200 {
						t.Errorf("under the cookie: %d %v", got.status, got.body)
					}
				}
			}
		})
	}
}

// v06Start starts an index on db following matches over hc, not running
// until the caller runs it.
func v06Start(t *testing.T, w *v75x, db string, hc *http.Client, noRun bool) *svc {
	t.Helper()
	all := []string{"schemas", "cat-season", "matches", "matches-r7"}
	return startSvcWith(t, w.s.Client(t, client.WithBearer(w.k.Grant(t, w.s.Now(), "svc:indexer", all, []string{"read"}))),
		svcOpts{db: db, ns: []string{"matches"}, untyped: true, now: w.s.Now, noRun: noRun, hc: hc},
		func(o *indexOpts) {
			o.EdgeGrants, o.ExchangeRate = edge.NewCookies("index", []byte("0123456789abcdef0123456789abcdef")), index.DefaultExchangeRate
		})
}
