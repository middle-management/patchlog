package tree_test

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/tree"
)

// v081StopReads are the listings of v081StopWorld that show sec's item
// (sec.s, titled "Secret vw3k"), or its placement, or cursor past it.
var v081StopReads = []string{
	"/children?of=root", "/children?of=root&after=a0", "/roots", "/subtree?of=root",
	"/ancestors?of=sec.s", "/where?item=/r/sec/s", "/problems", "/orphans", "/manifest?of=root",
}

// §A.4, §B.5 Behind, §B.7, §B.11.5 (ACCESS-11, v0.26.1): a stop takes a
// namespace out of the combined checkpoint and out of what a public or
// g/all reader is judged by (Service.listed), so from the moment the stop
// is marked no answer to such a reader may show its content: not a
// listing kept at an at from before the stop, at any op, cursor or
// redirect, while the stop's purges of ns:{ns} are still to come. The
// checker's TTL is an hour, so its cached document, public, can't be what
// refuses. Readers are those of a public catalog (anonymous); with sec
// read by grant, of g/all by a grant that doesn't read sec (v0.81: before
// ACCESS-11 it was 403); and of a subject set (RoleView) that read sec's
// item only while sec read public.
func TestV081XRev2StopWindow(t *testing.T) {
	t.Parallel()
	for _, c := range []string{"public", "g/all", "subject set"} {
		t.Run(c, func(t *testing.T) {
			t.Parallel()
			catRead, contentRead := "public", "public"
			mods := []func(*tree.Options){func(o *tree.Options) { o.CheckerTTL = time.Hour }}
			switch c {
			case "g/all":
				contentRead = "grant"
			case "subject set":
				catRead = "grant"
				mods = append(mods, withScopeView)
			}
			w := newV081StopWorld(t, catRead, contentRead, mods...)
			all := []string{"cat", "pub", "sec"}
			reader, other := "", ""
			switch c {
			case "g/all":
				reader = w.k.Grant(t, w.s.Now(), "user:amy", all, []string{"read"})
				other = w.k.Grant(t, w.s.Now(), "user:p", []string{"cat", "pub"}, []string{"read"})
			case "subject set":
				// Its subject set shows the nodes; sec's item it reads
				// only while sec reads public.
				names := map[string]any{"op": "test", "path": "/resource", "schema": map[string]any{"enum": []any{"root", "pub.p", "sec.s"}}}
				reader = w.k.Grant(t, w.s.Now(), "user:r", []string{"cat"}, []string{"read"}, map[string]any{"rules": []any{names}})
				other = reader
			}
			// Kept at the at before the stop, under the shape that reads
			// sec (anonymous, or g/all reading sec namespace-wide).
			reads := v081StopReads
			if c == "subject set" {
				// Problems, orphans and manifests aren't filtered.
				reads = reads[:6]
			}
			var kept []string
			for _, p := range reads {
				st, _, b, at := v0261Get(w.x, "/cat"+p, reader)
				if st != 200 || !strings.Contains(at, "/at/") {
					t.Fatalf("setup %s: %d %s %s", p, st, at, b)
				}
				kept = append(kept, at)
			}
			if st, _, b, _ := v0261Get(w.x, "/cat/children?of=root", reader); !strings.Contains(b, "vw3k") {
				t.Fatalf("setup: sec's item not listed: %d %s", st, b)
			}
			type seen struct {
				path   string
				status int
				body   string
			}
			var (
				mu   sync.Mutex
				got  []seen
				once sync.Once
				ran  = make(chan struct{})
			)
			w.x.s.AfterStop(func(ns string) {
				if ns != "sec" {
					return
				}
				once.Do(func() {
					defer close(ran)
					for _, p := range append(kept, "/cat/children?of=root", "/cat/roots") {
						st, b := v081RawGet(t, w.x, p, other)
						mu.Lock()
						got = append(got, seen{p, st, b})
						mu.Unlock()
					}
				})
			})
			w.stop(t)
			select {
			case <-ran:
			case <-time.After(10 * time.Second):
				t.Fatal("the stop's hook didn't run")
			}
			w.x.s.AfterStop(nil)
			mu.Lock()
			defer mu.Unlock()
			for _, g := range got {
				t.Logf("%s: %d", g.path, g.status)
				if g.status == 200 && strings.Contains(g.body, "vw3k") {
					t.Errorf("sec stopped, its purges still to come: GET %s served sec's item: %s", g.path, g.body)
				}
			}
			// Once the purges are made, the same.
			for _, p := range kept {
				if st, b := v081RawGet(t, w.x, p, other); st == 200 && strings.Contains(b, "vw3k") {
					t.Errorf("sec stopped: GET %s served sec's item: %s", p, b)
				}
			}
		})
	}
}

// v081RawGet is a GET of path at x, with token as its bearer unless
// empty, redirects not followed, bounded by a deadline.
func v081RawGet(t *testing.T, x *svc, path, token string) (int, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req := must(http.NewRequestWithContext(ctx, "GET", x.http.URL+path, nil))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	r, err := noRedirect.Do(req)
	if err != nil {
		t.Errorf("GET %s: %v", path, err)
		return 0, ""
	}
	defer r.Body.Close()
	return r.StatusCode, string(must(io.ReadAll(r.Body)))
}
