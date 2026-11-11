package dav_test

import (
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/dav"
)

// XT-1 (7), the gateway's half (§7.1, v0.82: "A tombstone's /rev/{T} is
// 410 with { tombstone, last }"; TOOLS §11 Deleted resources, §H.4): x is
// a flat resource another user deleted, its head the tombstone T after P.
// The core answers T's own /rev with the new 410, and the gateway in
// front of it reads the file as gone, absent from its directory. A save
// tagged with the version the user had, P, or with T itself, is 409 and
// isn't written over the delete (it judges by x's head, and where it
// reads the tagged revision the 410 is the core's), never "pruned" (§8.6)
// nor 412; the reload is the GET
// that finds it gone, 404, and the save after it makes the file anew, a
// restore over T (§8.2).
func TestV082XGatewayAtATombstone(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	asked := map[string]int{} // GETs of /rev/{id} the core answered, by status
	var tomb string
	e := newEnv(t, []string{"docs"}, nil, nil, func(c *clienttest.Options, _ *dav.Options) {
		c.Wrap = func(h http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				watch := tomb != "" && r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/rev/"+tomb)
				mu.Unlock()
				if !watch {
					h.ServeHTTP(w, r)
					return
				}
				rec := &v82xStatus{ResponseWriter: w}
				h.ServeHTTP(rec, r)
				mu.Lock()
				asked[r.Header.Get("X-Author")] = rec.code
				mu.Unlock()
			})
		}
	})
	P := e.create("docs", "x", map[string]any{"a": "1"})
	if tag := e.expect(e.do("GET", "/docs/x.json", ""), 200, "GET").header.Get("ETag"); tag != `"`+P+`"` {
		t.Fatalf("x's ETag %s, want P %s", tag, P)
	}
	T := must(e.c.Delete(e.ctx, "docs", "x", P)).ID
	mu.Lock()
	tomb = T
	mu.Unlock()

	// The core, as v0.82 has it.
	_, err := e.c.Doc(e.ctx, "docs", "x", T)
	if ae, ok := client.AsAPIError(err); !ok || ae.Status != 410 || ae.Tombstone() != T || ae.Last() != P {
		t.Fatalf("the core's /rev/{T}: %v, want 410 naming tombstone %s and last %s", err, T, P)
	}

	if got := names(e.propfind("/docs/"), "/docs/"); len(got) != 0 {
		t.Fatalf("docs lists %v, want nothing", got)
	}
	for _, c := range []struct{ what, rev string }{{"the version the user had", P}, {"the tombstone itself", T}} {
		r := e.expect(e.do("PUT", "/docs/x.json", `{"a": "mine"}`, "If-Match", `"`+c.rev+`"`), 409, "PUT tagged with "+c.what)
		if !strings.Contains(r.body, "deleted") || strings.Contains(r.body, "pruned") {
			t.Errorf("PUT tagged with %s: %s, want the delete named, not a prune", c.what, r.body)
		}
		if h, _ := e.load("docs", "x"); h.State != client.Tombstoned || h.ID != T || h.Last != P {
			t.Fatalf("PUT tagged with %s: the head %+v, want the tombstone %s kept", c.what, h, T)
		}
	}
	mu.Lock()
	t.Logf("GETs of /rev/{T} the core answered, by X-Author: %v", asked)
	if code, did := asked["dav"]; did && code != 410 {
		t.Errorf("the gateway's read of /rev/{T} was answered %d, want 410", code)
	}
	mu.Unlock()

	// The reload finds it gone, and the next save makes it anew over T.
	e.expect(e.do("GET", "/docs/x.json", ""), 404, "GET of the deleted file")
	e.expect(e.do("PUT", "/docs/x.json", `{"a": "mine"}`), 201, "PUT after the reload")
	h, doc := e.load("docs", "x")
	if h.State != client.Live {
		t.Fatalf("the head after the save: %+v", h)
	}
	sameJSON(t, doc, map[string]any{"a": "mine"})
	if le := e.lastEntry("docs", "x"); le.Kind != "rev" || le.Parent != T {
		t.Errorf("the save's entry is a %s on %s, want a restore, a rev on the tombstone %s (§8.2)", le.Kind, le.Parent, T)
	}
}

type v82xStatus struct {
	http.ResponseWriter
	code int
}

func (s *v82xStatus) WriteHeader(code int) {
	s.code = code
	s.ResponseWriter.WriteHeader(code)
}
