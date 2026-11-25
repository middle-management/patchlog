package client_test

import (
	"context"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
)

// A read-filtering grant is a view (§7.9, auto.go): the plain NSLog,
// NSLogPage, Heads and LongPoll of a partial reader read its view's
// filtered answers and say so, redirected there in a namespace that isn't
// public and through the view ViewOf finds, once, in a public one. An
// unrestricted reader and a request without a grant read as before, with
// no lookups after the first read, none at all where the namespace isn't
// public; WithUnfilteredOnly keeps the unfiltered reads.
func TestV090AutoView(t *testing.T) {
	t.Parallel()
	for _, read := range []string{"grant", "public"} {
		for _, sealed := range []bool{false, true} {
			name := read + "/plain"
			if sealed {
				name = read + "/sealed"
			}
			t.Run(name, func(t *testing.T) {
				t.Parallel()
				v090AutoView(t, read, sealed)
			})
		}
	}
}

// v090Counts counts the requests that look a view up (§7.9 view):
// POST /edge-grants and POST /ns/{ns}/keys.
type v090Counts struct {
	mu         sync.Mutex
	edge, keys int
}

func (n *v090Counts) wrap(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.mu.Lock()
		switch {
		case r.Method == "POST" && r.URL.Path == "/edge-grants":
			n.edge++
		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/keys"):
			n.keys++
		}
		n.mu.Unlock()
		h.ServeHTTP(w, r)
	})
}

func (n *v090Counts) get() (edge, keys int) {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.edge, n.keys
}

func v090AutoView(t *testing.T, read string, sealed bool) {
	ctx := context.Background()
	var n v090Counts
	opts := clienttest.Options{Auth: true, EdgeGrants: true, Wrap: n.wrap}
	doc := map[string]any{"read": read}
	wrap := func(p []any) []any { return p }
	if sealed {
		opts.KeyStore = keyStore(t)
		doc["encryption"] = map[string]any{"level": "sealed"}
		wrap = nonced
	}
	s := clienttest.New(t, opts)
	k := clienttest.NewKey("k")
	// k2's entry carries the read rule, so a grant from it is a partial
	// reader until the entry drops it.
	k2 := clienttest.NewKey("k2")
	ruled := k2.Entry("read")
	ruled["rules"] = []any{map[string]any{"op": "test", "path": "/doc/team", "value": "a"}}
	doc["keys"] = []any{k.Entry("*"), ruled}
	must(s.Client(t, client.WithBearer(s.OperatorGrant(t, "n"))).CreateNamespace(ctx, "n", doc))
	op := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:o", []string{"n"}, []string{"read", "config"})))
	admin := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:a", []string{"n"}, []string{"read", "create", "append"})), client.WithKeys(client.NewKeys(nil)))
	must(admin.Create(ctx, "n", "a1", wrap(client.GenesisPatches(map[string]any{"team": "a"}))))
	must(admin.Create(ctx, "n", "b1", wrap(client.GenesisPatches(map[string]any{"team": "b"}))))

	reader := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:r", []string{"n"}, []string{"read"},
		map[string]any{"rules": []any{map[string]any{"op": "test", "path": "/doc/team", "value": "a"}}})), client.WithKeys(client.NewKeys(nil)))
	resources := func(es []client.NSEntry) []string {
		var out []string
		for _, e := range es {
			if e.Kind == "head" {
				out = append(out, e.Resource)
			}
		}
		return out
	}
	rows := func(items []client.HeadItem) []string {
		var out []string
		for _, it := range items {
			out = append(out, it.Resource)
		}
		return out
	}
	// round reads ns with every plain call and checks each answer is
	// filtered as want says, showing want's resources.
	round := func(c *client.Client, filtered bool, want []string) {
		t.Helper()
		h := must(c.NSHead(ctx, "n"))
		es, fa, err := c.NSLog(ctx, "n", h.ID, "")
		if err != nil || fa.Filtered() != filtered || !slices.Equal(resources(es), want) {
			t.Fatalf("NSLog: %v %+v %v, want %v filtered %v", err, fa, resources(es), want, filtered)
		}
		page, _, pfa, err := c.NSLogPage(ctx, "n", h.ID, "")
		if err != nil || pfa.Filtered() != filtered || !slices.Equal(resources(page), want) {
			t.Fatalf("NSLogPage: %v %+v %v", err, pfa, resources(page))
		}
		items, hfa, err := c.Heads(ctx, "n", h.ID)
		if err != nil || hfa.Filtered() != filtered || !slices.Equal(rows(items), want) {
			t.Fatalf("Heads: %v %+v %v", err, hfa, rows(items))
		}
		items, _, hfa, err = c.HeadsPrefixPage(ctx, "n", h.ID, "a", "")
		if err != nil || hfa.Filtered() != filtered || !slices.Equal(rows(items), []string{"a1"}) {
			t.Fatalf("HeadsPrefixPage: %v %+v %v", err, hfa, rows(items))
		}
		lp, err := c.LongPoll(ctx, "n", "", "")
		if err != nil || lp.Filtered() != filtered || !slices.Equal(resources(lp.Entries), want) {
			t.Fatalf("LongPoll: %v %+v", err, lp)
		}
		if filtered && (fa.View == "" || hfa.View != fa.View || lp.View != fa.View) {
			t.Fatalf("views %+v %+v %+v", fa, hfa, lp.FilteredAt)
		}
	}
	steady := func(who string, c *client.Client, filtered bool, want []string, maxEdge int) {
		t.Helper()
		e0, _ := n.get()
		round(c, filtered, want)
		e1, k1 := n.get()
		round(c, filtered, want)
		round(c, filtered, want)
		e2, k2 := n.get()
		if e2 != e1 || k2 != k1 {
			t.Fatalf("%s: lookups after the first round: /edge-grants %d→%d, /keys %d→%d", who, e1, e2, k1, k2)
		}
		if e1-e0 > maxEdge {
			t.Fatalf("%s: %d POST /edge-grants, want at most %d", who, e1-e0, maxEdge)
		}
	}
	public := read == "public"
	lookups := 0
	if public && !sealed {
		lookups = 1
	}
	steady("partial reader", reader, true, []string{"a1"}, lookups)
	steady("unrestricted reader", admin, false, []string{"a1", "b1"}, lookups)
	if public && !sealed {
		steady("anonymous", s.Client(t), false, []string{"a1", "b1"}, 0)
	}

	if public && !sealed {
		// Reads at once ask once between them.
		fresh := s.Client(t, client.WithBearer(reader.Bearer()))
		h := must(fresh.NSHead(ctx, "n"))
		e0, _ := n.get()
		var wg sync.WaitGroup
		for range 8 {
			wg.Go(func() {
				if _, fa, err := fresh.NSLog(ctx, "n", h.ID, ""); err != nil || !fa.Filtered() {
					t.Errorf("NSLog at once: %v %+v", err, fa)
				}
			})
		}
		wg.Wait()
		if e, _ := n.get(); e != e0+1 {
			t.Fatalf("reads at once: %d POST /edge-grants, want 1", e-e0)
		}
	}

	// Unfiltered only: the redirect is a *FilteredError; a public
	// namespace's unfiltered answer stands, its view never looked up.
	strict := reader.Unfiltered()
	h := must(strict.NSHead(ctx, "n"))
	e0, k0 := n.get()
	_, _, lerr := strict.NSLog(ctx, "n", h.ID, "")
	_, _, herr := strict.Heads(ctx, "n", h.ID)
	_, perr := strict.LongPoll(ctx, "n", "", "")
	switch {
	case !public:
		for _, err := range []error{lerr, herr, perr} {
			if fe, ok := client.AsFiltered(err); !ok || fe.NS != "n" || fe.View == "" {
				t.Fatalf("unfiltered only: %v", err)
			}
		}
	case !sealed:
		if lerr != nil || herr != nil || perr != nil {
			t.Fatalf("unfiltered only, public: %v %v %v", lerr, herr, perr)
		}
		es, fa, _ := strict.NSLog(ctx, "n", h.ID, "")
		if fa.Filtered() || !slices.Equal(resources(es), []string{"a1", "b1"}) {
			t.Fatalf("unfiltered only, public: %+v %v", fa, resources(es))
		}
	default:
		// The unfiltered sealed answers open under no key the reader holds.
		if lerr == nil {
			t.Fatal("unfiltered only, public sealed: the range opened")
		}
	}
	if e, k := n.get(); e != e0 || (k != k0 && !sealed) {
		t.Fatalf("unfiltered only looked a view up: /edge-grants %d→%d, /keys %d→%d", e0, e, k0, k)
	}

	// A grant whose view is the key's rule; dropping the rule makes it an
	// unrestricted reader, whose remembered view is then 403: the client
	// asks again, once, and reads at the unfiltered URLs.
	r2 := s.Client(t, client.WithBearer(k2.Grant(t, s.Now(), "user:r2", []string{"n"}, []string{"read"})), client.WithKeys(client.NewKeys(nil)))
	round(r2, true, []string{"a1"})
	nh := must(op.NSHead(ctx, "n"))
	plain := k2.Entry("read")
	must(op.PatchConfig(ctx, "n", nh.Config, ops(map[string]any{"op": "replace", "path": "/keys/1", "value": plain})))
	e0, _ = n.get()
	round(r2, false, []string{"a1", "b1"})
	if e, _ := n.get(); public && !sealed && e != e0+1 {
		t.Fatalf("after the rule changed: %d POST /edge-grants, want 1", e-e0)
	}
	round(r2, false, []string{"a1", "b1"})

	// A grant that expires while it reads through its view gets the
	// view's refusal, never the unfiltered answer in its place, and the
	// client asks no more.
	if public {
		h := must(reader.NSHead(ctx, "n"))
		s.Clock.Advance(2 * time.Hour)
		e0, k0 := n.get()
		for range 3 {
			if es, fa, err := reader.NSLog(ctx, "n", h.ID, ""); !client.IsAuth(err) {
				t.Fatalf("an expired grant's NSLog: %v %+v %v", err, fa, resources(es))
			}
			if lp, err := reader.LongPoll(ctx, "n", "", ""); !client.IsAuth(err) {
				t.Fatalf("an expired grant's LongPoll: %v %+v", err, lp)
			}
		}
		if e, k := n.get(); e+k > e0+k0+1 {
			t.Fatalf("an expired grant asked %d times", e+k-e0-k0)
		}
	}
}
