package index_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/follow"
	"github.com/middle-management/patchlog/internal/index"
)

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

const d2020 = "https://json-schema.org/draft/2020-12/schema"

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// svc is a running index with its HTTP server.
type svc struct {
	t      *testing.T
	ix     *index.Index
	http   *httptest.Server
	cancel context.CancelFunc
	done   chan struct{}
	core   *client.Client
	mu     sync.Mutex
	batch  []*follow.Batch
	purges [][]string
	dbPath string
}

func (s *svc) PurgeTags(tags []string) {
	s.mu.Lock()
	s.purges = append(s.purges, tags)
	s.mu.Unlock()
}

type svcOpts struct {
	db       string
	ns       []string
	untyped  bool
	rebuild  bool
	branches bool
	noRun    bool
	noFTS    bool
	minWait  time.Duration
	now      func() time.Time
	hc       *http.Client
}

func startSvc(t *testing.T, core *client.Client, o svcOpts) *svc {
	t.Helper()
	s := &svc{t: t, core: core, done: make(chan struct{}), dbPath: o.db}
	if o.hc != nil {
		core = core.With(client.WithHTTPClient(o.hc))
	}
	opt := index.Options{
		Client: core, DB: o.db, Namespaces: o.ns, UntypedListing: o.untyped, Rebuild: o.rebuild, Branches: o.branches, NoFTS: o.noFTS,
		MinWait: o.minWait, Purger: s, Now: o.now, CheckerTTL: time.Millisecond,
		Logf:          func(f string, a ...any) { t.Logf(f, a...) },
		OnApply:       func(b *follow.Batch) { s.mu.Lock(); s.batch = append(s.batch, b); s.mu.Unlock() },
		FollowOptions: []follow.Option{follow.WithBackoff(time.Millisecond, 20*time.Millisecond)},
	}
	s.ix = must(index.Open(context.Background(), opt))
	s.http = httptest.NewServer(s.ix.Handler())
	ctx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel
	if o.noRun {
		close(s.done)
	} else {
		go func() { s.ix.Run(ctx); close(s.done) }()
	}
	t.Cleanup(s.stop)
	return s
}

func (s *svc) stop() {
	if s.cancel == nil {
		return
	}
	s.cancel()
	<-s.done
	s.http.Close()
	s.ix.Close()
	s.cancel = nil
}

func (s *svc) batches() []*follow.Batch {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]*follow.Batch(nil), s.batch...)
}

// caughtUp waits until the index reached the core's head of ns.
func (s *svc) caughtUp(ns string) string {
	s.t.Helper()
	var head string
	waitFor(s.t, "index of "+ns+" to catch up", func() bool {
		h, err := s.core.NSHead(context.Background(), ns)
		if err != nil {
			return false
		}
		head = h.ID
		return s.ix.Checkpoint(ns) == h.ID
	})
	return head
}

type resp struct {
	status int
	header http.Header
	body   map[string]any
}

var noFollow = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

func (s *svc) raw(path, token string) resp {
	s.t.Helper()
	req := must(http.NewRequest("GET", s.http.URL+path, nil))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	r := must(noFollow.Do(req))
	defer r.Body.Close()
	b := must(io.ReadAll(r.Body))
	out := resp{status: r.StatusCode, header: r.Header}
	if len(b) > 0 {
		if err := json.Unmarshal(b, &out.body); err != nil {
			s.t.Fatalf("GET %s: %d %s", path, r.StatusCode, b)
		}
	}
	return out
}

// search follows redirects and returns the 200 body.
func (s *svc) search(path, token string) map[string]any {
	s.t.Helper()
	for range 5 {
		r := s.raw(path, token)
		switch r.status {
		case 200:
			return r.body
		case 302:
			path = r.header.Get("Location")
		default:
			s.t.Fatalf("GET %s: %d %v", path, r.status, r.body)
		}
	}
	s.t.Fatalf("GET %s: too many redirects", path)
	return nil
}

func resources(body map[string]any) []string {
	var out []string
	for _, h := range body["hits"].([]any) {
		out = append(out, h.(map[string]any)["resource"].(string))
	}
	return out
}

func (s *svc) expect(path string, want ...string) map[string]any {
	s.t.Helper()
	b := s.search(path, "")
	if got := strings.Join(resources(b), ","); got != strings.Join(want, ",") {
		s.t.Errorf("%s: got [%s], want [%s]", path, got, strings.Join(want, ","))
	}
	return b
}

// --- fixtures ---------------------------------------------------------------

type world struct {
	s                        *clienttest.Server
	c                        *client.Client
	match, match2, playerRef string
}

func setup(t *testing.T) *world {
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{LongPoll: 150 * time.Millisecond})
	c := s.Client(t, client.WithAuthor("admin"))
	must(c.CreateNamespace(ctx, "schemas", map[string]any{"read": "public"}))
	must(c.CreateNamespace(ctx, "matches", map[string]any{"read": "public"}))
	player := must(c.CreateDoc(ctx, "schemas", "player", map[string]any{
		"$schema": d2020, "type": "object",
		"properties": map[string]any{"name": map[string]any{"type": "string", "x-index": "text"}, "id": map[string]any{"$ref": "#/$defs/id"}},
		"$defs":      map[string]any{"id": map[string]any{"type": "string", "x-index": "facet"}},
	}))
	w := &world{s: s, c: c, playerRef: "/r/schemas/player/rev/" + player.ID}
	matchSchema := func(extra string) map[string]any {
		return map[string]any{
			"$schema": d2020, "type": "object",
			"properties": map[string]any{
				"$schema":    map[string]any{"type": "string"},
				"title":      map[string]any{"type": "string", "x-index": "text"},
				"notes":      map[string]any{"type": "object", "x-index": "text"},
				"tags":       map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "x-index": "facet"},
				"status":     map[string]any{"type": "string", "x-index": "facet"},
				"live":       map[string]any{"type": "boolean", "x-index": "facet"},
				"kickoff":    map[string]any{"type": "string", "format": "date-time", "x-index": "sort"},
				"attendance": map[string]any{"type": "number", "x-index": "sort"},
				"players":    map[string]any{"type": "array", "items": map[string]any{"$ref": w.playerRef}},
				"extra":      map[string]any{"const": extra},
			},
		}
	}
	m1 := must(c.CreateDoc(ctx, "schemas", "match", matchSchema("v1")))
	w.match = "/r/schemas/match/rev/" + m1.ID
	m2 := must(c.Append(ctx, "schemas", "match", m1.ID, []any{map[string]any{"op": "replace", "path": "/properties/extra/const", "value": "v2"}}))
	w.match2 = "/r/schemas/match/rev/" + m2.ID
	return w
}

func (w *world) doc(t *testing.T, name, schema string, fields map[string]any) *client.WriteResult {
	fields["$schema"] = schema
	return must(w.c.CreateDoc(context.Background(), "matches", name, fields))
}

func (w *world) seed(t *testing.T) {
	w.doc(t, "derby", w.match, map[string]any{
		"title": "The Derby", "tags": []any{"local", "rivalry"}, "status": "done", "live": false,
		"kickoff": "2026-10-04T18:00:00+02:00", "attendance": 42000,
		"players": []any{map[string]any{"name": "Zlatan Ibrahimovic", "id": "p1"}, map[string]any{"name": "Henrik Larsson", "id": "p2"}},
		"notes":   map[string]any{"summary": "a tense evening", "list": []any{"rain", "red card"}},
	})
	w.doc(t, "cup", w.match, map[string]any{
		"title": "Cup semi final", "tags": []any{"cup"}, "status": "planned", "live": true,
		"kickoff": "2026-10-05T12:00:00Z", "attendance": 9000,
		"players": []any{map[string]any{"name": "Larsson junior", "id": "p3"}},
	})
	w.doc(t, "final", w.match2, map[string]any{
		"title": "Cup final", "tags": []any{"cup", "local"}, "status": "planned",
		"kickoff": "2026-10-05T09:30:00.5Z", "attendance": 61000.5, "extra": "v2",
	})
	must(w.c.CreateDoc(context.Background(), "matches", "notes", map[string]any{"title": "Derby notes, untyped"}))
}

// --- tests ------------------------------------------------------------------

func TestTypedQueries(t *testing.T) { testTypedQueries(t, false) }

// TestTypedQueriesLike runs the same queries on the LIKE-based text table.
func TestTypedQueriesLike(t *testing.T) { testTypedQueries(t, true) }

func testTypedQueries(t *testing.T, noFTS bool) {
	w := setup(t)
	w.seed(t)
	s := startSvc(t, w.c, svcOpts{db: filepath.Join(t.TempDir(), "i.db"), ns: []string{"matches"}, untyped: true, noFTS: noFTS})
	s.caughtUp("matches")
	if s.ix.FTS() == noFTS {
		t.Fatalf("FTS = %v", s.ix.FTS())
	}

	// Plain listing: typed and untyped documents, by name.
	s.expect("/matches", "cup", "derby", "final", "notes")
	// Text: fields through $ref (player names), object leaves under a text annotation.
	s.expect("/matches?q=derby", "derby") // the untyped "notes" is not searchable
	s.expect("/matches?q=larsson", "cup", "derby")
	s.expect("/matches?q=larsson+henrik", "derby")
	s.expect("/matches?q=red+card", "derby")
	s.expect("/matches?q=lars*", "cup", "derby")
	s.expect("/matches?q=nothing-matches-this")
	// Facets: arrays expand, values through $defs/$ref, non-strings as JSON.
	s.expect("/matches?facet[/tags]=local", "derby", "final")
	s.expect("/matches?facet[/tags]=local&facet[/tags]=cup", "cup", "derby", "final")
	s.expect("/matches?facet[/tags]=local&facet[/status]=planned", "final")
	s.expect("/matches?facet[/players/id]=p3", "cup")
	s.expect("/matches?facet[/live]=true", "cup")
	// Sort and ranges (numbers typed; RFC 3339 normalised to UTC).
	s.expect("/matches?sort=-/attendance", "final", "derby", "cup", "notes")
	s.expect("/matches?sort=/kickoff&facet[/status]=planned", "final", "cup")
	s.expect("/matches?sort=/kickoff", "derby", "final", "cup", "notes")
	s.expect("/matches?gt[/attendance]=9000", "derby", "final")
	s.expect("/matches?ge[/attendance]=9000&lt[/attendance]=42000", "cup")
	s.expect("/matches?ge[/kickoff]=2026-10-05T11:30:00%2B02:00&sort=/kickoff", "final", "cup")
	s.expect("/matches?lt[/kickoff]=2026-10-05T00:00:00Z", "derby")
	// Schema: exact revision or all revisions (prefix).
	s.expect("/matches?schema="+w.match, "cup", "derby")
	s.expect("/matches?schema="+w.match2, "final")
	s.expect("/matches?schema=/r/schemas/match", "cup", "derby", "final")
	s.expect("/matches?schema=/r/schemas/mat")

	// Hit shape.
	b := s.search("/matches?q=zlatan", "")
	h := b["hits"].([]any)[0].(map[string]any)
	head := must(w.c.Head(context.Background(), "matches", "derby")).ID
	if h["id"] != head || h["url"] != clienttest.Origin+"/r/matches/derby/rev/"+head || h["schema"] != w.match {
		t.Errorf("hit %v", h)
	}
	if fmt.Sprint(h["/tags"]) != "[local rivalry]" || fmt.Sprint(h["/players/id"]) != "[p1 p2]" || fmt.Sprint(h["/live"]) != "[false]" {
		t.Errorf("hit facets %v", h)
	}
	if sc, _ := h["score"].(float64); sc <= 0 {
		t.Errorf("score %v", h["score"])
	}
	if b["at"] != s.ix.Checkpoint("matches") {
		t.Errorf("at %v", b["at"])
	}

	// Counts and paging.
	b = s.search("/matches?counts=/tags&limit=2", "")
	if got := resources(b); fmt.Sprint(got) != "[cup derby]" {
		t.Errorf("page 1 %v", got)
	}
	if c := fmt.Sprint(b["counts"]); c != "map[/tags:[map[count:2 value:cup] map[count:2 value:local] map[count:1 value:rivalry]]]" {
		t.Errorf("counts %s", c)
	}
	next, _ := b["next"].(string)
	if next == "" {
		t.Fatal("no next")
	}
	b = s.search(next, "")
	if got := resources(b); fmt.Sprint(got) != "[final notes]" || b["next"] != nil {
		t.Errorf("page 2 %v next %v", got, b["next"])
	}

	// Redirect and cache headers.
	r := s.raw("/matches?q=cup", "")
	if r.status != 302 || r.header.Get("Cache-Control") != "public, max-age=0, s-maxage=1, stale-while-revalidate=5" ||
		r.header.Get("Location") != "/matches/at/"+s.ix.Checkpoint("matches")+"?q=cup" {
		t.Errorf("pointer: %d %v", r.status, r.header)
	}
	r = s.raw(r.header.Get("Location"), "")
	if r.status != 200 || !strings.Contains(r.header.Get("Cache-Control"), "immutable") || r.header.Get("Cache-Tag") != "ns:matches" {
		t.Errorf("at: %d %v", r.status, r.header)
	}
	// Bad input.
	for _, p := range []string{"/matches?bogus=1", "/matches?sort=kickoff", "/matches?limit=0", "/matches?facet[x]=1", "/matches?min=nope"} {
		if r := s.raw(p, ""); r.status != 400 {
			t.Errorf("%s: %d", p, r.status)
		}
	}
	if r := s.raw("/other", ""); r.status != 404 {
		t.Errorf("unindexed namespace: %d", r.status)
	}
}

func TestUntypedListingOff(t *testing.T) {
	w := setup(t)
	w.seed(t)
	s := startSvc(t, w.c, svcOpts{db: filepath.Join(t.TempDir(), "i.db"), ns: []string{"matches"}, untyped: false})
	s.caughtUp("matches")
	s.expect("/matches", "cup", "derby", "final")
	// A typed document that becomes untyped leaves the index.
	ctx := context.Background()
	h := must(w.c.Head(ctx, "matches", "cup"))
	must(w.c.Append(ctx, "matches", "cup", h.ID, []any{map[string]any{"op": "remove", "path": "/$schema"}}))
	s.caughtUp("matches")
	s.expect("/matches", "derby", "final")
	s.expect("/matches?q=semi")
}

func TestUpdatesTombstonePurge(t *testing.T) {
	ctx := context.Background()
	w := setup(t)
	w.seed(t)
	s := startSvc(t, w.c, svcOpts{db: filepath.Join(t.TempDir(), "i.db"), ns: []string{"matches"}, untyped: true})
	s.caughtUp("matches")

	// An update re-indexes.
	h := must(w.c.Head(ctx, "matches", "cup"))
	must(w.c.Append(ctx, "matches", "cup", h.ID, []any{map[string]any{"op": "replace", "path": "/title", "value": "Cup quarter final"}}))
	s.caughtUp("matches")
	s.expect("/matches?q=semi")
	s.expect("/matches?q=quarter", "cup")

	// Tombstone.
	h = must(w.c.Head(ctx, "matches", "derby"))
	must(w.c.Delete(ctx, "matches", "derby", h.ID))
	s.caughtUp("matches")
	s.expect("/matches?q=zlatan")
	s.expect("/matches?facet[/tags]=local", "final")
	s.expect("/matches", "cup", "final", "notes")
	s.mu.Lock()
	if len(s.purges) != 0 {
		t.Errorf("tombstone purged tags: %v", s.purges)
	}
	s.mu.Unlock()

	// Purge: rows gone and the service's cache tags purged.
	h = must(w.c.Head(ctx, "matches", "final"))
	must(w.c.Purge(ctx, "matches", "final", h.ID, false))
	s.caughtUp("matches")
	s.expect("/matches?facet[/tags]=cup", "cup")
	s.expect("/matches", "cup", "notes")
	s.mu.Lock()
	purges := fmt.Sprint(s.purges)
	s.mu.Unlock()
	if purges != "[[ns:matches]]" {
		t.Errorf("purges %s", purges)
	}
}

// failing makes GETs of one resource fail while armed.
type failing struct {
	armed atomic.Bool
	path  string
	rt    http.RoundTripper
}

func (f *failing) RoundTrip(r *http.Request) (*http.Response, error) {
	if f.armed.Load() && strings.HasPrefix(r.URL.Path, f.path) {
		return nil, errors.New("injected failure")
	}
	return f.rt.RoundTrip(r)
}

func TestBatchIsOneUnit(t *testing.T) {
	ctx := context.Background()
	w := setup(t)
	ft := &failing{path: "/r/matches/b/", rt: http.DefaultTransport}
	s := startSvc(t, w.c, svcOpts{db: filepath.Join(t.TempDir(), "i.db"), ns: []string{"matches"}, noRun: true, hc: &http.Client{Transport: ft}})
	origin := must(w.c.Origin(ctx))

	// Bring the index to the current head.
	head := must(w.c.NSHead(ctx, "matches")).ID
	entries := must(w.c.NSLog(ctx, "matches", head, ""))
	var units []follow.Unit
	for _, e := range entries {
		units = append(units, follow.Unit{Entry: e})
	}
	if err := s.ix.Apply(ctx, &follow.Batch{Origin: origin, NS: "matches", Units: units, NewCheckpoint: head}); err != nil {
		t.Fatal(err)
	}

	br := must(w.c.Batch(ctx, "matches", client.BatchRequest{Items: []client.BatchItem{
		{Resource: "a", IfNoneMatch: true, Steps: []client.Step{client.PatchStep(client.GenesisPatches(map[string]any{"$schema": w.match, "title": "alpha"}))}},
		{Resource: "b", IfNoneMatch: true, Steps: []client.Step{client.PatchStep(client.GenesisPatches(map[string]any{"$schema": w.match, "title": "beta"}))}},
	}}, false))
	entries = must(w.c.NSLog(ctx, "matches", br.NSID, head))
	if len(entries) != 1 || entries[0].Kind != "batch" {
		t.Fatalf("entries %+v", entries)
	}
	b := &follow.Batch{Origin: origin, NS: "matches", Units: []follow.Unit{{Entry: entries[0]}}, From: head, NewCheckpoint: br.NSID}

	ft.armed.Store(true)
	if err := s.ix.Apply(ctx, b); err == nil {
		t.Fatal("Apply succeeded with a failing fetch")
	}
	if s.ix.Checkpoint("matches") != head {
		t.Fatal("checkpoint moved")
	}
	s.expect("/matches?q=alpha") // nothing of the batch is visible
	ft.armed.Store(false)
	if err := s.ix.Apply(ctx, b); err != nil {
		t.Fatal(err)
	}
	s.expect("/matches?schema=/r/schemas/match", "a", "b")
	if s.ix.Checkpoint("matches") != br.NSID {
		t.Fatal("checkpoint not at the batch")
	}
	// Idempotent: applying again changes nothing.
	if err := s.ix.Apply(ctx, b); err != nil {
		t.Fatal(err)
	}
	s.expect("/matches?schema=/r/schemas/match", "a", "b")
}

func TestCheckpointSurvivesRestart(t *testing.T) {
	ctx := context.Background()
	w := setup(t)
	w.seed(t)
	db := filepath.Join(t.TempDir(), "i.db")
	s := startSvc(t, w.c, svcOpts{db: db, ns: []string{"matches"}, untyped: true})
	cp := s.caughtUp("matches")
	s.stop()

	h := must(w.c.Head(ctx, "matches", "cup"))
	must(w.c.Append(ctx, "matches", "cup", h.ID, []any{map[string]any{"op": "replace", "path": "/title", "value": "Cup replay"}}))

	s2 := startSvc(t, w.c, svcOpts{db: db, ns: []string{"matches"}, untyped: true})
	if s2.ix.Checkpoint("matches") != cp {
		t.Fatalf("checkpoint after reopen %q, want %q", s2.ix.Checkpoint("matches"), cp)
	}
	s2.caughtUp("matches")
	bs := s2.batches()
	if len(bs) == 0 || bs[0].From != cp {
		t.Fatalf("first batch after restart from %q, want %q", bs[0].From, cp)
	}
	n := 0
	for _, b := range bs {
		n += len(b.Units)
	}
	if n != 1 {
		t.Errorf("reprocessed %d units, want 1", n)
	}
	s2.expect("/matches?q=replay", "cup")
	s2.expect("/matches?q=derby", "derby")
}

func TestRebuild(t *testing.T) {
	w := setup(t)
	w.seed(t)
	db := filepath.Join(t.TempDir(), "i.db")
	s := startSvc(t, w.c, svcOpts{db: db, ns: []string{"matches"}, untyped: true})
	s.caughtUp("matches")
	s.stop()

	s2 := startSvc(t, w.c, svcOpts{db: db, ns: []string{"matches"}, untyped: true, rebuild: true, noRun: true})
	if s2.ix.Checkpoint("matches") != "" {
		t.Fatal("rebuild kept the checkpoint")
	}
	s2.stop()
	s3 := startSvc(t, w.c, svcOpts{db: db, ns: []string{"matches"}, untyped: true, rebuild: true})
	s3.caughtUp("matches")
	if bs := s3.batches(); len(bs) == 0 || bs[0].From != "" {
		t.Fatal("rebuild did not replay from the beginning")
	}
	s3.expect("/matches?q=larsson", "cup", "derby")
}

func TestMinAndStale(t *testing.T) {
	ctx := context.Background()
	w := setup(t)
	s := startSvc(t, w.c, svcOpts{db: filepath.Join(t.TempDir(), "i.db"), ns: []string{"matches"}, minWait: 2 * time.Second})
	first := s.caughtUp("matches")

	// Read-your-writes: the write's X-Namespace-Revision as min.
	wr := w.doc(t, "derby", w.match, map[string]any{"title": "The Derby"})
	r := s.raw("/matches?q=derby&min="+wr.NSID, "")
	if r.status != 302 {
		t.Fatalf("min: %d %v", r.status, r.body)
	}
	loc := r.header.Get("Location")
	if !strings.HasPrefix(loc, "/matches/at/") || strings.Contains(loc, "min=") {
		t.Fatalf("location %s", loc)
	}
	s.expect(loc, "derby")
	// An older min passes immediately.
	if r := s.raw("/matches?min="+first, ""); r.status != 302 {
		t.Fatalf("old min: %d", r.status)
	}

	// Stale ns_id: 302 to the current checkpoint.
	cur := s.ix.Checkpoint("matches")
	r = s.raw("/matches/at/"+first+"?q=derby", "")
	if r.status != 302 || r.header.Get("Location") != "/matches/at/"+cur+"?q=derby" {
		t.Fatalf("stale: %d %s", r.status, r.header.Get("Location"))
	}

	// The follower is stopped: min is not reached → 503 with Retry-After.
	s.cancel()
	<-s.done
	s.ix.SetMinWait(150 * time.Millisecond)
	future := must(w.c.CreateDoc(ctx, "matches", "final", map[string]any{"title": "x"}))
	start := time.Now()
	r = s.raw("/matches?min="+future.NSID, "")
	if r.status != 503 || r.header.Get("Retry-After") == "" || r.header.Get("Cache-Control") != "no-store" {
		t.Fatalf("min ahead: %d %v", r.status, r.header)
	}
	if d := time.Since(start); d < 150*time.Millisecond {
		t.Errorf("did not wait: %s", d)
	}
}

func TestPurgeNamespace(t *testing.T) {
	ctx := context.Background()
	w := setup(t)
	w.seed(t)
	s := startSvc(t, w.c, svcOpts{db: filepath.Join(t.TempDir(), "i.db"), ns: []string{"matches"}, untyped: true})
	s.caughtUp("matches")
	s.expect("/matches?q=larsson", "cup", "derby")

	cfg := must(w.c.NSHead(ctx, "matches")).Config
	must(w.c.PatchConfig(ctx, "matches", cfg, []any{map[string]any{"op": "add", "path": "/frozen", "value": true}}))
	head := must(w.c.NSHead(ctx, "matches")).ID
	must(w.c.PurgeNamespace(ctx, "matches", head))
	waitFor(t, "purge-ns", func() bool { return s.raw("/matches", "").status == 410 })
	s.mu.Lock()
	purges := fmt.Sprint(s.purges)
	s.mu.Unlock()
	if purges != "[[ns:matches]]" {
		t.Errorf("purges %s", purges)
	}
	// The purged state survives a restart.
	s.stop()
	s2 := startSvc(t, w.c, svcOpts{db: s.dbPath, ns: []string{"matches"}, untyped: true, noRun: true})
	if r := s2.raw("/matches?q=larsson", ""); r.status != 410 {
		t.Errorf("after restart: %d", r.status)
	}
	if got := s2.ix.CountRows("matches"); got != 0 {
		t.Errorf("%d rows left", got)
	}
}
