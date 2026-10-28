package index_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/follow"
)

// answering answers GETs under prefix with status, as the core would
// refuse them, and passes everything else on.
type answering struct {
	prefix string
	status int
	rt     http.RoundTripper
}

func (a *answering) RoundTrip(r *http.Request) (*http.Response, error) {
	if !strings.HasPrefix(r.URL.Path, a.prefix) {
		return a.rt.RoundTrip(r)
	}
	h := http.Header{}
	h.Set("Content-Type", "application/json")
	if a.status == 429 {
		h.Set("Retry-After", "1")
	}
	return &http.Response{StatusCode: a.status, Header: h, Request: r,
		Body: io.NopCloser(strings.NewReader(`{"code":"refused","message":"injected"}`))}, nil
}

// CORE-6/SERVICES-2 (§A.1, Open 86): a schema revision answering a 4xx
// other than 429 (a 401 to the service's own grant included) leaves the
// document indexed as untyped and the checkpoint moves on; a 429 or a 5xx
// is transient, and the batch is retried.
func TestV074V03SchemaFinalStatus(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	w := setup(t)
	w.doc(t, "derby", w.match, map[string]any{"title": "The Derby", "status": "done"})
	origin := must(w.c.Origin(ctx))
	head := must(w.c.NSHead(ctx, "matches")).ID
	var units []follow.Unit
	for _, e := range must(w.c.NSLog(ctx, "matches", head, "")) {
		units = append(units, follow.Unit{Entry: e})
	}
	batch := &follow.Batch{Origin: origin, NS: "matches", Units: units, NewCheckpoint: head}
	for _, c := range []struct {
		status int
		final  bool
	}{
		{401, true}, {400, true}, {403, true}, {405, true},
		{429, false}, {500, false}, {503, false},
	} {
		db := filepath.Join(t.TempDir(), "i.db")
		rt := &answering{prefix: "/r/schemas/match/", status: c.status, rt: transport}
		s := startSvcWith(t, w.c, svcOpts{db: db, ns: []string{"matches"}, untyped: true, noRun: true, hc: &http.Client{Transport: rt}})
		err := s.ix.Apply(ctx, batch)
		if !c.final {
			if err == nil || s.ix.Checkpoint("matches") != "" {
				t.Errorf("schema %d: Apply %v, checkpoint %q; want a transient failure", c.status, err, s.ix.Checkpoint("matches"))
			}
			s.stop()
			continue
		}
		if err != nil {
			t.Errorf("schema %d: Apply %v, want the document indexed untyped", c.status, err)
		} else if s.ix.Checkpoint("matches") != head {
			t.Errorf("schema %d: checkpoint %q, want %s", c.status, s.ix.Checkpoint("matches"), head)
		}
		s.stop()
		d := dumpIndex(t, db)
		parts := strings.Split(d, "--\n")
		if !strings.Contains(parts[0], "derby") || strings.Contains(parts[0], w.match) || parts[1] != "" || parts[2] != "" {
			t.Errorf("schema %d: index\n%s\nwant derby untyped, without rows", c.status, d)
		}
	}
}

// CORE-7/SERVICES-3 (§A.2, §A.4, Open 88): a schema marks, and the walk
// collects, through dependentSchemas whatever the data, so a document
// without the dependency's member still has its rows there.
func TestV074V03DependentSchemasWhateverTheData(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	w := setup(t)
	dep := must(w.c.CreateDoc(ctx, "schemas", "dep", map[string]any{"$schema": d2020, "type": "object",
		"dependentSchemas": map[string]any{"a": map[string]any{"properties": map[string]any{"b": map[string]any{"x-index": "facet"}}}}}))
	must(w.c.CreateDoc(ctx, "matches", "nodep", map[string]any{"$schema": "/r/schemas/dep/rev/" + dep.ID, "b": "x"}))
	s := startSvc(t, w.c, svcOpts{db: filepath.Join(t.TempDir(), "i.db"), ns: []string{"matches"}})
	s.caughtUp("matches")
	body := s.expect("/matches?facet[/b]=x&counts=/b", "nodep")
	counts, _ := body["counts"].(map[string]any)
	if got, _ := counts["/b"].(map[string]any); len(got) != 1 || got["x"] != 1.0 {
		t.Errorf("counts %v, want {/b: {x: 1}}", body["counts"])
	}
}

// SERVICES-1 (§A.5, §A.4, Open 84): on a query of one namespace, a min
// naming another namespace is 400, the body's min listing it, even one the
// service follows and the reader may see, which v0.51 waited for and
// redirected; no wait comes first.
func TestV074V03ForeignMinStrict(t *testing.T) {
	t.Parallel()
	w := setup(t)
	s := startSvc(t, w.c, svcOpts{db: filepath.Join(t.TempDir(), "i.db"), ns: []string{"matches", "schemas"}, minWait: time.Minute})
	w.doc(t, "derby", w.match, map[string]any{"title": "The Derby"})
	at := s.caughtUp("matches")
	sch := s.caughtUp("schemas")
	start := time.Now()
	for _, u := range []string{"/matches?q=derby&min=schemas:" + sch, "/matches/at/" + at + "?q=derby&min=schemas:" + sch,
		"/matches?q=derby&min=matches:" + at + "&min=schemas:" + sch} {
		r := s.raw(u, "")
		if r.status != 400 || r.body["code"] != "bad_input" || fmt.Sprint(r.body["min"]) != fmt.Sprint([]string{"schemas:" + sch}) {
			t.Errorf("%s: %d %v, want 400 listing schemas:%s", u, r.status, r.body, sch)
		}
	}
	if d := time.Since(start); d > 10*time.Second {
		t.Errorf("waited %s before refusing", d)
	}
	if r := s.raw("/matches?q=derby&min=matches:"+at, ""); r.status != 302 {
		t.Errorf("a min of matches: %d %v", r.status, r.body)
	}
}
