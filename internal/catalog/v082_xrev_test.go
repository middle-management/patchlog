package catalog_test

import (
	"context"
	"regexp"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/tree"
)

// Scenario 128, SVC-21 (SERVICES §B.5 Behind:
// "It leaves the combined checkpoint, so at moves when the service stops
// and when it resumes following it"): the at a listing redirects to is
// another one once the service stops following matches, with nothing
// else written, and another again once it follows it again. Here the
// stop and the resume are each caused by a config entry of matches (its
// first key removed, then added again), which the service can't apply
// while stopped; a resume with nothing written at all is
// TestV082XrevAtMovesAcrossStopNothingWritten in internal/tree.
func TestV082XrevAtMovesOnStopAndResume(t *testing.T) {
	w := setup(t)
	w.seed()
	w.start()
	w.caughtUp()
	ctx := context.Background()
	fan := w.caller("user:fred", "fan-club")
	atRE := regexp.MustCompile(`/at/([^/?]+)/`)
	at := func() string {
		r := w.do("GET", "/cat/roots", fan, nil)
		if r.status != 302 {
			return ""
		}
		m := atRE.FindStringSubmatch(r.header.Get("Location"))
		if m == nil {
			t.Fatalf("Location %q", r.header.Get("Location"))
		}
		return m[1]
	}
	stopped := func() bool {
		st := false
		w.svc.Tree().View(func(g *tree.Graph, _ map[string]string) { st = g.Stopped("matches") })
		return st
	}
	// A second key keeps matches administrable; the at after that write
	// is the one to compare with.
	k2 := clienttest.NewKey("admin2")
	w.patchMatches(map[string]any{"op": "add", "path": "/keys/-", "value": k2.Entry("*")})
	admin2 := w.s.Client(t, client.WithBearer(k2.Grant(t, w.s.Now(), "user:admin2", []string{"matches"}, []string{"read", "config"})))
	w.caughtUp()
	before := at()
	if before == "" {
		t.Fatal("no listing before the stop")
	}
	cfg := must(admin2.NSHead(ctx, "matches"))
	keys := must(admin2.NSDoc(ctx, "matches", cfg.ID)).Value["keys"].([]any)
	must(admin2.PatchConfig(ctx, "matches", cfg.Config, []any{map[string]any{"op": "remove", "path": "/keys/0"}}))
	waitFor(t, "the service to stop following matches", stopped)
	during := at()
	t.Logf("before %s, stopped %s", before, during)
	if during == "" || during == before {
		t.Errorf("at once matches is stopped: %q, was %q: it didn't move", during, before)
	}
	must(admin2.PatchConfig(ctx, "matches", must(admin2.NSHead(ctx, "matches")).Config, []any{map[string]any{"op": "add", "path": "/keys/0", "value": keys[0]}}))
	waitFor(t, "the service to follow matches again", func() bool { return !stopped() })
	after := ""
	waitFor(t, "a listing after the resume", func() bool { after = at(); return after != "" })
	t.Logf("resumed %s", after)
	if after == during {
		t.Errorf("at once matches is followed again: %q, as while stopped: it didn't move", after)
	}
}
