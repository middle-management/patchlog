package index_test

import (
	"context"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/lifecycle"
)

// A ?min= wait ends at once when the server stops (lifecycle.Stopping),
// with the answer a wait that ran out gets.
func TestMinWaitEndsOnShutdown(t *testing.T) {
	w := setup(t)
	s := startSvc(t, w.c, svcOpts{db: filepath.Join(t.TempDir(), "i.db"), ns: []string{"matches"}, minWait: 30 * time.Second})
	s.caughtUp("matches")
	s.cancel() // the follower stops: min is never reached
	<-s.done
	future := w.doc(t, "final", w.match, map[string]any{"title": "x"})

	stop := make(chan struct{})
	req := httptest.NewRequest("GET", "/matches?min="+future.NSID, nil)
	req = req.WithContext(lifecycle.WithStopping(context.Background(), stop))
	rec := httptest.NewRecorder()
	done := make(chan struct{})
	go func() { s.ix.Handler().ServeHTTP(rec, req); close(done) }()
	time.Sleep(100 * time.Millisecond)
	select {
	case <-done:
		t.Fatalf("answered before shutdown: %d", rec.Code)
	default:
	}
	start := time.Now()
	close(stop)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("min wait still running after shutdown")
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("took %s", d)
	}
	if rec.Code != 503 || rec.Header().Get("Retry-After") == "" {
		t.Fatalf("answer: %d %v", rec.Code, rec.Header())
	}
}
