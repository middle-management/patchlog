package tree_test

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/lifecycle"
)

// A ?min= wait ends at once when the server stops (lifecycle.Stopping),
// with the answer a wait that ran out gets.
func TestMinWaitEndsOnShutdown(t *testing.T) {
	w := setup(t)
	w.seed(t)
	x := startSvc(t, w.c, svcOpts{})
	x.caughtUp("cat", "matches")
	x.cancel() // the followers stop: min is never reached
	<-x.done
	must(w.c.CreateDoc(context.Background(), "matches", "late", map[string]any{"title": "late"}))
	nsHead := must(w.c.NSHead(context.Background(), "matches")).ID

	stop := make(chan struct{})
	req := httptest.NewRequest("GET", "/cat/roots?min=matches:"+nsHead, nil)
	req = req.WithContext(lifecycle.WithStopping(context.Background(), stop))
	rec := httptest.NewRecorder()
	done := make(chan struct{})
	start := time.Now()
	go func() { x.s.Handler().ServeHTTP(rec, req); close(done) }()
	close(stop)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("min wait still running after shutdown")
	}
	// MinWait is 2 s in these tests.
	if d := time.Since(start); d > time.Second {
		t.Fatalf("took %s", d)
	}
	if rec.Code != 503 {
		t.Fatalf("answer: %d %v %s", rec.Code, rec.Header(), rec.Body)
	}
}
