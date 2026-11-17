package index

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
)

// SERVICES §B.11.9 Where (v0.85): "A service learns whether
// authentication is on from the origin's GET / (§7), reusing a successful
// read for at most a minute and none once a later read has failed." With
// a CheckerTTL of ten minutes a read is still reused for a minute at
// most; a read that fails is an error, and the next one asks again, never
// answering from the read before it.
func TestV085AuthOffReuse(t *testing.T) {
	var hits, fail atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if fail.Load() != 0 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"origin":"https://cms.example","spec":"0.85","auth":"disabled"}`))
	}))
	defer srv.Close()
	c, err := client.New(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	ix := &Index{c: c}
	ix.opt.CheckerTTL = 10 * time.Minute
	ctx := context.Background()
	ask := func(want int64, what string) (bool, error) {
		t.Helper()
		off, err := ix.authOff(ctx)
		if got := hits.Load(); got != want {
			t.Fatalf("%s: %d reads of the root, want %d", what, got, want)
		}
		return off, err
	}
	if off, err := ask(1, "the first"); err != nil || !off {
		t.Fatalf("the first read: %v %v", off, err)
	}
	if off, err := ask(1, "within the minute"); err != nil || !off {
		t.Fatalf("reused: %v %v", off, err)
	}
	ix.auth.mu.Lock()
	ix.auth.at = time.Now().Add(-61 * time.Second)
	ix.auth.mu.Unlock()
	if off, err := ask(2, "a minute later"); err != nil || !off {
		t.Fatalf("read again: %v %v", off, err)
	}
	ix.auth.mu.Lock()
	ix.auth.at = time.Now().Add(-61 * time.Second)
	ix.auth.mu.Unlock()
	fail.Store(1)
	before := hits.Load()
	if _, err := ix.authOff(ctx); err == nil {
		t.Fatal("a failed read of the root gave an answer")
	}
	if hits.Load() == before {
		t.Fatal("the root wasn't read")
	}
	n := hits.Load()
	if _, err := ix.authOff(ctx); err == nil || hits.Load() == n {
		t.Fatalf("after a failed read: err %v, reads %d (were %d): want another read, and its failure", err, hits.Load(), n)
	}
}
