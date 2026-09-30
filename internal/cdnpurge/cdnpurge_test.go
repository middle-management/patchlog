package cdnpurge

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// cdn records purge requests.
type cdn struct {
	mu      sync.Mutex
	batches [][]string
	methods []string
}

func (c *cdn) record(r *http.Request) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.batches = append(c.batches, strings.Fields(r.Header.Get("X-Purge-Tags")))
	c.methods = append(c.methods, r.Method)
}

func (c *cdn) tags() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []string
	for _, b := range c.batches {
		out = append(out, b...)
	}
	sort.Strings(out)
	return out
}

func quiet(string, ...any) {}

func closeNow(t *testing.T, p *Purger) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := p.Close(ctx); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestBatchingAndCoalescing(t *testing.T) {
	var c cdn
	gate := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-gate // hold the first request so the rest queue up
		c.record(r)
	}))
	defer srv.Close()
	p, err := New(Options{URLs: []string{srv.URL + "/"}, MaxTags: 3, Logf: quiet})
	if err != nil {
		t.Fatal(err)
	}
	p.PurgeTags([]string{"r:ns/first"})
	time.Sleep(50 * time.Millisecond) // the sender now waits on the gate
	for i := 0; i < 3; i++ {
		p.PurgeTags([]string{"ns:ns", "r:ns/a", "r:ns/b.c", "idx:ns", "r:ns/a"})
	}
	close(gate)
	closeNow(t, p)

	got := c.tags()
	want := []string{"idx:ns", "ns:ns", "r:ns/a", "r:ns/b.c", "r:ns/first"}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("tags %v, want %v (each once)", got, want)
	}
	for _, b := range c.batches {
		if len(b) > 3 {
			t.Fatalf("batch %v over MaxTags", b)
		}
	}
	if len(c.batches) != 3 { // [first], then 4 tags in 3+1
		t.Fatalf("batches %v", c.batches)
	}
	if c.methods[0] != "PURGE" {
		t.Fatalf("method %s", c.methods[0])
	}
}

func TestHeaderLengthChunking(t *testing.T) {
	var c cdn
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { c.record(r) }))
	defer srv.Close()
	p, _ := New(Options{URLs: []string{srv.URL}, MaxHeaderBytes: 40, Logf: quiet})
	var tags []string
	for i := 0; i < 30; i++ {
		tags = append(tags, "r:namespace/"+strings.Repeat("x", i%5)+string(rune('a'+i%26))+string(rune('a'+i/26)))
	}
	tags = append(tags, "r:ns/"+strings.Repeat("l", 60)) // longer than the limit: sent alone
	p.PurgeTags(tags)
	closeNow(t, p)
	if n := len(c.tags()); n != len(tags) {
		t.Fatalf("got %d tags, want %d", n, len(tags))
	}
	for _, b := range c.batches {
		if h := strings.Join(b, " "); len(h) > 40 && len(b) > 1 {
			t.Fatalf("header %q (%d bytes) over the limit", h, len(h))
		}
	}
}

func TestRetries(t *testing.T) {
	var c cdn
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) <= 2 {
			http.Error(w, "busy", http.StatusServiceUnavailable)
			return
		}
		c.record(r)
	}))
	defer srv.Close()
	p, _ := New(Options{URLs: []string{srv.URL}, Backoff: time.Millisecond, Logf: quiet})
	p.PurgeTags([]string{"r:ns/name"})
	closeNow(t, p)
	if got := c.tags(); len(got) != 1 || got[0] != "r:ns/name" || calls.Load() != 3 {
		t.Fatalf("tags %v after %d calls", got, calls.Load())
	}
}

func TestPermanentFailureNotRetried(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		http.Error(w, "not in ACL", http.StatusForbidden)
	}))
	defer srv.Close()
	var logged atomic.Int32
	p, _ := New(Options{URLs: []string{srv.URL}, Backoff: time.Millisecond, Logf: func(f string, a ...any) {
		if strings.Contains(f, "failed") {
			logged.Add(1)
		}
	}})
	p.PurgeTags([]string{"ns:x"})
	closeNow(t, p)
	if calls.Load() != 1 || logged.Load() != 1 {
		t.Fatalf("calls %d, failures logged %d", calls.Load(), logged.Load())
	}
}

func TestGivesUpAfterAttempts(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()
	p, _ := New(Options{URLs: []string{srv.URL}, Attempts: 3, Backoff: time.Millisecond, Logf: quiet})
	p.PurgeTags([]string{"ns:x"})
	closeNow(t, p)
	if calls.Load() != 3 {
		t.Fatalf("calls %d, want 3", calls.Load())
	}
}

// A CDN that is down (connection refused) or hangs never slows PurgeTags,
// and the queue stays bounded.
func TestNeverBlocks(t *testing.T) {
	hang := make(chan struct{})
	hanging := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-hang:
		case <-r.Context().Done():
		}
	}))
	defer hanging.Close()
	defer close(hang)
	down := httptest.NewServer(http.NotFoundHandler())
	downURL := down.URL
	down.Close()

	var dropped atomic.Int32
	p, err := New(Options{URLs: []string{hanging.URL, downURL}, QueueSize: 1000, Timeout: time.Hour,
		Logf: func(f string, a ...any) {
			if strings.Contains(f, "queue full") {
				dropped.Add(int32(a[1].(int)))
			}
		}})
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	for i := 0; i < 20000; i++ {
		p.PurgeTags([]string{"r:ns/" + string(rune('a'+i%26)) + strings.Repeat("x", i%50), "ns:ns"})
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("20000 PurgeTags took %v", d)
	}
	for _, tg := range p.targets {
		tg.mu.Lock()
		n := len(tg.pending)
		tg.mu.Unlock()
		if n > 1000 {
			t.Fatalf("queue %d over QueueSize", n)
		}
	}

	// Close gives up at its deadline, even with a request hanging.
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start = time.Now()
	if err := p.Close(ctx); err == nil {
		t.Fatal("Close succeeded with the CDN down")
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("Close took %v past its deadline", d)
	}
	p.PurgeTags([]string{"after:close"}) // doesn't panic or block
}

func TestShutdownFlush(t *testing.T) {
	var c cdn
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(20 * time.Millisecond)
		c.record(r)
	}))
	defer srv.Close()
	p, _ := New(Options{URLs: []string{srv.URL}, MaxTags: 1, Logf: quiet})
	want := []string{"ns:a", "ns:b", "ns:c", "ns:d", "ns:e"}
	p.PurgeTags(want)
	closeNow(t, p) // returns only once every tag was sent
	if got := c.tags(); strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("flushed %v, want %v", got, want)
	}
}

func TestMultipleURLs(t *testing.T) {
	var a, b cdn
	sa := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { a.record(r) }))
	defer sa.Close()
	sb := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { b.record(r) }))
	defer sb.Close()
	p, _ := New(Options{URLs: []string{sa.URL, sb.URL}, Method: "BAN", Logf: quiet})
	p.PurgeTags([]string{"ns:x"})
	closeNow(t, p)
	if len(a.tags()) != 1 || len(b.tags()) != 1 || a.methods[0] != "BAN" {
		t.Fatalf("a %v b %v", a.batches, b.batches)
	}
}

func TestBadURL(t *testing.T) {
	for _, u := range []string{"", "cdn:8080", "ftp://x/", "http://"} {
		if _, err := New(Options{URLs: []string{u}}); err == nil {
			t.Errorf("New(%q) succeeded", u)
		}
	}
	if _, err := New(Options{}); err == nil {
		t.Error("New without URLs succeeded")
	}
}
