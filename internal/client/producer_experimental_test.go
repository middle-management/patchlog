package client_test

import (
	"context"
	"errors"
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
)

// lossy delivers every PATCH to the server and loses the answer of every
// third one: the client sees an error for a write that was made.
type lossy struct {
	next http.RoundTripper
	n    atomic.Int64
	lost atomic.Int64
}

var errLost = errors.New("answer lost")

func (l *lossy) RoundTrip(r *http.Request) (*http.Response, error) {
	res, err := l.next.RoundTrip(r)
	if err != nil || r.Method != http.MethodPatch || !containsPath(r.URL.Path, "/r/") {
		return res, err
	}
	if l.n.Add(1)%3 == 0 {
		res.Body.Close()
		l.lost.Add(1)
		return nil, errLost
	}
	return res, nil
}

func containsPath(p, s string) bool { return len(p) >= len(s) && p[:len(s)] == s }

// appendAll makes n logical appends to hot/d's list from a stale head,
// each repeated until an answer arrives, and returns the list's length.
func appendAll(t *testing.T, withProducer bool) (items, lost int) {
	t.Helper()
	s := clienttest.New(t, clienttest.Options{ExperimentalRebase: true})
	ctx := context.Background()
	c := s.Client(t, client.WithAuthor("ed"))
	if _, err := c.CreateNamespace(ctx, "hot", map[string]any{"read": "public"}); err != nil {
		t.Fatal(err)
	}
	base, err := c.CreateDoc(ctx, "hot", "d", map[string]any{"list": []any{}})
	if err != nil {
		t.Fatal(err)
	}
	l := &lossy{}
	wc := s.Client(t, client.WithAuthor("w"), client.WithTransport(func(next http.RoundTripper) http.RoundTripper { l.next = next; return l }))
	const n = 12 // under the default burst of 20 writes
	for i := 0; i < n; i++ {
		opts := []client.WriteOption{client.WithExperimentalRebase()}
		if withProducer {
			opts = append(opts, client.WithExperimentalProducer("p1", 0, int64(i)))
		}
		for attempt := 0; ; attempt++ {
			// Always from the first head: every write but the first is rebased.
			_, err := wc.Append(ctx, "hot", "d", base.ID, rbOp("add", "/list/-", i), opts...)
			if err == nil {
				break
			}
			if !errors.Is(err, errLost) || attempt > 5 {
				t.Fatalf("append %d: %v", i, err)
			}
		}
	}
	_, d, err := c.Load(ctx, "hot", "d")
	if err != nil {
		t.Fatal(err)
	}
	return len(d.Value.(map[string]any)["list"].([]any)), int(l.lost.Load())
}

// A rebased write repeated after a lost answer is applied again; with a
// producer key it is written once.
func TestExperimentalProducerMakesRetriesSafe(t *testing.T) {
	t.Parallel()
	const n = 12
	items, lost := appendAll(t, false)
	if lost == 0 || items != n+lost {
		t.Fatalf("without a producer key: %d items after %d lost answers, expected every repeat applied again (%d)", items, lost, n+lost)
	}
	items, lost = appendAll(t, true)
	if lost == 0 || items != n {
		t.Fatalf("with a producer key: %d items after %d lost answers, want %d", items, lost, n)
	}
}

func TestExperimentalProducerRules(t *testing.T) {
	t.Parallel()
	s := clienttest.New(t, clienttest.Options{ExperimentalRebase: true})
	ctx := context.Background()
	c := s.Client(t, client.WithAuthor("ed"))
	if _, err := c.CreateNamespace(ctx, "hot", map[string]any{"read": "public"}); err != nil {
		t.Fatal(err)
	}
	base, err := c.CreateDoc(ctx, "hot", "d", map[string]any{"list": []any{}, "n": 0})
	if err != nil {
		t.Fatal(err)
	}
	rb := client.WithExperimentalRebase()
	put := func(epoch, seq int64, v int) (*client.WriteResult, int) {
		w, err := c.Append(ctx, "hot", "d", base.ID, rbOp("add", "/list/-", v), rb, client.WithExperimentalProducer("p", epoch, seq))
		if ae, ok := client.AsAPIError(err); ok {
			return nil, ae.Status
		}
		if err != nil {
			t.Fatal(err)
		}
		return w, w.Status
	}
	if _, st := put(0, 1, 0); st != 400 {
		t.Errorf("a first write with seq 1: %d, want 400", st)
	}
	w0, st := put(0, 0, 0)
	if st != 201 {
		t.Fatalf("seq 0: %d", st)
	}
	if again, st := put(0, 0, 99); st != 200 || again.ID != w0.ID {
		t.Errorf("seq 0 again: %d %+v, want 200 with %s", st, again, w0.ID)
	}
	if _, st := put(0, 2, 2); st != 409 {
		t.Errorf("a gap: %d, want 409", st)
	}
	if _, st := put(0, 1, 1); st != 201 {
		t.Errorf("seq 1: %d", st)
	}
	if _, st := put(0, 0, 0); st != 204 {
		t.Errorf("an older seq: %d, want 204", st)
	}
	// A write that is refused doesn't use up its seq.
	_, err = c.Append(ctx, "hot", "d", base.ID, []any{map[string]any{"op": "remove", "path": "/nope"}}, rb, client.WithExperimentalProducer("p", 0, 2))
	if ae, ok := client.AsAPIError(err); !ok || ae.Status != 422 {
		t.Fatalf("a patch that doesn't apply: %v", err)
	}
	if _, st := put(0, 2, 2); st != 201 {
		t.Errorf("seq 2 after its refusal: %d", st)
	}
	// A new epoch starts at 0, and the old one is then refused.
	if _, st := put(1, 0, 3); st != 201 {
		t.Errorf("epoch 1: %d", st)
	}
	if _, st := put(0, 3, 4); st != 403 {
		t.Errorf("the old epoch: %d, want 403", st)
	}
	_, d, _ := c.Load(ctx, "hot", "d")
	if l := d.Value.(map[string]any)["list"].([]any); len(l) != 4 {
		t.Errorf("list %v, want 4 items", l)
	}
}
