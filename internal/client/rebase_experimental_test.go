package client_test

import (
	"context"
	"encoding/json"
	"sync"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
)

func rbOp(o, path string, v any) []any {
	return []any{map[string]any{"op": o, "path": path, "value": v}}
}

// The experimental rebase: a stale append is applied to the head when
// nothing written since overlaps what it touches, and is a 412 otherwise.
func TestExperimentalRebase(t *testing.T) {
	t.Parallel()
	s := clienttest.New(t, clienttest.Options{ExperimentalRebase: true})
	ctx := context.Background()
	c := s.Client(t, client.WithAuthor("ed"))
	if _, err := c.CreateNamespace(ctx, "hot", map[string]any{"read": "public"}); err != nil {
		t.Fatal(err)
	}
	base, err := c.CreateDoc(ctx, "hot", "d", map[string]any{"a": 1, "b": 1, "list": []any{}, "rows": []any{map[string]any{"n": 1}}})
	if err != nil {
		t.Fatal(err)
	}
	rb := client.WithExperimentalRebase()
	stale := func(err error) bool { ae, ok := client.AsAPIError(err); return ok && ae.Status == 412 }
	doc := func() map[string]any {
		_, d, err := c.Load(ctx, "hot", "d")
		if err != nil {
			t.Fatal(err)
		}
		return d.Value.(map[string]any)
	}

	// Someone else writes /a.
	h1, err := c.Append(ctx, "hot", "d", base.ID, rbOp("replace", "/a", 2))
	if err != nil {
		t.Fatal(err)
	}
	// Without the header a stale write is a 412, as ever.
	if _, err := c.Append(ctx, "hot", "d", base.ID, rbOp("replace", "/b", 2)); !stale(err) {
		t.Fatalf("plain stale write: %v", err)
	}
	// A different member: rebased, and the result holds both changes.
	w, err := c.Append(ctx, "hot", "d", base.ID, rbOp("replace", "/b", 2), rb)
	if err != nil {
		t.Fatalf("disjoint: %v", err)
	}
	if w.ID == h1.ID || w.Entry == nil {
		t.Fatalf("result %+v", w)
	}
	if d := doc(); d["a"] != json.Number("2") && d["a"] != float64(2) && d["a"] != int64(2) {
		t.Fatalf("a = %v (%T)", d["a"], d["a"])
	}
	h, _ := c.Head(ctx, "hot", "d")
	if h.ID != w.ID {
		t.Fatalf("head %s, want the rebased %s", h.ID, w.ID)
	}
	// The same member: 412. A test on it too, and a copy from it.
	for name, p := range map[string][]any{
		"same path":   rbOp("replace", "/a", 3),
		"parent path": rbOp("replace", "", map[string]any{}),
		"test":        {map[string]any{"op": "test", "path": "/a", "value": 1}, map[string]any{"op": "add", "path": "/c", "value": 1}},
		"copy from":   {map[string]any{"op": "copy", "from": "/a", "path": "/c"}},
	} {
		if _, err := c.Append(ctx, "hot", "d", base.ID, p, rb); !stale(err) {
			t.Errorf("%s: %v, want 412", name, err)
		}
	}
	// Appends to one array from the same base all land.
	cur := w.ID
	for i := 0; i < 3; i++ {
		if _, err := c.Append(ctx, "hot", "d", cur, rbOp("add", "/list/-", i), rb); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	if l := doc()["list"].([]any); len(l) != 3 {
		t.Fatalf("list %v", l)
	}
	// An index into an array counts as the whole array: against appends,
	// and against another element.
	if _, err := c.Append(ctx, "hot", "d", cur, rbOp("replace", "/list/0", 9), rb); !stale(err) {
		t.Errorf("index after appends: %v, want 412", err)
	}
	h, _ = c.Head(ctx, "hot", "d")
	if _, err := c.Append(ctx, "hot", "d", h.ID, rbOp("replace", "/rows/0/n", 2)); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Append(ctx, "hot", "d", h.ID, rbOp("add", "/rows/-", map[string]any{"n": 3}), rb); !stale(err) {
		t.Errorf("append after an element write: %v, want 412", err)
	}
	// A rebased write still fails its own checks on the result.
	h, _ = c.Head(ctx, "hot", "d")
	if _, err := c.Append(ctx, "hot", "d", h.ID, rbOp("replace", "/a", 5)); err != nil {
		t.Fatal(err)
	}
	_, err = c.Append(ctx, "hot", "d", h.ID, []any{map[string]any{"op": "remove", "path": "/nope"}}, rb)
	if ae, ok := client.AsAPIError(err); !ok || ae.Status != 422 {
		t.Errorf("a patch that doesn't apply: %v, want 422", err)
	}
	// A delete is never rebased, and an id that isn't an ancestor is a 412.
	if _, err := c.Append(ctx, "hot", "d", h1.ID[:len(h1.ID)-1]+"a", rbOp("replace", "/b", 7), rb); err == nil {
		t.Error("an unknown If-Match was accepted")
	}
}

// Off by default: the header changes nothing.
func TestExperimentalRebaseOff(t *testing.T) {
	t.Parallel()
	s := clienttest.New(t, clienttest.Options{})
	ctx := context.Background()
	c := s.Client(t, client.WithAuthor("ed"))
	if _, err := c.CreateNamespace(ctx, "hot", map[string]any{"read": "public"}); err != nil {
		t.Fatal(err)
	}
	base, _ := c.CreateDoc(ctx, "hot", "d", map[string]any{"a": 1, "b": 1})
	if _, err := c.Append(ctx, "hot", "d", base.ID, rbOp("replace", "/a", 2)); err != nil {
		t.Fatal(err)
	}
	_, err := c.Append(ctx, "hot", "d", base.ID, rbOp("replace", "/b", 2), client.WithExperimentalRebase())
	if ae, ok := client.AsAPIError(err); !ok || ae.Status != 412 {
		t.Fatalf("%v, want 412", err)
	}
}

// Writers of one document that each own a member all get every write in.
func TestExperimentalRebaseConcurrent(t *testing.T) {
	t.Parallel()
	s := clienttest.New(t, clienttest.Options{ExperimentalRebase: true})
	ctx := context.Background()
	c := s.Client(t, client.WithAuthor("ed"))
	if _, err := c.CreateNamespace(ctx, "hot", map[string]any{"read": "public"}); err != nil {
		t.Fatal(err)
	}
	init := map[string]any{"list": []any{}}
	const writers, each = 6, 3
	for k := 0; k < writers; k++ {
		init["w"+string(rune('a'+k))] = 0
	}
	base, err := c.CreateDoc(ctx, "hot", "d", init)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errs := make(chan error, writers*each*2)
	for k := 0; k < writers; k++ {
		wg.Add(1)
		go func(k int) {
			defer wg.Done()
			wc := s.Client(t, client.WithAuthor("w"+string(rune('a'+k))))
			mine := base.ID
			for i := 1; i <= each; i++ {
				p := []any{map[string]any{"op": "replace", "path": "/w" + string(rune('a'+k)), "value": i}, map[string]any{"op": "add", "path": "/list/-", "value": k*10 + i}}
				w, err := wc.AppendLatest(ctx, "hot", "d", mine, client.Backoff{}, func(string) (any, error) { return p, nil }, client.WithExperimentalRebase())
				if err != nil {
					errs <- err
					return
				}
				mine = w.ID
			}
		}(k)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	_, d, err := c.Load(ctx, "hot", "d")
	if err != nil {
		t.Fatal(err)
	}
	m := d.Value.(map[string]any)
	if l := m["list"].([]any); len(l) != writers*each {
		t.Fatalf("%d list items, want %d", len(l), writers*each)
	}
	for k := 0; k < writers; k++ {
		if b, _ := json.Marshal(m["w"+string(rune('a'+k))]); string(b) != "3" {
			t.Errorf("writer %d's member is %s", k, b)
		}
	}
}

// A rebased write is validated on the head it lands on: two writes that are
// each valid on their base and touch nothing in common can still break the
// schema together, and the second is then a 422, not a 412. A dependency
// the schema doesn't express is protected by a test op, whose path counts
// as touched.
func TestExperimentalRebaseValidatesOnHead(t *testing.T) {
	t.Parallel()
	s := clienttest.New(t, clienttest.Options{ExperimentalRebase: true})
	ctx := context.Background()
	c := s.Client(t, client.WithAuthor("ed"))
	if _, err := c.CreateNamespace(ctx, "hot", map[string]any{"read": "public"}); err != nil {
		t.Fatal(err)
	}
	sw, err := c.CreateDoc(ctx, "hot", "schema", map[string]any{
		"$schema": "https://json-schema.org/draft/2020-12/schema",
		"type":    "object",
		"properties": map[string]any{
			"list":  map[string]any{"type": "array", "maxItems": 2},
			"start": map[string]any{"type": "integer"},
			"end":   map[string]any{"type": "integer"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	base, err := c.CreateDoc(ctx, "hot", "d", map[string]any{"$schema": "/r/hot/schema/rev/" + sw.ID, "list": []any{1}, "start": 1, "end": 5})
	if err != nil {
		t.Fatal(err)
	}
	rb := client.WithExperimentalRebase()
	status := func(err error) int {
		if ae, ok := client.AsAPIError(err); ok {
			return ae.Status
		}
		return 0
	}

	// Valid alone, invalid together: both append a second item from the
	// same base; the list may hold two.
	first, err := c.Append(ctx, "hot", "d", base.ID, rbOp("add", "/list/-", 2), rb)
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Append(ctx, "hot", "d", base.ID, rbOp("add", "/list/-", 3), rb)
	if status(err) != 422 {
		t.Fatalf("a third item past maxItems: %v, want 422", err)
	}
	if h, _ := c.Head(ctx, "hot", "d"); h.ID != first.ID {
		t.Fatalf("the refused write moved the head to %s", h.ID)
	}
	// The refusal holds nobody up: a write behind it still lands.
	if _, err := c.Append(ctx, "hot", "d", base.ID, rbOp("replace", "/start", 2), rb); err != nil {
		t.Fatalf("a valid write after the refused one: %v", err)
	}

	// An invariant the schema doesn't hold (start < end): one writer moved
	// start to 2 above; another, from the same base, sets end to 2.
	// Untested, the two rebase into start = end.
	if _, err := c.Append(ctx, "hot", "d", base.ID, rbOp("replace", "/end", 2), rb); err != nil {
		t.Fatalf("untested dependent write: %v", err)
	}
	_, d, err := c.Load(ctx, "hot", "d")
	if err != nil {
		t.Fatal(err)
	}
	m := d.Value.(map[string]any)
	if sb, _ := json.Marshal(m["start"]); string(sb) != "2" {
		t.Fatalf("start = %s", sb)
	}
	if eb, _ := json.Marshal(m["end"]); string(eb) != "2" {
		t.Fatalf("end = %s", eb)
	}
	// With a test on what it depends on, the same write is a 412: start
	// changed since its base.
	guarded := []any{
		map[string]any{"op": "test", "path": "/start", "value": 1},
		map[string]any{"op": "replace", "path": "/end", "value": 3},
	}
	if _, err := c.Append(ctx, "hot", "d", base.ID, guarded, rb); status(err) != 412 {
		t.Fatalf("a write that tests a value changed since its base: %v, want 412", err)
	}
	// A test on a member nobody wrote since is judged on the head and
	// passes.
	h, _ := c.Head(ctx, "hot", "d")
	if _, err := c.Append(ctx, "hot", "d", h.ID, rbOp("replace", "/end", 9)); err != nil {
		t.Fatal(err)
	}
	ok := []any{
		map[string]any{"op": "test", "path": "/start", "value": 2},
		map[string]any{"op": "add", "path": "/note", "value": "x"},
	}
	if _, err := c.Append(ctx, "hot", "d", h.ID, ok, rb); err != nil {
		t.Fatalf("a test on an untouched member: %v", err)
	}
}
