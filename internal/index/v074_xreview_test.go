package index_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
)

// §E.2.3, §A.4, §E.2.6 (v0.74 cross review): with authentication
// disabled, /keys gives the current epoch alone, so an index started after
// a sealed namespace was rotated (a new index, -rebuild, or v0.74's
// one-time format-2 rebuild) can't open the genesis namespace document or
// a document sealed under epoch 1. It still reaches the namespace: the
// namespace document at the head stands in for the genesis one (follow),
// a document it can't open is left out, and what it can open is indexed,
// instead of the follower starting over for ever and every query being
// 503 behind.
func TestV074FreshIndexAfterRotationAuthDisabled(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{KeyStore: keyStore(t), LongPoll: 150 * time.Millisecond})
	c := s.Client(t, client.WithAuthor("w"), client.WithKeys(client.NewKeys(nil)))
	must(c.CreateNamespace(ctx, "schemas", map[string]any{"read": "public"}))
	must(c.CreateNamespace(ctx, "p", map[string]any{"read": "public", "encryption": map[string]any{"level": "sealed"}}))
	sch := must(c.CreateDoc(ctx, "schemas", "item", map[string]any{"$schema": d2020, "type": "object",
		"properties": map[string]any{"title": map[string]any{"type": "string", "x-index": "text"}}}))
	must(createNonced(c, "p", "a", map[string]any{"$schema": "/r/schemas/item/rev/" + sch.ID, "title": "rotated a"}))
	s.Clock.Advance(time.Minute)
	must(s.Engine.RotateEpoch(ctx, "p", "system:rotate"))
	must(createNonced(c, "p", "b", map[string]any{"$schema": "/r/schemas/item/rev/" + sch.ID, "title": "rotated b"}))

	x := startSvc(t, c, svcOpts{db: filepath.Join(t.TempDir(), "i.db"), ns: []string{"p"}, now: s.Now})
	x.caughtUp("p")
	r := x.fetch("/p?q=rotated", "") // 200, not 503 behind
	hits, _ := decodeJSON(t, r.body)["hits"].([]any)
	if len(hits) != 1 || hits[0].(map[string]any)["resource"] != "b" {
		t.Fatalf("hits %v, want b's alone (a is sealed under an epoch the index gets no key for)", hits)
	}
}
