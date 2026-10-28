package tree_test

import (
	"context"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/keystore"
)

// §E.2.3, §E.2.6 (v0.74 cross review): with authentication disabled,
// /keys gives the current epoch alone, so a tree service started after
// its sealed catalog was rotated can't open the catalog's genesis
// namespace document, nor a node sealed under epoch 1. It still reaches
// the catalog: the namespace document at the head stands in for the
// genesis one (follow), a node it can't open is left out, and the nodes
// it can open are listed, instead of the follower starting over for ever
// and every listing being 503 behind.
func TestV074FreshTreeAfterRotationAuthDisabled(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{KeyStore: must(keystore.New(keystore.Generate())), LongPoll: 150 * time.Millisecond})
	c := s.Client(t, client.WithAuthor("w"), client.WithKeys(client.NewKeys(nil)))
	must(c.CreateNamespace(ctx, "cat", map[string]any{"read": "public",
		"encryption": map[string]any{"level": "sealed"}, "catalog": map[string]any{"trust": []any{}, "mode": "tree"}}))
	createNonced(t, c, "cat", "old", map[string]any{"title": "Old", "parents": []any{}})
	s.Clock.Advance(time.Minute)
	must(s.Engine.RotateEpoch(ctx, "cat", "system:rotate"))
	createNonced(t, c, "cat", "fresh", map[string]any{"title": "Fresh", "parents": []any{}})

	x := startSvc(t, c, svcOpts{now: s.Now})
	x.caughtUp("cat")
	r := x.fetch("/cat/roots", "") // 200, not 503 behind
	var names []string
	roots, _ := decode(t, r.body)["roots"].([]any)
	for _, e := range roots {
		names = append(names, e.(map[string]any)["name"].(string))
	}
	if len(names) != 1 || names[0] != "fresh" {
		t.Fatalf("roots %v, want fresh alone (old is sealed under an epoch the service gets no key for): %s", names, r.body)
	}
}
