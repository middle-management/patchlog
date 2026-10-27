package client_test

import (
	"context"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
)

// Head tells a purged namespace from a purged resource (§8.3, §8.5): every
// name of a purged namespace is 410 purged with head, its purge-ns entry,
// which Head.PurgedNS gives; a resource purged on its own has none.
func TestV073HeadPurgedNamespace(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{})
	c := s.Client(t, client.WithAuthor("alice"))
	must(c.CreateNamespace(ctx, "main", map[string]any{"read": "public"}))
	w := must(c.CreateDoc(ctx, "main", "a", map[string]any{"n": 0}))
	must(c.Purge(ctx, "main", "a", w.ID, false))
	if h := must(c.Head(ctx, "main", "a")); h.State != client.Purged || h.PurgedNS != "" {
		t.Fatalf("purged resource: %+v", h)
	}
	nh := must(c.NSHead(ctx, "main"))
	must(c.PatchConfig(ctx, "main", nh.Config, ops(op("add", "/frozen", true))))
	pid := must(c.PurgeNamespace(ctx, "main", must(c.NSHead(ctx, "main")).ID))
	for _, name := range []string{"a", "never"} {
		if h := must(c.Head(ctx, "main", name)); h.State != client.Purged || h.PurgedNS != pid {
			t.Errorf("%s in a purged namespace: %+v (want PurgedNS %s)", name, h, pid)
		}
	}
}
