package client_test

import (
	"context"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
)

// §7.1 and §7.4 as the client surfaces them: a document's Modified
// (Last-Modified) and Digest (Repr-Digest), and a /heads entry's Created,
// Size and Digest, which match the document's bytes (ReprDigest); a
// tombstone's entry has Created only. In a sealed namespace the server
// sends none of them: Created and Digest are "", Size 0 and Modified zero.
func TestHeadMetaFields(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{KeyStore: keyStore(t)})
	c := s.Client(t, client.WithAuthor("alice")).With(client.WithKeys(client.NewKeys(nil)))
	must(c.CreateNamespace(ctx, "p", map[string]any{"read": "public"}))
	must(c.CreateNamespace(ctx, "s", map[string]any{"read": "public", "encryption": map[string]any{"level": "sealed"}}))
	for _, ns := range []string{"p", "s"} {
		a := must(c.Create(ctx, ns, "a", nonced(client.GenesisPatches(map[string]any{"n": "ü"}))))
		s.Clock.Advance(90 * time.Minute)
		a = must(c.Append(ctx, ns, "a", a.ID, nonced(ops(op("add", "/m", 1)))))
		b := must(c.Create(ctx, ns, "b", nonced(client.GenesisPatches(map[string]any{}))))
		bt := must(c.Delete(ctx, ns, "b", b.ID))
		items := map[string]client.HeadItem{}
		for _, it := range must(c.Heads(ctx, ns, must(c.NSHead(ctx, ns)).ID)) {
			items[it.Resource] = it
		}
		d := must(c.Doc(ctx, ns, "a", a.ID))
		lg := must(c.Log(ctx, ns, "a", a.ID, ""))
		created := lg[len(lg)-1].Created
		tm, err := time.Parse(time.RFC3339Nano, created)
		if err != nil {
			t.Fatal(err)
		}
		it, bi := items["a"], items["b"]
		if it.Target != a.ID || bi.Kind != "tombstone" || bi.Target != bt.ID || bi.Size != 0 || bi.Digest != "" {
			t.Fatalf("%s: entries %+v %+v", ns, it, bi)
		}
		if ns == "p" {
			if !d.Modified.Equal(tm.Truncate(time.Second)) || it.Created != created || bi.Created == "" {
				t.Fatalf("plain: Modified %v, entries %+v %+v, created %s", d.Modified, it, bi, created)
			}
			if d.Digest == "" || d.Digest != client.ReprDigest(d.Raw) || it.Digest != d.Digest || it.Size != int64(len(d.Raw)) {
				t.Fatalf("plain: doc digest %q, entry %+v, %d bytes %s", d.Digest, it, len(d.Raw), client.ReprDigest(d.Raw))
			}
		} else if !d.Modified.IsZero() || d.Digest != "" || it.Created != "" || it.Digest != "" || it.Size != 0 || bi.Created != "" {
			t.Fatalf("sealed: Modified %v, doc digest %q, entries %+v %+v", d.Modified, d.Digest, it, bi)
		}
	}
}
