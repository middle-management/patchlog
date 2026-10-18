package client_test

import (
	"context"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
)

// The reference extensions (README) as the client surfaces them: a
// document's Modified (Last-Modified) and Digest (Repr-Digest), and a
// /heads entry's Created, Size and Digest, which match the document's
// bytes (ReprDigest); a tombstone's entry has Created only. In a sealed
// namespace the entries have no Size or Digest, and a document no Digest
// (the header would describe the JWE), though Modified is set.
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
		if !d.Modified.Equal(tm.Truncate(time.Second)) {
			t.Fatalf("%s: Modified %v, created %s", ns, d.Modified, created)
		}
		it := items["a"]
		if it.Target != a.ID || it.Created != created {
			t.Fatalf("%s: entry %+v, created %s", ns, it, created)
		}
		if ns == "p" {
			if d.Digest == "" || d.Digest != client.ReprDigest(d.Raw) || it.Digest != d.Digest || it.Size != int64(len(d.Raw)) {
				t.Fatalf("plain: doc digest %q, entry %+v, %d bytes %s", d.Digest, it, len(d.Raw), client.ReprDigest(d.Raw))
			}
		} else if d.Digest != "" || it.Digest != "" || it.Size != 0 {
			t.Fatalf("sealed: doc digest %q, entry %+v", d.Digest, it)
		}
		if bi := items["b"]; bi.Kind != "tombstone" || bi.Target != bt.ID || bi.Created == "" || bi.Size != 0 || bi.Digest != "" {
			t.Fatalf("%s: tombstone %+v", ns, bi)
		}
	}
}
