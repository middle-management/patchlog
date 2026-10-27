package bundle_test

import (
	"bytes"
	"testing"

	"github.com/middle-management/patchlog/internal/bundle"
	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/ids"
)

// §C.3.1 (GR-37): the 86-character <sig> binds request input only. A
// server at v0.55 stored an unlisted kid's signature unverified whatever
// its length, so in a full-history bundle such a revision stays
// unverifiable, not a broken link; a short sig by a listed kid still fails
// to verify.
func TestV073StoredShortSignature(t *testing.T) {
	t.Parallel()
	nsKey := clienttest.NewKey("ns-key")
	bot := signerKey(t, "bot-1", 1)
	g := mint(t, nsKey.Priv, nsKey.Kid, "alice", bot)
	gid := g.ID().String()
	for _, c := range []struct {
		sig  string
		want bundle.SigStatus
	}{
		{"Ed25519:other:AAAA", bundle.SigUnverifiable},
		{"Ed25519:bot-1:AAAA", bundle.SigFailed},
	} {
		b := writeHistory(t, "matches", "derby", func(w *bundle.Writer) ids.ID {
			noErr(t, w.Line(grantLine(t, "matches", g, keyEntryOf(nsKey))))
			l, id := history(t, "matches", "derby", nil, client.GenesisPatches(map[string]any{"n": 1}),
				func(*ids.ID, []byte) string { return c.sig }, gid)
			noErr(t, w.Line(l))
			return id
		})
		var results []bundle.SigResult
		if _, err := bundle.VerifyWith(ctx, bytes.NewReader(b), bundle.VerifyOptions{OnSignature: func(r bundle.SigResult) { results = append(results, r) }}); err != nil {
			t.Fatal(err)
		}
		if len(results) != 1 || results[0].Status != c.want {
			t.Errorf("%s: results %+v, want one %s", c.sig, results, c.want)
		}
	}
}
