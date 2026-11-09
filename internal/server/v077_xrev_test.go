package server

import "testing"

// Cross-review, security scenario Encryption 71 (§E.2.2 Epochs, §2.1): a
// sealed namespace's blob whose referencing revisions have no epoch yet.
// At epoch 1, refused requests for it: a GET …/blob/{bid} by a caller
// without read (404), a Blob-From copy into a public target, which ranks
// lower (404), and one by a caller without read on the source (404).
// After a rotation to 2, a reader's GET …/blob/{bid} redirects to epoch
// 2: a refused request fixes no epoch.
func TestV077XrevRefusedFixesNoBlobEpoch(t *testing.T) {
	t.Parallel()
	p := newProtectionEnv(t, map[string]map[string]any{"s": {"read": "grant"}, "pub": {"read": "public"}, "t": {"read": "grant"}})
	get := p.blobIn("s", "a", []byte("bytes asked for without read"))
	ranks := p.blobIn("s", "b", []byte("bytes copied into a public target"))
	noread := p.blobIn("s", "c", []byte("bytes copied without read on the source"))
	expect(t, p.patchNS("s", ops(op("add", "/encryption", map[string]any{"level": "sealed"})), p.star), 201)

	blind := p.grant(p.k, "user:blind", []string{"s"}, []string{"create"}, p.long)
	expectCode(t, p.get(blobPath("s", "a", get), blind), 404, "not_found")
	w := p.grant(p.k, "user:w", []string{"s", "pub"}, []string{"read", "create", "append"}, p.long)
	expect(t, p.copyBlob("pub", "x", ranks, blobPath("s", "b", ranks), "", w), 404)
	tw := p.grant(p.k, "user:tw", []string{"t"}, []string{"read", "create", "append"}, p.long)
	expect(t, p.copyBlob("t", "x", noread, blobPath("s", "c", noread), "", tw), 404)

	p.rotate("s", 2)
	rd := p.grant(p.k, "user:rd", []string{"s"}, []string{"read"}, p.long)
	for _, b := range []struct{ name, bid string }{{"a", get}, {"b", ranks}, {"c", noread}} {
		g := p.get(blobPath("s", b.name, b.bid), rd)
		expect(t, g, 302)
		if want := blobPath("s", b.name, b.bid) + "/e/2"; g.H.Get("Location") != want {
			t.Errorf("%s: redirect to %q, want %q: a refused request fixed an epoch", b.name, g.H.Get("Location"), want)
		}
	}
}
