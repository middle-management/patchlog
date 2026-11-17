package server

import (
	"testing"

	"github.com/middle-management/patchlog/internal/seal"
)

// v0.85 §7.1 table, …/raw (HTTP-16; E2E scenario 78): in a sealed or
// end-to-end namespace a tombstoned resource's …/raw and its tombstone's
// …/rev/{T}/raw answer 404 not_offered to a reader, "whatever the
// document URL would answer", which here is the 410 that names last. A
// caller failing the read check gets that check's answer. (A purge's 410
// still comes first, §8.3, §8.5: TestRawNotOffered,
// TestV073RawOfPurgedSealedResource.)
func TestV085RawOfTombstoneNotOffered(t *testing.T) {
	t.Parallel()
	e := newSealedAuthEnv(t, withBlobTuning)
	k := newKey("admin")
	e.mkNS("s", sealedDoc(map[string]any{"keys": []any{k.entry("*")}}))
	admin := e.grant(k, "user:root", []string{"s"}, allVerbs)
	reader := e.grant(k, "user:r", []string{"s"}, []string{"read"})
	other := e.grant(k, "user:o", []string{"s"}, []string{"read"}, map[string]any{"rules": []any{
		map[string]any{"op": "test", "path": "/resource", "value": "b"}}})
	d1 := e.wr("s", "derby", "", withNonce(addRoot(map[string]any{"n": 1.0})), admin)
	tomb := e.del("s", "derby", d1, admin)

	f := newE2E(t)
	key := seal.NewKey()
	e1 := etagOf(f.writeRaw("e", "derby", "", sealed(t, key, "e#1", "e", "derby", "", addRoot(map[string]any{"n": 1.0})), f.writerG))
	etomb := f.del("e", "derby", e1, f.writerG)

	for _, c := range []struct {
		what           string
		e              *tenv
		ns, tomb, last string
		reader, other  string
	}{
		{"sealed", e, "s", tomb, d1, reader, other},
		{"e2e", f.tenv, "e", etomb, e1, f.readerG, ""},
	} {
		doc := "/r/" + c.ns + "/derby"
		// The document URLs: the tombstone's 410, with last.
		for _, p := range []string{doc, doc + "/rev/" + c.tomb} {
			r := c.e.get(p, c.reader)
			expectCode(t, r, 410, "gone")
			if r.Obj()["tombstone"] != c.tomb || r.Obj()["last"] != c.last {
				t.Fatalf("%s: GET %s: %s", c.what, p, r.Body)
			}
		}
		// Their raw URLs: not offered, never that 410.
		for _, p := range []string{doc + "/raw", doc + "/rev/" + c.tomb + "/raw"} {
			r := c.e.get(p, c.reader)
			expectCode(t, r, 404, "not_offered")
			if _, has := r.Obj()["last"]; has || r.Obj()["tombstone"] != nil {
				t.Fatalf("%s: GET %s names the tombstone: %s", c.what, p, r.Body)
			}
			if h := c.e.do(req{method: "HEAD", path: p, bearer: c.reader}); h.Code != 404 || len(h.Body) != 0 {
				t.Fatalf("%s: HEAD %s: %d %q", c.what, p, h.Code, h.Body)
			}
			// The read check comes first.
			expectCode(t, c.e.get(p), 401, "unauthenticated")
			if c.other != "" {
				expectCode(t, c.e.get(p, c.other), 404, "not_found")
			}
		}
	}
}
