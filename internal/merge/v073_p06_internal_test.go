package merge

import (
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
)

// §E.3.1 Declared blobs: a sealed op declares only blobs of the sealed type
// without a nonce.
func TestV073UndeclarableBlob(t *testing.T) {
	sealed := map[string]any{"$blob": "1aaa", "type": client.SealedBlobType, "size": 9.0,
		"sealed": map[string]any{"key": "k", "type": "image/png", "size": 3.0}}
	for _, c := range []struct {
		doc  any
		want string
	}{
		{map[string]any{"img": sealed}, ""},
		{map[string]any{"title": "x"}, ""},
		{map[string]any{"a": []any{sealed, map[string]any{"$blob": "1bbb", "type": "image/png", "size": 3.0, "nonce": "abcdefghijklmnopqrstuvwxyz"}}}, "1bbb"},
		{map[string]any{"img": map[string]any{"$blob": "1ccc", "type": client.SealedBlobType, "size": 9.0, "nonce": "abcdefghijklmnopqrstuvwxyz"}}, "1ccc with a nonce"},
		{map[string]any{"img": map[string]any{"$blob": "1ddd", "type": "image/png", "size": 3.0}}, `1ddd of type "image/png"`},
		// Schema documents hold no references (§7.8).
		{map[string]any{"$schema": "https://json-schema.org/draft/2020-12/schema", "x": map[string]any{"$blob": "1eee", "type": "image/png"}}, ""},
	} {
		got := undeclarableBlob(c.doc)
		if (c.want == "") != (got == "") || !strings.Contains(got, c.want) {
			t.Fatalf("%v: %q, want %q", c.doc, got, c.want)
		}
	}
}

// §F.3 kept bullet (v0.73): at E3 a resource kept at a live base head that
// references a blob a sealed op can't declare gets no item: it stays
// unmerged and is offered again, and the plan says why. One whose head
// references only declarable blobs is recorded with the sealed empty set.
func TestV073E3KeptUndeclarableBlobNoItem(t *testing.T) {
	for _, block := range []string{"", `blob 1ddd of type "image/png"`} {
		r := &Resource{Name: "derby", Class: Replay, Base: "1base", BaseState: client.Live.String(), IfMatch: "1base", keepBlock: block}
		r.conflict(ConflictOverlap, "both sides wrote", "/img")
		p := &Plan{Target: "m", Branch: "r7", TargetLevel: "e2e", Resources: []*Resource{r}}
		if err := p.Resolve("derby"); err != nil {
			t.Fatal(err)
		}
		if !p.Clean() || !r.Dropped {
			t.Fatalf("%q: %+v", block, r)
		}
		if block == "" {
			if !r.Kept || !r.HasItem() || r.IfMatch != "1base" || len(p.Items()) != 1 {
				t.Fatalf("kept without undeclarable blobs: %+v", r)
			}
			continue
		}
		if r.Kept || r.HasItem() || len(p.Items()) != 0 || r.IfMatch != "" {
			t.Fatalf("kept over an undeclarable blob has an item: %+v", r)
		}
		if !strings.Contains(r.Note, block) || !strings.Contains(r.Note, "offered again (§F.3, §E.3.1)") {
			t.Fatalf("note %q", r.Note)
		}
		if st := p.Status(); len(st) != 1 || st[0].Note != r.Note {
			t.Fatalf("status %+v", st)
		}
	}
}
