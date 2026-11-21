package index_test

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/derived"
)

// v0.89 (SERVICES §A.4 Private namespaces, §E.2.6): in a sealed
// namespace the index judges a reader's /doc rules on the documents it
// opens with its keys, doc being null only at E2E, and serves the hits of
// a partial reader per entry, each sealed under the K_rev of its
// revision, which the origin's filtered answers carry to that reader.
func TestV089IndexJudgesSealedDocs(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{Auth: true, KeyStore: keyStore(t), LongPoll: 150 * time.Millisecond})
	k := clienttest.NewKey("k")
	must(s.Client(t, client.WithBearer(s.OperatorGrant(t, "sec"))).CreateNamespace(ctx, "sec", map[string]any{"read": "grant", "keys": []any{k.Entry("*")},
		"encryption": map[string]any{"level": "sealed"}}))
	must(s.Client(t, client.WithBearer(s.OperatorGrant(t, "schemas"))).CreateNamespace(ctx, "schemas", map[string]any{"read": "public", "keys": []any{k.Entry("*")}}))
	w := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:w", []string{"sec", "schemas"}, []string{"read", "create"})), client.WithKeys(client.NewKeys(nil)))
	sch := must(w.CreateDoc(ctx, "schemas", "item", map[string]any{"$schema": d2020, "type": "object",
		"properties": map[string]any{"title": map[string]any{"type": "string", "x-index": "text"}}}))
	ids := map[string]string{}
	for n, team := range map[string]string{"a": "a", "b": "b", "c": "a"} {
		ids[n] = must(createNonced(w, "sec", n, map[string]any{"$schema": "/r/schemas/item/rev/" + sch.ID, "title": "secret " + n, "team": team})).ID
	}
	ic := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "svc:indexer", []string{"sec"}, []string{"read"})), client.WithKeys(client.NewKeys(nil)))
	x := startSvc(t, ic, svcOpts{db: filepath.Join(t.TempDir(), "i.db"), ns: []string{"sec"}, now: s.Now})
	x.caughtUp("sec")

	reader := k.Grant(t, s.Now(), "user:r", []string{"sec"}, []string{"read"},
		map[string]any{"rules": []any{map[string]any{"op": "test", "path": "/doc/team", "value": "a"}}})
	f := x.fetch("/sec?q=secret", reader)
	if !strings.Contains(f.path, "/sec/view/") || f.header.Get("Content-Type") != "application/json" || strings.Contains(string(f.body), "secret") {
		t.Fatalf("the partial reader's answer at %s: %q %s", f.path, f.header.Get("Content-Type"), f.body)
	}
	hits := decodeJSON(t, f.body)["hits"].([]any)
	var got []string
	ke := epochKeys(t, w, "sec")
	for _, h := range hits {
		h := h.(map[string]any)
		name, id := h["resource"].(string), h["id"].(string)
		got = append(got, name)
		if id != ids[name] {
			t.Errorf("hit %s at %s, want %s", name, id, ids[name])
		}
		// Under the view key of its revision's K_rev (§E.2.6).
		v := decodeJSON(t, must(derived.OpenItem(h["sealed"].(string), derived.ItemKey(ke, "sec", name, id), derived.View{NS: "sec", Target: f.path}, "sec", name)))
		if v["score"] == nil {
			t.Errorf("hit %s opens to %v", name, v)
		}
	}
	if strings.Join(sortedStrings(got), ",") != "a,c" {
		t.Fatalf("the partial reader's hits %v, want a and c: b's team is b", got)
	}

	// The K_rev the origin's filtered answer carries to that reader opens
	// a hit as well: origin and index needn't agree on a view.
	rc := s.Client(t, client.WithBearer(reader), client.WithKeys(client.NewKeys(nil)))
	if _, fa, err := rc.FilteredLog(ctx, "sec", ""); err != nil || !fa.Filtered() {
		t.Fatalf("the origin's filtered range: %+v %v", fa, err)
	}
	if d, err := rc.Doc(ctx, "sec", "a", ids["a"]); err != nil || !strings.Contains(string(d.Raw), "secret a") {
		t.Fatalf("a as the partial reader opens it: %v", err)
	}
}

func sortedStrings(xs []string) []string {
	out := append([]string(nil), xs...)
	for i := range out {
		for j := i + 1; j < len(out); j++ {
			if out[j] < out[i] {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}
