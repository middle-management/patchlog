package vectors_test

import (
	"slices"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/keystore"
	"github.com/middle-management/patchlog/internal/seal"
)

// w4x (P38 x the core), §E.2.2, §7.1: the sealed.json resource log entry
// rows seal the payload a sealed deployment seals for a revision's and a
// tombstone's log entry, with the members the core's LogEntry.value
// gives: author and created beside id, kind and parent (and patches).
func TestV073W4xSealedLogEntryPlaintextsServed(t *testing.T) {
	t.Parallel()
	ks, err := keystore.New(keystore.Generate())
	if err != nil {
		t.Fatal(err)
	}
	s := clienttest.New(t, clienttest.Options{KeyStore: ks})
	c := s.Client(t, client.WithAuthor("bob")).With(client.WithKeys(client.NewKeys(nil)))
	if _, err := c.CreateNamespace(ctx, "demo", map[string]any{"read": "public", "encryption": map[string]any{"level": "sealed"}}); err != nil {
		t.Fatal(err)
	}
	r, err := c.Create(ctx, "demo", "derby", []byte(`[{"op":"add","path":"","value":{"title":"Hello","views":0}},{"op":"add","path":"/$nonce","value":"`+seal.NewNonce()+`"}]`))
	if err != nil {
		t.Fatal(err)
	}
	d, err := c.Delete(ctx, "demo", "derby", r.ID)
	if err != nil {
		t.Fatal(err)
	}
	log, err := c.Log(ctx, "demo", "derby", d.ID, "")
	if err != nil {
		t.Fatal(err)
	}
	served := map[string][]string{}
	for _, e := range log {
		if e.Kid == "" {
			t.Fatalf("the %s entry was not served sealed", e.Kind)
		}
		var ks []string
		for k := range e.Raw {
			ks = append(ks, k)
		}
		slices.Sort(ks)
		served["resource log entry ("+e.Kind+")"] = ks
	}
	if len(served) != 2 {
		t.Fatalf("served entries %v", served)
	}
	seen := 0
	for _, v := range loadVectors(t, "sealed").Vectors {
		name, _ := v["name"].(string)
		want, ok := served[name]
		if !ok {
			continue
		}
		seen++
		var vec []string
		for k := range jsonv.MustParse([]byte(v["plaintext"].(string))).(map[string]any) {
			vec = append(vec, k)
		}
		slices.Sort(vec)
		if !slices.Equal(vec, want) {
			t.Errorf("sealed.json %s plaintext members %v; a sealed deployment seals %v", name, vec, want)
		}
	}
	if seen != len(served) {
		t.Fatalf("%d of the %d log entry rows found in sealed.json", seen, len(served))
	}
}
