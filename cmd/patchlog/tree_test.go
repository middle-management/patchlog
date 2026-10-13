package main

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/edge"
)

func TestTreeCatalogFlags(t *testing.T) {
	if got := strings.Join(splitCatalogs([]string{"cat", "topics, cat", " ", "x"}), " "); got != "cat topics x" {
		t.Errorf("splitCatalogs: %q", got)
	}
	for _, c := range []struct {
		db, cat string
		n       int
		want    string
	}{
		{"tree.db", "cat", 1, "tree.db"},
		{"/data/tree.db", "topics", 2, "/data/tree-topics.db"},
		{"/data/tree", "topics", 2, "/data/tree-topics"},
		{"/data/tree-{catalog}.db", "cat", 1, "/data/tree-cat.db"},
		{"/data/{catalog}/t.db", "topics", 2, "/data/topics/t.db"},
	} {
		if got := treeDB(c.db, c.cat, c.n); got != c.want {
			t.Errorf("treeDB(%q, %q, %d) = %q, want %q", c.db, c.cat, c.n, got, c.want)
		}
	}
}

// TestServiceEdgeGrantCookies (§B.11.5, §C.5 "Format"): the catalog
// service's edge-grant key and kid are its own. The kid defaults to
// catalog-{catalog} and may not be the origin's; the key may not be the
// one the origin derives from the edge secret.
func TestServiceEdgeGrantCookies(t *testing.T) {
	cf := &corsFlags{credentials: new(bool)}
	ck, err := serviceEdgeGrantCookies("cat", "", edge.DefaultKid, "", nil, cf)
	if err != nil || ck.Kid() != "catalog-cat" || ck.SameSite != http.SameSiteLaxMode {
		t.Fatalf("default: %v %v", ck, err)
	}
	if _, err := serviceEdgeGrantCookies("cat", "origin", edge.DefaultKid, "", nil, cf); err == nil {
		t.Error("the origin's default kid accepted")
	}
	if _, err := serviceEdgeGrantCookies("cat", "edge-1", "edge-1", "", nil, cf); err == nil {
		t.Error("the origin's named kid accepted")
	}
	dir := t.TempDir()
	secret := []byte("the deployment's edge secret")
	ev, err := edge.New(secret, "", "")
	if err != nil {
		t.Fatal(err)
	}
	derived := filepath.Join(dir, "derived.key")
	if err := os.WriteFile(derived, edge.KeyFromSecret(secret), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := serviceEdgeGrantCookies("cat", "", edge.DefaultKid, derived, ev, cf); err == nil {
		t.Error("the origin's derived key accepted")
	}
	own := filepath.Join(dir, "own.key")
	if err := os.WriteFile(own, []byte("a key of the catalog service's own\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cf.credOrigins = multi{"https://app.example"}
	if ck, err := serviceEdgeGrantCookies("cat", "cat-2026", edge.DefaultKid, own, ev, cf); err != nil || ck.Kid() != "cat-2026" || ck.SameSite != http.SameSiteNoneMode {
		t.Errorf("own key: %v %v", ck, err)
	}
	// A catalog named r or ns gets none, so the service still starts
	// (tree.Open refuses edge grants for it, which the open loop would
	// retry for ever); naming a key or kid for it is an error.
	for _, cat := range []string{"r", "ns"} {
		if ck, err := serviceEdgeGrantCookies(cat, "", edge.DefaultKid, "", nil, cf); ck != nil || err != nil {
			t.Errorf("catalog %s: %v %v", cat, ck, err)
		}
		if _, err := serviceEdgeGrantCookies(cat, "", edge.DefaultKid, own, nil, cf); err == nil {
			t.Errorf("catalog %s with a key: accepted", cat)
		}
		if _, err := serviceEdgeGrantCookies(cat, "k", edge.DefaultKid, "", nil, cf); err == nil {
			t.Errorf("catalog %s with a kid: accepted", cat)
		}
	}
}
