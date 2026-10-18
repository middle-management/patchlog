package main

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

// TestServiceEdgeGrantCookies (§B.11.5, §C.5.3): the catalog
// service's edge-grant keys and kids are its own. -edge-grant-key is
// repeatable, [KID=]FILE as the origin takes it, a plain FILE named by
// -edge-grant-kid (default catalog-{catalog}): cookies are minted under
// the last and accepted under any, so the service's key rotates. No kid
// may be one of the origin's, every one -origin-edge-grant-kid lists
// (repeatable or comma-separated, default origin), and no key the one
// derived from the edge secret, which the origin may hold.
func TestServiceEdgeGrantCookies(t *testing.T) {
	cf := &corsFlags{credentials: new(bool)}
	origin := originKids(nil)
	ck, err := serviceEdgeGrantCookies("cat", "", origin, nil, nil, cf)
	if err != nil || ck.Kid() != "catalog-cat" || ck.SameSite != http.SameSiteLaxMode {
		t.Fatalf("default: %v %v", ck, err)
	}
	if _, err := serviceEdgeGrantCookies("cat", "origin", origin, nil, nil, cf); err == nil {
		t.Error("the origin's default kid accepted")
	}
	dir := t.TempDir()
	file := func(name, key string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(key), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	own := file("own.key", "a key of the catalog service's own\n")
	next := file("next.key", "the catalog service's next key\n")
	// The origin holds k1 and k2 while it rotates: neither is the
	// service's, however the list is given.
	for _, list := range [][]string{{"k1,k2"}, {"k1", "k2"}, {" k1 , k2 "}} {
		kids := originKids(list)
		for _, kid := range []string{"k1", "k2"} {
			if _, err := serviceEdgeGrantCookies("cat", kid, kids, nil, nil, cf); err == nil {
				t.Errorf("origin kids %q: the service's -edge-grant-kid %s accepted", list, kid)
			}
			if _, err := serviceEdgeGrantCookies("cat", "", kids, []string{"c1=" + own, kid + "=" + next}, nil, cf); err == nil {
				t.Errorf("origin kids %q: the service's key named %s accepted", list, kid)
			}
		}
		if ck, err := serviceEdgeGrantCookies("cat", "origin", kids, nil, nil, cf); err != nil || ck.Kid() != "origin" {
			t.Errorf("origin kids %q: origin, no longer the origin's: %v %v", list, ck, err)
		}
	}
	secret := []byte("the deployment's edge secret")
	ev, err := edge.New(secret, "", "")
	if err != nil {
		t.Fatal(err)
	}
	derived := filepath.Join(dir, "derived.key")
	if err := os.WriteFile(derived, edge.KeyFromSecret(secret), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, keys := range [][]string{{derived}, {own, "c2=" + derived}, {"edge-secret"}} {
		if _, err := serviceEdgeGrantCookies("cat", "", origin, keys, ev, cf); err == nil {
			t.Errorf("the origin's derived key accepted: %q", keys)
		}
	}
	cf.credOrigins = multi{"https://app.example"}
	if ck, err := serviceEdgeGrantCookies("cat", "cat-2026", origin, []string{own}, ev, cf); err != nil || ck.Kid() != "cat-2026" || ck.SameSite != http.SameSiteNoneMode {
		t.Errorf("own key: %v %v", ck, err)
	}
	// Rotating: a cookie minted under the first key alone verifies once
	// the next is added as the newest, which mints.
	now := time.Unix(1790000000, 0)
	cl := edge.Claims{Prefix: "/cat/g/all", Exp: now.Add(time.Minute).Unix()}
	before, err := serviceEdgeGrantCookies("cat", "", origin, []string{own}, ev, cf)
	if err != nil {
		t.Fatal(err)
	}
	after, err := serviceEdgeGrantCookies("cat", "", origin, []string{own, "c2=" + next}, ev, cf)
	if err != nil || after.Kid() != "c2" || strings.Join(after.Kids(), " ") != "catalog-cat c2" {
		t.Fatalf("rotating: %v %v", after, err)
	}
	vouches := func(p string) bool { return strings.HasPrefix(p, "/cat/g/") }
	before.Vouches, after.Vouches = vouches, vouches
	if _, err := after.Verify(before.Issue(cl, now).Value, now); err != nil {
		t.Errorf("the first key's cookie after rotation: %v", err)
	}
	// A catalog named r or ns gets none, so the service still starts
	// (tree.Open refuses edge grants for it, which the open loop would
	// retry for ever); naming a key or kid for it is an error.
	for _, cat := range []string{"r", "ns"} {
		if ck, err := serviceEdgeGrantCookies(cat, "", origin, nil, nil, cf); ck != nil || err != nil {
			t.Errorf("catalog %s: %v %v", cat, ck, err)
		}
		if _, err := serviceEdgeGrantCookies(cat, "", origin, []string{own}, nil, cf); err == nil {
			t.Errorf("catalog %s with a key: accepted", cat)
		}
		if _, err := serviceEdgeGrantCookies(cat, "k", origin, nil, nil, cf); err == nil {
			t.Errorf("catalog %s with a kid: accepted", cat)
		}
	}
}

// The edge-grant flags of tree need -access, -exchange-rate included:
// the plain tree service mints no edge grants, and would ignore them.
func TestTreeEdgeFlagsNeedAccess(t *testing.T) {
	if err := edgeFlagsNeedAccess(nil, nil, "", ""); err != nil {
		t.Errorf("none: %v", err)
	}
	for name, err := range map[string]error{
		"-edge-grant-key":        edgeFlagsNeedAccess([]string{"k.key"}, nil, "", ""),
		"-origin-edge-grant-kid": edgeFlagsNeedAccess(nil, []string{"k1"}, "", ""),
		"-edge-grant-kid":        edgeFlagsNeedAccess(nil, nil, "c1", ""),
		"-exchange-rate":         edgeFlagsNeedAccess(nil, nil, "", "10,100"),
	} {
		if err == nil {
			t.Errorf("%s without -access: accepted", name)
		}
	}
}
