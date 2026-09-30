package main

import (
	"strings"
	"testing"
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
