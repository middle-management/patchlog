package client_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
)

// HTTP-31, HTTP-19 (§7.4 GET /ns/{ns}/branches?after={key}; v0.86): the
// listing is paged, { "branches": [ … ], "next"? }. BranchesPage reads a
// page and its next; Branches follows next to the last page and returns
// every row, in byte order of key.
func TestV086BranchesFollowNext(t *testing.T) {
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{LogPageSize: 2})
	c := s.Client(t, client.WithAuthor("alice"))
	must(c.CreateNamespace(ctx, "main", map[string]any{"read": "public"}))
	want := []string{"a-b", "a0", "a_b", "ab", "b"}
	for _, name := range []string{"b", "ab", "a_b", "a0", "a-b"} {
		must(c.CreateBranch(ctx, "main", client.BranchRequest{Name: name}))
	}
	var got []string
	for _, b := range must(c.Branches(ctx, "main")) {
		got = append(got, b.Name)
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("Branches %v, want every page's rows %v", got, want)
	}
	page, next, err := c.BranchesPage(ctx, "main", "")
	if err != nil || len(page) != 2 || page[0].Name != "a-b" || page[1].Name != "a0" || next != "a0" {
		t.Fatalf("first page %+v, next %q, %v", page, next, err)
	}
	page, next, err = c.BranchesPage(ctx, "main", "ab")
	if err != nil || len(page) != 1 || page[0].Name != "b" || next != "" {
		t.Fatalf("last page %+v, next %q, %v", page, next, err)
	}
}
