package grantcheck_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
)

// Grant checks with a log page size of 2 (§7.1 Paging): the keys a branch
// copied are found in its base's log after at, a range of several pages
// once the base has moved on.
func TestPagedFlows(t *testing.T) {
	clienttest.Paged(t, 2, func(t *testing.T) {
		ctx := context.Background()
		f := newFixture(t)
		must(f.adminC.CreateDoc(ctx, "sec", "a", map[string]any{}))
		must(f.adminC.CreateBranch(ctx, "sec", client.BranchRequest{Name: "rel"}))
		for i := range 4 {
			must(f.adminC.CreateDoc(ctx, "sec", fmt.Sprintf("x%d", i), map[string]any{}))
		}
		tok := f.grant(f.issuer, "user:bob", []string{"rel"}, []string{"read"})
		if d, err := f.ch.CheckRead(ctx, "rel", tok, "a"); err != nil || !d.Allowed {
			t.Fatalf("branch read with a copied key: %v %+v", err, d)
		}
	})
}
