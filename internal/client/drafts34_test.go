package client_test

import (
	"context"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/schema"
	"github.com/middle-management/patchlog/internal/verify"
)

// §6.1, §7.4 (v0.34): the branch listing shows each branch's drafts, and
// ResolveSchema applies drafts.for for the namespace it resolves for, where
// it can see it.
func TestResolveSchemaDraftsFor(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{})
	c := s.Client(t, client.WithAuthor("alice"))
	for _, ns := range []string{"schemas", "matches"} {
		if _, err := c.CreateNamespace(ctx, ns, map[string]any{"read": "public"}); err != nil {
			t.Fatal(err)
		}
	}
	addDrafts := func(list ...any) []any {
		return []any{map[string]any{"op": "add", "path": "/drafts", "value": map[string]any{"for": list}}}
	}
	sch := map[string]any{"$schema": schema.Dialect2020, "type": "object"}
	// Two candidates holding the same revision: one for matches-r7 only,
	// one for nobody else.
	for name, p := range map[string][]any{"schemas-a": addDrafts("matches-r7"), "schemas-b": nil} {
		if _, err := c.CreateBranch(ctx, "schemas", client.BranchRequest{Name: name, Patches: p}); err != nil {
			t.Fatal(err)
		}
	}
	wa, err := c.CreateDoc(ctx, "schemas-a", "team", sch)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.CreateDoc(ctx, "schemas-b", "team", sch); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"matches-r7", "matches-r8"} {
		if _, err := c.CreateBranch(ctx, "matches", client.BranchRequest{Name: name}); err != nil {
			t.Fatal(err)
		}
	}
	bs, err := c.Branches(ctx, "schemas")
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range bs {
		switch b.Name {
		case "schemas-a":
			if len(b.Drafts) != 1 || b.Drafts[0] != "matches-r7" {
				t.Fatalf("schemas-a drafts %v", b.Drafts)
			}
		case "schemas-b":
			if b.Drafts != nil {
				t.Fatalf("schemas-b drafts %v", b.Drafts)
			}
		}
	}
	ref, _ := schema.ParseRef("/r/schemas/team/rev/" + wa.ID)
	// For matches-r7, only schemas-a serves.
	r, err := c.ResolveSchema(ctx, ref, client.ResolveOptions{Drafts: true, For: "matches-r7", Prefer: []string{"schemas-b"}})
	if err != nil || r.NS != "schemas-a" {
		t.Fatalf("for matches-r7: %+v %v", r, err)
	}
	// For matches-r8, neither does.
	if _, err := c.ResolveSchema(ctx, ref, client.ResolveOptions{Drafts: true, For: "matches-r8"}); !client.IsNotFound(err) {
		t.Fatalf("for matches-r8: %v", err)
	}
	// A candidate serves itself.
	if r, err := c.ResolveSchema(ctx, ref, client.ResolveOptions{Drafts: true, For: "schemas-b"}); err != nil || r.NS != "schemas-b" {
		t.Fatalf("for schemas-b: %+v %v", r, err)
	}
	// Without For, any copy serves (content is the same everywhere).
	if _, err := c.ResolveSchema(ctx, ref, client.ResolveOptions{Drafts: true}); err != nil {
		t.Fatal(err)
	}
}

// §3.5 (v0.34): a forced purge's entries carry forced: true, parsed by the
// client and part of the hashed entry the verifier recomputes.
func TestForcedEntriesVerify(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{})
	c := s.Client(t, client.WithAuthor("alice"))
	for _, ns := range []string{"schemas", "matches"} {
		if _, err := c.CreateNamespace(ctx, ns, map[string]any{"read": "public"}); err != nil {
			t.Fatal(err)
		}
	}
	w, err := c.CreateDoc(ctx, "schemas", "team", map[string]any{"$schema": schema.Dialect2020, "type": "object"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.CreateDoc(ctx, "matches", "m", map[string]any{"$schema": "/r/schemas/team/rev/" + w.ID}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Purge(ctx, "schemas", "team", w.ID, false); !client.IsInUse(err) {
		t.Fatalf("purge: %v", err)
	}
	if _, err := c.Purge(ctx, "schemas", "team", w.ID, true); err != nil {
		t.Fatal(err)
	}
	h, err := c.NSHead(ctx, "schemas")
	if err != nil {
		t.Fatal(err)
	}
	log, err := c.NSLog(ctx, "schemas", h.ID, "")
	if err != nil {
		t.Fatal(err)
	}
	last := log[len(log)-1]
	if last.Kind != "purge" || !last.Forced {
		t.Fatalf("last entry %+v", last)
	}
	if _, err := verify.VerifyNSChain(log, ""); err != nil {
		t.Fatal(err)
	}
	// Without forced, the id doesn't verify.
	last.Forced = false
	log[len(log)-1] = last
	if _, err := verify.VerifyNSChain(log, ""); err == nil {
		t.Fatal("an entry stripped of forced verified")
	}
}
