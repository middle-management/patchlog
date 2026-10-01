package bundle_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/bundle"
	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/schema"
)

// §G.4.2: a document referencing a schema revision that exists only in a
// branch (a draft, §6.1) can't be exported until that branch is merged.
func TestExportRefusesDrafts(t *testing.T) {
	src := newDeployment(t, stagingOrigin)
	src.ns("schemas", nil)
	src.ns("matches", nil)
	must(src.c.CreateBranch(ctx, "schemas", client.BranchRequest{Name: "schemas-r7",
		Patches: ops(op("add", "/drafts", map[string]any{"for": []any{"matches-r7"}}))}))
	sch := map[string]any{"$schema": "https://json-schema.org/draft/2020-12/schema", "type": "object"}
	t1 := src.create("schemas-r7", "team", sch)
	must(src.c.CreateBranch(ctx, "matches", client.BranchRequest{Name: "matches-r7"}))
	src.create("matches-r7", "m1", map[string]any{"$schema": "/r/schemas/team/rev/" + t1})

	var buf bytes.Buffer
	_, _, err := bundle.Export(ctx, src.c, &buf, bundle.ExportOptions{Select: []string{"matches-r7"}})
	if err == nil || !strings.Contains(err.Error(), "exists only in branch schemas-r7") {
		t.Fatalf("export of a document using a draft: %v", err)
	}

	// The client resolver finds the draft as validating consumers must.
	r, err := src.c.ResolveSchema(ctx, mustRef(t, "/r/schemas/team/rev/"+t1), client.ResolveOptions{Drafts: true})
	if err != nil || r.NS != "schemas-r7" {
		t.Fatalf("resolve: %v %+v", err, r)
	}
	if _, err := src.c.ResolveSchema(ctx, mustRef(t, "/r/schemas/team/rev/"+t1), client.ResolveOptions{}); !client.IsNotFound(err) {
		t.Fatalf("without drafts: %v", err)
	}

	// Merged by fast-forward, it exports.
	must(src.c.CreateDoc(ctx, "schemas", "team", sch))
	exportFrom(t, src, bundle.ExportOptions{Select: []string{"matches-r7"}})
}

func mustRef(t *testing.T, p string) schema.Ref {
	t.Helper()
	r, ok := schema.ParseRef(p)
	if !ok {
		t.Fatalf("bad ref %s", p)
	}
	return r
}
