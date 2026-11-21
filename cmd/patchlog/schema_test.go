package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
)

// patchlog schema file prints the file schema of file trees (TOOLS §H.2),
// and --create writes it where gateways look for it, once.
func TestSchemaFileCLI(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{})
	out, _, err := clientRun(t, ctx, s.URL, "schema", "file")
	if err != nil {
		t.Fatal(err)
	}
	var v map[string]any
	if err := json.Unmarshal([]byte(out), &v); err != nil || v["properties"] == nil {
		t.Fatalf("schema file: %v %s", err, out)
	}
	c := s.Client(t, client.WithAuthor("alice"))
	if _, err := c.CreateNamespace(ctx, "schemas", map[string]any{"read": "public"}); err != nil {
		t.Fatal(err)
	}
	first, _, err := clientRun(t, ctx, s.URL, "schema", "file", "--create")
	if err != nil || !strings.HasPrefix(first, "/r/schemas/file/rev/") {
		t.Fatalf("--create: %q %v", first, err)
	}
	again, _, err := clientRun(t, ctx, s.URL, "schema", "file", "--create")
	if err != nil || again != first {
		t.Errorf("--create again: %q %v, want %q (unchanged)", again, err, first)
	}
	// The schema's title rules hold at the core.
	if _, err := c.CreateNamespace(ctx, "files", map[string]any{"read": "public"}); err != nil {
		t.Fatal(err)
	}
	ref := strings.TrimSpace(first)
	for _, bad := range []map[string]any{
		{"$schema": ref, "folder": "/", "name": "a/b"},
		{"$schema": ref, "folder": "/", "name": ".."},
		{"$schema": ref, "folder": "/", "name": "x‮y"},
		{"$schema": ref, "folder": "nope", "name": "x"},
	} {
		if _, err := c.CreateDoc(ctx, "files", "bad", bad); err == nil {
			t.Errorf("%v: accepted", bad)
		}
	}
	if _, err := c.CreateDoc(ctx, "files", "good", map[string]any{"$schema": ref, "folder": "/a b", "name": "ﬁle ü.txt", "content": 1.0}); err != nil {
		t.Errorf("a good title refused: %v", err)
	}
}

func TestSchemaImportCLI(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/root.json":
			w.Write([]byte(`{"$schema":"http://json-schema.org/draft-07/schema#","properties":{"d":{"$ref":"dep.json#/definitions/x"}}}`))
		case "/dep.json":
			w.Write([]byte(`{"definitions":{"x":{"type":"string"}}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	var out, errb bytes.Buffer
	schemaImport := func(args ...string) int {
		return command(t, append([]string{"schema", "import"}, args...)...).(*schemaImportCmd).importSchemas(context.Background(), &out, &errb)
	}
	if code := schemaImport("--ns", "schemas", "--dry-run", "--json", "--name", "thing", srv.URL+"/root.json"); code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	var res struct {
		Written bool
		Entries []struct{ Source, Resource, Path, Action string }
	}
	if err := json.Unmarshal(out.Bytes(), &res); err != nil {
		t.Fatalf("%v: %s", err, out.String())
	}
	if res.Written || len(res.Entries) != 2 || res.Entries[1].Resource != "thing" || !strings.HasPrefix(res.Entries[1].Path, "/r/schemas/thing/rev/1") || res.Entries[0].Action != "create" {
		t.Errorf("%s", out.String())
	}
	out.Reset()
	if code := schemaImport("--ns", "schemas", "--dry-run", srv.URL+"/root.json"); code != 0 || !strings.Contains(out.String(), "/r/schemas/root/rev/") {
		t.Errorf("table: %d %s", code, out.String())
	}
	if code := schemaImport("--ns", "schemas", srv.URL+"/root.json"); code != 2 {
		t.Errorf("missing --api: exit %d", code)
	}
}
