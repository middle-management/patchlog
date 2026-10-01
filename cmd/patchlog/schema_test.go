package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

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
	if code := schemaImport(context.Background(), []string{"-ns", "schemas", "-dry-run", "-json", "-name", "thing", srv.URL + "/root.json"}, &out, &errb); code != 0 {
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
	if code := schemaImport(context.Background(), []string{"-ns", "schemas", "-dry-run", srv.URL + "/root.json"}, &out, &errb); code != 0 || !strings.Contains(out.String(), "/r/schemas/root/rev/") {
		t.Errorf("table: %d %s", code, out.String())
	}
	if code := schemaImport(context.Background(), []string{"-ns", "schemas", srv.URL + "/root.json"}, &out, &errb); code != 2 {
		t.Errorf("missing -api: exit %d", code)
	}
}
