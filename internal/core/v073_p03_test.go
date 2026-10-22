package core

import (
	"context"
	"errors"
	"testing"

	"github.com/middle-management/patchlog/internal/schema"
)

// CIS-13: a schema revision referenced only through a $ref whose fragment
// is a plain name, an $anchor of that revision, is referenced (§6.1): a
// purge that would remove its last copy is in_use. Documents validate
// through the anchor.
func TestV073AnchorRefInUse(t *testing.T) {
	t.Parallel()
	s := newSchemaEnv(t)
	s.mkNS("s")
	s.mkNS("d")
	lib := s.put("s", "lib", "", map[string]any{"$schema": schema.Dialect2020,
		"$defs": map[string]any{"k": map[string]any{"$anchor": "k", "type": "object", "required": []any{"k"}}}})
	user := s.put("s", "user", "", map[string]any{"$schema": schema.Dialect2020, "$ref": "/r/s/lib/rev/" + lib + "#k"})
	userPath := "/r/s/user/rev/" + user
	s.put("d", "ok", "", map[string]any{"$schema": userPath, "k": 1.0})
	_, err := s.e.WriteResource(context.Background(), s.req("d"), createItem("bad", map[string]any{"$schema": userPath}))
	var ae *Error
	if !errors.As(err, &ae) || ae.Status != 422 || ae.Body["code"] != "invalid" {
		t.Fatalf("a document the anchor's schema refuses: %v", err)
	}
	_, err = s.e.Purge(context.Background(), s.req("s"), "lib", lib, false)
	if !errors.As(err, &ae) || ae.Status != 409 || ae.Body["code"] != "in_use" {
		t.Fatalf("purging the schema reached only through an anchor: %v", err)
	}
	// A plain name the revision doesn't define makes a schema invalid.
	_, err = s.e.WriteResource(context.Background(), s.req("s"), createItem("nope",
		map[string]any{"$schema": schema.Dialect2020, "$ref": "/r/s/lib/rev/" + lib + "#nope"}))
	if !errors.As(err, &ae) || ae.Status != 422 || ae.Body["code"] != "invalid" {
		t.Fatalf("a plain name no anchor defines: %v", err)
	}
}

// CIS-13, invariant 3: v0.55 stored $refs whose fragment is a pointer once
// percent-decoded, "#%2F$defs%2Fk". Such a schema still loads, its
// documents validate through the pointer, and the revision it reaches
// still counts as referenced: purging it is in_use (§6.1).
func TestV073EncodedSlashFragmentInUse(t *testing.T) {
	t.Parallel()
	s := newSchemaEnv(t)
	s.mkNS("s")
	s.mkNS("d")
	lib := s.put("s", "lib", "", map[string]any{"$schema": schema.Dialect2020,
		"$defs": map[string]any{"k": map[string]any{"type": "object", "required": []any{"k"}}}})
	user := s.put("s", "user", "", map[string]any{"$schema": schema.Dialect2020,
		"$ref": "/r/s/lib/rev/" + lib + "#%2F$defs%2Fk"})
	userPath := "/r/s/user/rev/" + user
	s.put("d", "ok", "", map[string]any{"$schema": userPath, "k": 1.0})
	ctx := context.Background()
	_, err := s.e.WriteResource(ctx, s.req("d"), createItem("bad", map[string]any{"$schema": userPath}))
	var ae *Error
	if !errors.As(err, &ae) || ae.Status != 422 || ae.Body["code"] != "invalid" {
		t.Fatalf("a document the pointer's schema refuses: %v", err)
	}
	_, err = s.e.Purge(ctx, s.req("s"), "lib", lib, false)
	if !errors.As(err, &ae) || ae.Status != 409 || ae.Body["code"] != "in_use" {
		t.Fatalf("purging the schema a stored schema reaches: got %v, want 409 in_use", err)
	}
}
