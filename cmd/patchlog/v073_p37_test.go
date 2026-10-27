package main

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/edge"
)

// IX-18 (§C.5.3): the index's own edge-grant key is one the origin never
// holds: -edge-grant-key files as the origin takes them, minting with the
// last and accepting all, a random key named -edge-grant-kid (default
// index) without one; a kid of the origin's, or the key derived from
// -edge-secret, is refused.
func TestV073P37IndexEdgeGrantFlags(t *testing.T) {
	dir := t.TempDir()
	k1 := filepath.Join(dir, "k1")
	if err := os.WriteFile(k1, []byte("the index's key, sixteen bytes or more\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cors := addCORSFlags(flag.NewFlagSet("t", flag.ContinueOnError))
	ck, err := indexEdgeGrantCookies("index", []string{"origin"}, nil, nil, cors)
	if err != nil || ck.Kid() != "index" {
		t.Fatalf("random key: %v %v", ck, err)
	}
	ck, err = indexEdgeGrantCookies("index", []string{"origin"}, []string{"ix1=" + k1}, nil, cors)
	if err != nil || ck.Kid() != "ix1" {
		t.Fatalf("named key file: %v %v", ck, err)
	}
	if _, err := indexEdgeGrantCookies("index", []string{"origin", "ix1"}, []string{"ix1=" + k1}, nil, cors); err == nil || !strings.Contains(err.Error(), "origin's") {
		t.Errorf("a kid of the origin's: %v", err)
	}
	if _, err := indexEdgeGrantCookies("origin", []string{"origin"}, nil, nil, cors); err == nil {
		t.Error("the random key named as the origin's")
	}
	ev := must(edge.New([]byte("s3cret"), "", ""))
	sec := filepath.Join(dir, "derived")
	if err := os.WriteFile(sec, ev.CookieKey(), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := indexEdgeGrantCookies("index", []string{"origin"}, []string{sec}, ev, cors); err == nil || !strings.Contains(err.Error(), "-edge-secret") {
		t.Errorf("the key derived from the edge secret: %v", err)
	}
	if _, err := indexEdgeGrantCookies("index", []string{"origin"}, []string{"edge-secret"}, ev, cors); err == nil {
		t.Error("FILE edge-secret for the index")
	}
}
