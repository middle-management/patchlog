package core

import (
	"path/filepath"
	"strings"
	"testing"
)

// W1X: the deployment's own origin is published at GET / and carried by
// signing inputs, batch sources and bundle headers in the canonical form
// of §C.3 only (sig.CanonicalOrigin), so Open refuses any other; and a
// remote origin (§G.3) is held to the same form.
func TestW1XCanonicalOrigins(t *testing.T) {
	t.Parallel()
	for _, o := range []string{"https://Staging.Example", "https://a.example:443", "https://a.example/", "https://bücher.example", "a.example"} {
		e, err := Open(Options{Path: filepath.Join(t.TempDir(), "o.db"), Origin: o, AuthDisabled: true, RetentionInterval: -1})
		if err == nil {
			e.Close()
			t.Errorf("Open with origin %q succeeded", o)
		} else if !strings.Contains(err.Error(), "canonical origin") {
			t.Errorf("Open with origin %q: %v", o, err)
		}
	}
	e, err := Open(Options{Path: filepath.Join(t.TempDir(), "o.db"), Origin: "https://staging.example", AuthDisabled: true, RetentionInterval: -1})
	if err != nil {
		t.Fatalf("Open with a canonical origin: %v", err)
	}
	e.Close()
	for o, want := range map[string]bool{
		"https://b.example": true, "http://localhost:8080": true, "http://127.0.0.2": true, "http://[::1]:9": true,
		"http://b.example": false, "https://B.example": false, "https://b.example:443": false, "https://bücher.example": false,
		"https://b.example:0444": false, "http://localhost:80": false,
	} {
		if ValidRemoteOrigin(o) != want {
			t.Errorf("ValidRemoteOrigin(%q) = %v", o, !want)
		}
	}
}
