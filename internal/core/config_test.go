package core

import "testing"

func TestValidRemoteOrigin(t *testing.T) {
	t.Parallel()
	good := []string{"https://cms.example", "https://cms.example:8443", "http://localhost:8080", "http://127.0.0.1:9", "http://[::1]:8080", "http://localhost", "http://127.0.0.2:8080", "http://127.255.0.9:8123"}
	bad := []string{"http://cms.example", "https://cms.example/", "https://CMS.example", "https://cms.example:443",
		"http://localhost:80", "ftp://cms.example", "https://u@cms.example", "https://cms.example?x", "cms.example", "https://", "http://[::2]:8080"}
	for _, s := range good {
		if !ValidRemoteOrigin(s) {
			t.Errorf("%q rejected", s)
		}
	}
	for _, s := range bad {
		if ValidRemoteOrigin(s) {
			t.Errorf("%q accepted", s)
		}
	}
}

// documentSize is 1 MiB by default, and a namespace may set it up to the
// deployment maximum, 4 MiB by default (docs/CAPACITY.md).
func TestDocumentSizeDefaultAndMaximum(t *testing.T) {
	if got := DefaultLimits().DocumentSize; got != 1<<20 {
		t.Fatalf("default documentSize %d", got)
	}
	if got := DefaultMaximums().DocumentSize; got != 4<<20 {
		t.Fatalf("maximum documentSize %d", got)
	}
	c, err := parseConfig(map[string]any{"read": "public"}, DefaultLimits(), DefaultMaximums())
	if err != nil || c.Limits.DocumentSize != 1<<20 {
		t.Fatalf("unset: %v %v", c, err)
	}
	c, err = parseConfig(map[string]any{"read": "public", "limits": map[string]any{"documentSize": float64(4 << 20)}}, DefaultLimits(), DefaultMaximums())
	if err != nil || c.Limits.DocumentSize != 4<<20 {
		t.Fatalf("4 MiB: %v %v", c, err)
	}
	if _, err := parseConfig(map[string]any{"read": "public", "limits": map[string]any{"documentSize": float64(4<<20 + 1)}}, DefaultLimits(), DefaultMaximums()); err == nil {
		t.Fatal("over the maximum accepted")
	}
}
