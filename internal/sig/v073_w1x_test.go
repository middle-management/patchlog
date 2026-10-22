package sig

import "testing"

// W1X: one test of the canonical origin (§C.3) for a deployment's own
// origin, a batch's source.origin (§3.5), a remote base's (§G.3) and a
// bundle's (§G.4.1).
func TestW1XCanonicalOrigin(t *testing.T) {
	t.Parallel()
	for _, o := range []string{
		"https://a.example", "http://localhost:8080", "https://a.example:8443", "https://xn--bcher-kva.example",
		"http://127.0.0.1:1", "https://[::1]:8443", "http://a.example",
	} {
		if !CanonicalOrigin(o) {
			t.Errorf("CanonicalOrigin(%q) = false", o)
		}
	}
	for _, o := range []string{
		"", "a.example", "https://", "https://Staging.Example", "HTTPS://a.example", "https://a.example:443", "http://a.example:80",
		"https://a.example:0444", "https://a.example:0", "https://a.example:65536", "https://a.example:", "https://a.example/",
		"https://a.example/x", "https://a.example?x", "https://a.example?", "https://a.example#f", "https://u@a.example",
		"https://bücher.example", "https://b%C3%BCcher.example", "ftp://a.example", "https:a.example",
	} {
		if CanonicalOrigin(o) {
			t.Errorf("CanonicalOrigin(%q) = true", o)
		}
	}
}
