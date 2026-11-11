package schema

import (
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// Cross-review (conformance lens): v0.77's vectors, now §I.18 (§6.2 step 5):
// idn-hostname rejects ab--cd and a lone U+00B7 (contextual rules),
// hostname (RFC 1123 alone) accepts ab--cd, and both accept an uppercase
// A-label.
func TestV077XconfHostnameVectors(t *testing.T) {
	t.Parallel()
	for _, x := range []struct {
		host string
		ok   bool
	}{
		{"ab--cd", false},
		{"·", false},
		{"a·b", false},
		{"l·l", true},
		{"XN--BCHER-KVA", true},
		{"xn--bcher-kva", true},
	} {
		if err := validateIDNHostname(x.host); (err == nil) != x.ok {
			t.Errorf("idn-hostname %q: %v, want ok %v", x.host, err, x.ok)
		}
	}
	for _, x := range []struct {
		host string
		ok   bool
	}{
		{"ab--cd", true},
		{"XN--BCHER-KVA", true},
	} {
		if err := v077xFormat(t, "hostname", x.host); (err == nil) != x.ok {
			t.Errorf("hostname %q: %v, want ok %v", x.host, err, x.ok)
		}
	}
	for _, x := range []struct {
		addr string
		ok   bool
	}{
		{"a@ab--cd", false},
		{"a@·", false},
	} {
		if err := validateIDNEmail(x.addr); (err == nil) != x.ok {
			t.Errorf("idn-email %q: %v, want ok %v", x.addr, err, x.ok)
		}
	}
}

// v077xFormat validates v against {"format": f} compiled as V073 does.
func v077xFormat(t *testing.T, f string, v any) error {
	t.Helper()
	c := jsonschema.NewCompiler()
	V073.Configure(c)
	if err := c.AddResource("x.json", map[string]any{"format": f}); err != nil {
		t.Fatal(err)
	}
	sch, err := c.Compile("x.json")
	if err != nil {
		t.Fatal(err)
	}
	return sch.Validate(v)
}
