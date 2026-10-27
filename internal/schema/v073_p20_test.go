package schema

import (
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// CIS-15 (§6.4.2): a rule's schema fragment is applied with draft
// 2020-12's format assertions whenever it was written. Under Legacy,
// ConfigureFragment asserts idn-email and idn-hostname too, and keeps the
// library's semver as v0.55 asserted it; under V073 it is Configure.
func TestV073P20ConfigureFragment(t *testing.T) {
	t.Parallel()
	valid := func(rs Rules, frag bool, format string, v any) bool {
		c := jsonschema.NewCompiler()
		if frag {
			rs.ConfigureFragment(c)
		} else {
			rs.Configure(c)
		}
		if err := c.AddResource("urn:t", map[string]any{"format": format}); err != nil {
			t.Fatal(err)
		}
		s, err := c.Compile("urn:t")
		if err != nil {
			t.Fatal(err)
		}
		return s.Validate(v) == nil
	}
	for _, x := range []struct {
		rs              Rules
		format, yes, no string
		frag, plain     bool // whether ConfigureFragment, Configure assert it
	}{
		{Legacy, "idn-email", "jörg@exämple.se", "not an email", true, false},
		{Legacy, "idn-hostname", "exämple.se", "-bad-.se", true, false},
		{Legacy, "semver", "1.2.3", "one", true, true},
		{Legacy, "email", "a@example.se", "nope", true, true},
		{V073, "idn-email", "jörg@exämple.se", "not an email", true, true},
		{V073, "idn-hostname", "exämple.se", "-bad-.se", true, true},
		{V073, "semver", "1.2.3", "one", false, false},
	} {
		if !valid(x.rs, true, x.format, x.yes) || !valid(x.rs, false, x.format, x.yes) {
			t.Errorf("%v %s: %q fails", x.rs, x.format, x.yes)
		}
		if got := !valid(x.rs, true, x.format, x.no); got != x.frag {
			t.Errorf("%v ConfigureFragment %s: %q refused %v", x.rs, x.format, x.no, got)
		}
		if got := !valid(x.rs, false, x.format, x.no); got != x.plain {
			t.Errorf("%v Configure %s: %q refused %v", x.rs, x.format, x.no, got)
		}
	}
}
