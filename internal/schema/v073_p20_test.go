package schema

import "testing"

// CIS-15 (§6.4.2): a rule's schema fragment is applied with draft
// 2020-12's format assertions whenever it was written. Under Legacy,
// FragmentOptions asserts idn-email and idn-hostname too, and keeps
// semver as v0.55 asserted it; under V073 it is Options.
func TestV073P20FragmentOptions(t *testing.T) {
	t.Parallel()
	valid := func(rs Rules, frag bool, format string, v any) bool {
		o := rs.Options()
		if frag {
			o = rs.FragmentOptions()
		}
		s := compileOpts(t, o, map[string]any{"format": format})
		return s.Validate(v) == nil
	}
	for _, x := range []struct {
		rs              Rules
		format, yes, no string
		frag, plain     bool // whether FragmentOptions, Options assert it
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
			t.Errorf("%v FragmentOptions %s: %q refused %v", x.rs, x.format, x.no, got)
		}
		if got := !valid(x.rs, false, x.format, x.no); got != x.plain {
			t.Errorf("%v Options %s: %q refused %v", x.rs, x.format, x.no, got)
		}
	}
}
