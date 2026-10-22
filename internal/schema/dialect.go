package schema

import (
	"net/netip"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/middle-management/patchlog/internal/pattern"
	"github.com/santhosh-tekuri/jsonschema/v6"
	"golang.org/x/net/idna"
)

// Rules marks the rules a schema revision was written under, which select
// how it compiles: "A schema stored under an earlier version is compiled
// as that version did" (§6.1). The compiled-validator cache is keyed by
// revision path and marker.
type Rules uint8

const (
	// Legacy is how v0.55 compiled every schema: the library's formats
	// asserted, semver and period included, idn-email and idn-hostname
	// not, and other names ignored. A pattern \uXXXX translation refuses
	// but RE2 took as written still compiles. Stored revisions load as
	// Legacy until their markers are kept.
	Legacy Rules = iota
	// V073 asserts exactly the format set of draft 2020-12 (§6.2 step 5),
	// idn-email and idn-hostname with UTS 46 processing, and reads
	// patterns as §6.6 says. Schemas written now compile under it.
	V073
)

func (r Rules) String() string {
	if r == V073 {
		return "v0.73"
	}
	return "legacy"
}

// formats2020 is the format set draft 2020-12 defines. A schema written
// now naming any other is invalid, as an unknown keyword is (§6.2 step 5,
// §6.5).
var formats2020 = map[string]bool{}

func init() {
	for _, f := range []string{
		"date-time", "date", "time", "duration", "email", "idn-email", "hostname", "idn-hostname",
		"ipv4", "ipv6", "uri", "uri-reference", "iri", "iri-reference", "uuid", "uri-template",
		"json-pointer", "relative-json-pointer", "regex",
	} {
		formats2020[f] = true
	}
}

// IsFormat reports whether f is a format draft 2020-12 defines.
func IsFormat(f string) bool { return formats2020[f] }

// v073Formats are the formats V073 registers over the library's own: the
// two it lacks, and the two it asserts that draft 2020-12 doesn't define,
// which are annotations there.
var v073Formats = []*jsonschema.Format{
	{Name: "idn-email", Validate: validateIDNEmail},
	{Name: "idn-hostname", Validate: validateIDNHostname},
	{Name: "semver", Validate: func(any) error { return nil }},
	{Name: "period", Validate: func(any) error { return nil }},
}

// Configure sets c up to compile schemas as r says: draft 2020-12 unless a
// schema names another, format assertions on, the formats r asserts, and
// patterns read as §6.6 says. Rule schema fragments (§6.4.2) compile
// under V073.
func (r Rules) Configure(c *jsonschema.Compiler) {
	c.DefaultDraft(jsonschema.Draft2020)
	c.AssertFormat()
	c.UseRegexpEngine(r.regexpEngine)
	if r == V073 {
		for _, f := range v073Formats {
			c.RegisterFormat(f)
		}
	}
}

// regexpEngine compiles the patterns of pattern, patternProperties and the
// regex format, and of the meta-schema's checks of them.
func (r Rules) regexpEngine(s string) (jsonschema.Regexp, error) {
	re, err := r.CompileRegexp(s)
	if err != nil {
		return nil, err
	}
	return sourced{re, s}, nil
}

// CompileRegexp compiles a schema's pattern s as §6.6 reads it: RE2, with
// \uXXXX read as \x{XXXX} (pattern.Translate). Under Legacy a pattern the
// translation refuses but RE2 took as written, such as one with
// \x{D800}, compiles as it did (§6.1); no pattern RE2 took had a \u
// escape, so the translation changes none of them.
func (r Rules) CompileRegexp(s string) (*regexp.Regexp, error) {
	re, err := pattern.Compile(s)
	if err != nil && r == Legacy {
		if old, oerr := regexp.Compile(s); oerr == nil {
			return old, nil
		}
	}
	return re, err
}

// sourced is a compiled pattern that names itself as written, so messages
// quote the schema's pattern, not its translation.
type sourced struct {
	*regexp.Regexp
	src string
}

func (s sourced) String() string { return s.src }

// idnHost processes host names as UTS 46 does for lookup (RFC 5891 §5),
// nontransitional, with the Bidi rule and DNS's lengths.
var idnHost = idna.New(idna.MapForLookup(), idna.BidiRule(), idna.VerifyDNSLength(true), idna.Transitional(false))

// validateIDNHostname asserts idn-hostname: an internationalised host
// name (RFC 5890 §2.3.2.3), or an ASCII one (RFC 1123), which UTS 46
// processing accepts as well.
func validateIDNHostname(v any) error {
	s, ok := v.(string)
	if !ok {
		return nil
	}
	if _, err := idnHost.ToASCII(s); err != nil {
		return jsonschema.LocalizableError("%v", err)
	}
	return nil
}

// validateIDNEmail asserts idn-email (RFC 6531): an address whose local
// part may hold UTF-8 beyond ASCII, at an internationalised host name or
// an address literal.
func validateIDNEmail(v any) error {
	s, ok := v.(string)
	if !ok {
		return nil
	}
	at := strings.LastIndexByte(s, '@')
	if at == -1 {
		return jsonschema.LocalizableError("missing @")
	}
	local, domain := s[:at], s[at+1:]
	if local == "" {
		return jsonschema.LocalizableError("empty local part")
	}
	if len(local) > 64 {
		return jsonschema.LocalizableError("local part more than 64 octets long")
	}
	if !utf8.ValidString(local) {
		return jsonschema.LocalizableError("local part is not UTF-8")
	}
	if len(local) > 1 && strings.HasPrefix(local, `"`) && strings.HasSuffix(local, `"`) {
		for _, ch := range local[1 : len(local)-1] {
			if ch == '\\' || ch == '"' || ch < 0x20 || ch == 0x7f {
				return jsonschema.LocalizableError("invalid character %q in quoted local part", ch)
			}
		}
	} else {
		if strings.HasPrefix(local, ".") || strings.HasSuffix(local, ".") || strings.Contains(local, "..") {
			return jsonschema.LocalizableError("misplaced dot in local part")
		}
		for _, ch := range local {
			switch {
			case ch >= 'a' && ch <= 'z', ch >= 'A' && ch <= 'Z', ch >= '0' && ch <= '9':
			case strings.ContainsRune(".!#$%&'*+-/=?^_`{|}~", ch):
			case ch >= 0x80 && !unicode.IsControl(ch): // UTF8-non-ascii (RFC 6531 §3.3)
			default:
				return jsonschema.LocalizableError("invalid character %q", ch)
			}
		}
	}
	if lit, ok := strings.CutPrefix(domain, "["); ok {
		lit, ok = strings.CutSuffix(lit, "]")
		if !ok {
			return jsonschema.LocalizableError("unclosed address literal")
		}
		v6, isV6 := strings.CutPrefix(lit, "IPv6:")
		a, err := netip.ParseAddr(v6)
		if err != nil || a.Zone() != "" || a.Is4() == isV6 {
			return jsonschema.LocalizableError("invalid address literal %q", lit)
		}
		return nil
	}
	if err := validateIDNHostname(domain); err != nil {
		return jsonschema.LocalizableError("invalid domain: %v", err)
	}
	return nil
}
