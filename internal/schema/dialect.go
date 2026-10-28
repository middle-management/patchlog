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

// Rules marks the rules a schema revision was written under. Since v0.74
// every schema compiles under this version, whenever it was stored
// (§6.1, §6.2 step 5): the marker a revision row carries, and the
// RulesHeader it is served with, are metadata that select nothing in a
// schema's compile (Validator). Rules still configures a rule's schema
// fragment (ConfigureFragment), which internal/rules compiles under the
// marker of the namespace document it is stored in.
type Rules uint8

const (
	// Legacy is how v0.55 compiled every schema: the library's formats
	// asserted, semver and period included, idn-email and idn-hostname
	// not, and other names ignored. A pattern \uXXXX translation refuses
	// but RE2 took as written still compiles. Revisions stored before
	// markers were kept, and those whose marker the caller doesn't know,
	// carry it; only a stored rule fragment still compiles under it.
	Legacy Rules = iota
	// V073 asserts exactly the format set of draft 2020-12 (§6.2 step 5),
	// idn-email and idn-hostname by RFC 5890 without UTS 46 mapping, and
	// reads patterns as §6.6 says. Every schema compiles under it.
	V073
)

// current is the rules every schema compiles under (§6.1, §6.2 step 5).
const current = V073

func (r Rules) String() string {
	if r == V073 {
		return "v0.73"
	}
	return "legacy"
}

// RulesHeader is the response header a revision read of a schema
// document served in the clear carries, naming its marker (Rules.String):
// an addition, kept as metadata. Since v0.74 it selects nothing: every
// schema compiles under this version (§6.1).
const RulesHeader = "X-Schema-Rules"

// ParseRules reads a marker as Rules.String writes it.
func ParseRules(s string) (Rules, bool) {
	switch s {
	case "v0.73":
		return V073, true
	case "legacy":
		return Legacy, true
	}
	return Legacy, false
}

// formats2020 is the format set draft 2020-12 defines. A schema naming
// any other is invalid, as an unknown keyword is (§6.2 step 5, §6.5),
// whenever it was stored (§6.1).
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

// idnFormats are the two formats of draft 2020-12 the library lacks.
var idnFormats = []*jsonschema.Format{
	{Name: "idn-email", Validate: validateIDNEmail},
	{Name: "idn-hostname", Validate: validateIDNHostname},
}

// v073Formats are the formats V073 registers over the library's own: the
// two it lacks, and the two it asserts that draft 2020-12 doesn't define,
// which are annotations there.
var v073Formats = append([]*jsonschema.Format{
	{Name: "semver", Validate: func(any) error { return nil }},
	{Name: "period", Validate: func(any) error { return nil }},
}, idnFormats...)

// Configure sets c up to compile schemas as r says: draft 2020-12 unless a
// schema names another, format assertions on, the formats r asserts, and
// patterns read as §6.6 says. Every schema compiles as V073 says (§6.1);
// a caller compiling one itself, as the annotation walks do, configures
// with V073. Rule schema fragments (§6.4.2) compile by ConfigureFragment.
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

// ConfigureFragment is Configure for a rule's schema fragment, which is
// applied with format assertions as at step 5 of §6.2 whenever it was
// written (§6.4.2): §6.1's "compiled as that version did" is a schema
// document's. Under Legacy, a fragment stored before, idn-email and
// idn-hostname are asserted too, as under V073, and the library's other
// formats as v0.55 asserted them, semver and period included. So a
// fragment written now evaluates alike under either marker.
func (r Rules) ConfigureFragment(c *jsonschema.Compiler) {
	r.Configure(c)
	if r == Legacy {
		for _, f := range idnFormats {
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
// \uXXXX read as \x{XXXX} (pattern.Translate), a lone surrogate, or one
// written \x{…}, refused. Every schema's patterns compile so (§6.1), by
// V073; under Legacy, for a rule fragment stored before
// (ConfigureFragment), a pattern the translation refuses but RE2 took as
// written, such as one with \x{D800}, compiles as it did; no pattern RE2
// took had a \u escape, so the translation changes none of them.
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

// idnHost checks host names as RFC 5890 defines them, without UTS 46
// mapping (§6.2 step 5): IDNA2008's registration rules (RFC 5891 §4),
// which refuse any code point UTS 46 would map (an uppercase or fullwidth
// letter in a U-label), with the Bidi rule (RFC 5893), CONTEXTJ and DNS's
// lengths. The profile leaves out RFC 5892's CONTEXTO rules, which
// contextO checks after it.
var idnHost = idna.New(idna.ValidateForRegistration())

// validateIDNHostname asserts idn-hostname: a host name of labels that are
// each a U-label or an A-label (RFC 5890 §2.3.2.1), checked as they are,
// never mapped first, or an NR-LDH label (§2.3.1). An all-ASCII label is
// judged as LDH, case-insensitively as DNS compares it, so EXAMPLE.com
// passes as example.com does, and an A-label in any case must decode to a
// valid U-label; a label with any other code point must be a U-label as
// written.
func validateIDNHostname(v any) error {
	s, ok := v.(string)
	if !ok {
		return nil
	}
	f := foldLDH(s)
	if _, err := idnHost.ToASCII(f); err != nil {
		return jsonschema.LocalizableError("%v", err)
	}
	u, err := idnHost.ToUnicode(f)
	if err != nil {
		return jsonschema.LocalizableError("%v", err)
	}
	for _, l := range strings.Split(u, ".") {
		if err := contextO(l); err != nil {
			return err
		}
	}
	return nil
}

// contextO checks a U-label against RFC 5892 Appendix A's CONTEXTO rules,
// part of a U-label's validity (RFC 5891 §4.2.3.3, §5.4): a MIDDLE DOT
// between two l, a GREEK KERAIA before a Greek letter, a HEBREW GERESH or
// GERSHAYIM after a Hebrew one, a KATAKANA MIDDLE DOT in a label with a
// Hiragana, Katakana or Han character, and Arabic-Indic digits not mixed
// with extended ones.
func contextO(label string) error {
	rs := []rune(label)
	at := func(i int) rune {
		if i < 0 || i >= len(rs) {
			return -1
		}
		return rs[i]
	}
	var arabic, extended, kana bool
	for _, r := range rs {
		switch {
		case r >= 0x0660 && r <= 0x0669:
			arabic = true
		case r >= 0x06F0 && r <= 0x06F9:
			extended = true
		case unicode.In(r, unicode.Hiragana, unicode.Katakana, unicode.Han):
			kana = true
		}
	}
	for i, r := range rs {
		ok := true
		switch r {
		case 0x00B7:
			ok = at(i-1) == 'l' && at(i+1) == 'l'
		case 0x0375:
			ok = at(i+1) >= 0 && unicode.Is(unicode.Greek, at(i+1))
		case 0x05F3, 0x05F4:
			ok = at(i-1) >= 0 && unicode.Is(unicode.Hebrew, at(i-1))
		case 0x30FB:
			ok = kana
		}
		if !ok {
			return jsonschema.LocalizableError("idna: %+q in label %q breaks its CONTEXTO rule (RFC 5892)", r, label)
		}
	}
	if arabic && extended {
		return jsonschema.LocalizableError("idna: label %q mixes Arabic-Indic and extended Arabic-Indic digits (RFC 5892)", label)
	}
	return nil
}

// foldLDH returns s with each all-ASCII label in lowercase, the case LDH
// labels are compared in (RFC 5890 §2.3.1); labels holding anything else
// are left as written, for the registration rules to judge unmapped.
func foldLDH(s string) string {
	labels := strings.Split(s, ".")
	changed := false
	for i, l := range labels {
		if isASCII(l) && strings.ToLower(l) != l {
			labels[i], changed = strings.ToLower(l), true
		}
	}
	if !changed {
		return s
	}
	return strings.Join(labels, ".")
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= utf8.RuneSelf {
			return false
		}
	}
	return true
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
