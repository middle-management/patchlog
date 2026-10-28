package schema

import (
	"errors"
	"testing"
)

// CORE-2 (§6.2 step 5, Open 55): idn-hostname and idn-email by RFC 5890's
// rules without UTS 46 mapping. A U-label is judged as written, so an
// uppercase or fullwidth letter in one is refused; an all-ASCII label is
// LDH, compared case-insensitively.
func TestV074V03IDNHostnameUnmapped(t *testing.T) {
	t.Parallel()
	for _, x := range []struct {
		host string
		ok   bool
	}{
		{"bücher.example", true},
		{"EXAMPLE.com", true},
		{"Example.COM", true},
		{"example.com", true},
		{"xn--bcher-kva.example", true},
		{"XN--BCHER-KVA.example", true},
		{"실례.테스트", true},
		{"ßς.example", true},
		{"localhost", true},
		{"ｅｘａｍｐｌｅ.com", false},    // fullwidth: UTS 46 maps it
		{"Bücher.example", false}, // uppercase in a U-label
		{"BÜCHER.example", false},
		{"bücher.example", false}, // not NFC
		{"-bad-", false},
		{"-bad-.se", false},
		{"ex ample.com", false},
		{"xn--X", false},
		{"XN--aa---o47jg78q", false},
		{"a..b", false},
		{"", false},
	} {
		err := validateIDNHostname(x.host)
		if (err == nil) != x.ok {
			t.Errorf("idn-hostname %q: err %v, want ok %v", x.host, err, x.ok)
		}
	}
	for _, x := range []struct {
		addr string
		ok   bool
	}{
		{"jörg@bücher.example", true},
		{"a@EXAMPLE.com", true},
		{"a@Bücher.example", false},
		{"a@ｅｘａｍｐｌｅ.com", false},
	} {
		err := validateIDNEmail(x.addr)
		if (err == nil) != x.ok {
			t.Errorf("idn-email %q: err %v, want ok %v", x.addr, err, x.ok)
		}
	}
}

// The validator applies it to a document typed by a schema naming
// idn-hostname: a refusal points at the value (§6.2 step 5).
func TestV074V03IDNHostnameValidate(t *testing.T) {
	t.Parallel()
	st := newStore()
	path := "/r/schemas/host/rev/" + rev('h')
	st.docs[path] = j(`{` + d073 + `,"type":"object","properties":{"h":{"format":"idn-hostname"},"e":{"format":"idn-email"}}}`)
	v := NewValidator()
	for _, x := range []struct {
		doc     string
		pointer string
	}{
		{`{"h":"bücher.example","e":"a@EXAMPLE.com"}`, ""},
		{`{"h":"Bücher.example"}`, "/h"},
		{`{"h":"ｅｘａｍｐｌｅ.com"}`, "/h"},
		{`{"e":"a@Bücher.example"}`, "/e"},
	} {
		doc := j(x.doc)
		doc.(map[string]any)["$schema"] = path
		err := v.ValidateRules(doc, st.load, V073)
		if x.pointer == "" {
			if err != nil {
				t.Errorf("%s: %v", x.doc, err)
			}
			continue
		}
		var ve *ValidationError
		if !errors.As(err, &ve) || len(ve.Errors) == 0 || ve.Errors[0].Pointer != x.pointer {
			t.Errorf("%s: %v, want a refusal at %s", x.doc, err, x.pointer)
		}
	}
}

// A U-label's validity under RFC 5890 includes RFC 5892's CONTEXTO rules
// (RFC 5891 §4.2.3.3, §5.4), which IDNA2008's registration profile in
// x/net/idna leaves out (§6.2 step 5); an A-label decoding to such a label
// is refused as the U-label is.
func TestV074V03IDNContextO(t *testing.T) {
	t.Parallel()
	for _, x := range []struct {
		host string
		ok   bool
	}{
		{"l·l.com", true},
		{"a·l.com", false}, // MIDDLE DOT not between two l
		{"·l.com", false},
		{"l·.com", false},
		{"xn--al-0ea.com", false}, // a·l as an A-label
		{"・ア.com", true},
		{"漢・.com", true},
		{"・.com", false}, // KATAKANA MIDDLE DOT without Hiragana, Katakana or Han
		{"͵α.com", true},
		{"a͵.com", false}, // GREEK KERAIA not followed by Greek
		{"͵.com", false},
		{"א׳.com", true},
		{"׳.com", false},  // HEBREW GERESH not preceded by Hebrew
		{"״א.com", false}, // HEBREW GERSHAYIM likewise
		{"ب١٢.com", true},
		{"ب١۲.com", false}, // Arabic-Indic and extended digits mixed
	} {
		err := validateIDNHostname(x.host)
		if (err == nil) != x.ok {
			t.Errorf("idn-hostname %+q: err %v, want ok %v", x.host, err, x.ok)
		}
		err = validateIDNEmail("a@" + x.host)
		if (err == nil) != x.ok {
			t.Errorf("idn-email a@%+q: err %v, want ok %v", x.host, err, x.ok)
		}
	}
}
