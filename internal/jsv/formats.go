package jsv

import (
	"net/netip"
	"net/url"
	"strings"
)

// builtinFormats are the formats checked when format is asserted. They
// read each format the way github.com/santhosh-tekuri/jsonschema/v6 does,
// which this package is measured against. regex is checked with the
// schema's regexp engine, and a name not here (idn-email and idn-hostname
// among them) passes unless Options.Formats supplies it.
var builtinFormats = map[string]func(string) bool{
	"date-time":             isDateTime,
	"date":                  isDate,
	"time":                  isTime,
	"duration":              isDuration,
	"email":                 isEmail,
	"hostname":              isHostname,
	"ipv4":                  isIPv4,
	"ipv6":                  isIPv6,
	"uri":                   isURI,
	"iri":                   isURI,
	"uri-reference":         isURIReference,
	"iri-reference":         isURIReference,
	"uri-template":          isURITemplate,
	"uuid":                  isUUID,
	"json-pointer":          isJSONPointer,
	"relative-json-pointer": isRelativeJSONPointer,
}

func digits(s string) (n int, ok bool) {
	if s == "" {
		return 0, false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
		n = n*10 + int(s[i]-'0')
	}
	return n, true
}

// isDate reads an RFC 3339 full-date.
func isDate(s string) bool {
	if len(s) != 10 || s[4] != '-' || s[7] != '-' {
		return false
	}
	y, ok1 := digits(s[:4])
	m, ok2 := digits(s[5:7])
	d, ok3 := digits(s[8:])
	if !ok1 || !ok2 || !ok3 || m < 1 || m > 12 || d < 1 {
		return false
	}
	days := 31
	switch m {
	case 4, 6, 9, 11:
		days = 30
	case 2:
		days = 28
		if y%4 == 0 && (y%100 != 0 || y%400 == 0) {
			days = 29
		}
	}
	return d <= days
}

// isTime reads an RFC 3339 full-time, a leap second only at 23:59:60 UTC.
func isTime(s string) bool {
	if len(s) < 9 || s[2] != ':' || s[5] != ':' {
		return false
	}
	h, ok1 := digits(s[:2])
	m, ok2 := digits(s[3:5])
	sec, ok3 := digits(s[6:8])
	if !ok1 || !ok2 || !ok3 || h > 23 || m > 59 || sec > 60 {
		return false
	}
	s = s[8:]
	if s[0] == '.' {
		i := 1
		for i < len(s) && s[i] >= '0' && s[i] <= '9' {
			i++
		}
		if i == 1 {
			return false
		}
		s = s[i:]
	}
	if s != "z" && s != "Z" {
		if len(s) != 6 || s[3] != ':' {
			return false
		}
		sign := 0
		switch s[0] {
		case '+':
			sign = -1
		case '-':
			sign = 1
		default:
			return false
		}
		zh, ok1 := digits(s[1:3])
		zm, ok2 := digits(s[4:])
		if !ok1 || !ok2 || zh > 23 || zm > 59 {
			return false
		}
		hm := h*60 + m + sign*(zh*60+zm)
		if hm < 0 {
			hm += 24 * 60
		}
		h, m = hm/60, hm%60
	}
	return sec < 60 || h == 23 && m == 59
}

func isDateTime(s string) bool {
	if len(s) < 20 || s[10] != 't' && s[10] != 'T' {
		return false
	}
	return isDate(s[:10]) && isTime(s[11:])
}

// isDuration reads an RFC 3339 Appendix A duration.
func isDuration(s string) bool {
	s, ok := strings.CutPrefix(s, "P")
	if !ok || s == "" {
		return false
	}
	if w, ok := strings.CutSuffix(s, "W"); ok {
		_, ok := digits(w)
		return ok
	}
	date, time, hasTime := strings.Cut(s, "T")
	if hasTime && (time == "" || strings.Contains(time, "T")) {
		return false
	}
	return durationPart(date, "YMD") && durationPart(time, "HMS")
}

func durationPart(s, units string) bool {
	for s != "" {
		i := 0
		for i < len(s) && s[i] >= '0' && s[i] <= '9' {
			i++
		}
		if i == 0 || i == len(s) {
			return false
		}
		j := strings.IndexByte(units, s[i])
		if j < 0 {
			return false
		}
		units = units[j+1:]
		s = s[i+1:]
	}
	return true
}

func isIPv4(s string) bool {
	for i := 0; i < 4; i++ {
		g := s
		if i < 3 {
			j := strings.IndexByte(s, '.')
			if j < 0 {
				return false
			}
			g, s = s[:j], s[j+1:]
		}
		if len(g) > 1 && g[0] == '0' || len(g) > 3 {
			return false
		}
		if n, ok := digits(g); !ok || n > 255 {
			return false
		}
	}
	return true
}

func isIPv6(s string) bool {
	if !strings.Contains(s, ":") {
		return false
	}
	a, err := netip.ParseAddr(s)
	return err == nil && a.Zone() == ""
}

func isHostname(s string) bool {
	s = strings.TrimSuffix(s, ".")
	if len(s) > 253 {
		return false
	}
	for {
		label, rest, more := strings.Cut(s, ".")
		if len(label) < 1 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
		if !more {
			return true
		}
		s = rest
	}
}

func isEmail(s string) bool {
	if len(s) > 254 {
		return false
	}
	at := strings.LastIndexByte(s, '@')
	if at < 0 {
		return false
	}
	local, domain := s[:at], s[at+1:]
	if len(local) > 64 {
		return false
	}
	if len(local) > 1 && local[0] == '"' && local[len(local)-1] == '"' {
		if strings.ContainsAny(local[1:len(local)-1], `\"`) {
			return false
		}
	} else {
		if strings.HasPrefix(local, ".") || strings.HasSuffix(local, ".") || strings.Contains(local, "..") {
			return false
		}
		for _, c := range local {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune(".!#$%&'*+-/=?^_`{|}~", c)) {
				return false
			}
		}
	}
	if strings.HasPrefix(domain, "[") && strings.HasSuffix(domain, "]") {
		domain = domain[1 : len(domain)-1]
		if v6, ok := strings.CutPrefix(domain, "IPv6:"); ok {
			return isIPv6(v6)
		}
		return isIPv4(domain)
	}
	return isHostname(domain)
}

func parseURL(s string) (*url.URL, bool) {
	u, err := url.Parse(s)
	if err != nil {
		return nil, false
	}
	// net/url does not check an IPv6 host.
	if host := u.Hostname(); strings.Contains(host, ":") {
		if !strings.Contains(u.Host, "[") || !strings.Contains(u.Host, "]") || !isIPv6(host) {
			return nil, false
		}
	}
	return u, true
}

func isURI(s string) bool {
	u, ok := parseURL(s)
	return ok && u.IsAbs()
}

func isURIReference(s string) bool {
	if strings.Contains(s, `\`) {
		return false
	}
	_, ok := parseURL(s)
	return ok
}

func isURITemplate(s string) bool {
	u, ok := parseURL(s)
	if !ok {
		return false
	}
	for _, seg := range strings.Split(u.RawPath, "/") {
		seg, err := url.PathUnescape(seg)
		if err != nil {
			return false
		}
		open := false
		for _, c := range seg {
			switch c {
			case '{':
				if open {
					return false
				}
				open = true
			case '}':
				if !open {
					return false
				}
				open = false
			}
		}
		if open {
			return false
		}
	}
	return true
}

func isUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
				return false
			}
		}
	}
	return true
}

func isJSONPointer(s string) bool {
	if s == "" {
		return true
	}
	if s[0] != '/' {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] == '~' && (i+1 == len(s) || s[i+1] != '0' && s[i+1] != '1') {
			return false
		}
	}
	return true
}

func isRelativeJSONPointer(s string) bool {
	i := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	if i == 0 || i > 1 && s[0] == '0' {
		return false
	}
	return s[i:] == "#" || isJSONPointer(s[i:])
}
