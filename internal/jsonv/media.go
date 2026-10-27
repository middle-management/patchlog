package jsonv

import (
	"mime"
	"strings"
)

// MediaType reports whether contentType, a request's Content-Type header,
// names the media type want (lowercase), compared as RFC 9110 section
// 8.3.1 says: type and subtype ignoring case, with no parameter but an
// optional charset naming UTF-8, in any case (§7.2). Any other parameter,
// another charset, or a header that doesn't parse, is a different type.
func MediaType(contentType, want string) bool {
	mt, params, err := mime.ParseMediaType(contentType)
	if err != nil || mt != want {
		return false
	}
	for k, v := range params {
		if k != "charset" || !strings.EqualFold(v, "utf-8") {
			return false
		}
	}
	return true
}
