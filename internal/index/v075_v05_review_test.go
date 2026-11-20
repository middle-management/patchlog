package index_test

import (
	"net/http"
	"strings"
)

// exchange exchanges tok at the index and returns its prefixes for
// matches and /_refs, and the cookies.
func (w *v75x) exchange(tok string) (ns, refs string, cookies []*http.Cookie) {
	w.t.Helper()
	r := p37Do(w.t, w.x, "POST", "/edge-grants", tok, "", nil, "")
	if r.status != 200 {
		w.t.Fatalf("exchange: %d %v", r.status, r.body)
	}
	for _, p := range r.body["prefixes"].([]any) {
		switch s := p.(string); {
		case strings.HasPrefix(s, "/matches/"):
			ns = s
		case strings.HasPrefix(s, "/_refs/"):
			refs = s
		}
	}
	if ns == "" || refs == "" {
		w.t.Fatalf("prefixes %v", r.body["prefixes"])
	}
	return ns, refs, r.cookies
}
