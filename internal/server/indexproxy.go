package server

import (
	"net/http"
	"time"
)

// IndexProxyPrefix is where the playground reaches the search index
// (Addendum A) through the core's origin, for the same reason as
// TreeProxyPrefix.
const IndexProxyPrefix = "/playground/index/"

// indexResponseTimeout bounds how long the index may take to answer: a
// request with ?min= waits for the index to catch up (§A.5, the index's
// -min-wait, 2s unless set higher) and then asks the core once more.
const indexResponseTimeout = 2 * time.Minute

// NewIndexProxy returns a read-only reverse proxy to one search index, to be
// mounted at IndexProxyPrefix. The index serves several namespaces, each at
// /{ns}, so one URL does.
//
//   - GET and HEAD /playground/index/{path}?{query} go to {target}/{path}?{query}
//     (see serviceProxy for what is and isn't forwarded).
//   - The index's checkpoint redirects (302 /{ns}?… → /{ns}/at/{ns_id}?…, also
//     for ?min= waits and under /g/{subject set}/) come back under the prefix.
//     The "next" links in a result body are paths of the index itself, which
//     a client prefixes with IndexProxyPrefix.
//   - GET /playground/index/ itself answers {"proxy":"index"} so a client
//     can tell that the proxy is configured.
func NewIndexProxy(target string) (http.Handler, error) {
	s := serviceProxy{prefix: IndexProxyPrefix, name: "index", timeout: indexResponseTimeout}
	rp, err := s.reverse(target)
	if err != nil {
		return nil, err
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.gate(w, r, nil) {
			return
		}
		rp.ServeHTTP(w, r)
	}), nil
}
