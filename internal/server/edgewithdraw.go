package server

import (
	"fmt"
	"net/http"
	"net/url"

	"github.com/middle-management/patchlog/internal/edge"
)

// withdrawEdgeGrants is DELETE /edge-grants?prefix=… (§C.5.4):
// 204, no-store, with an expired Set-Cookie of the same name and
// attributes for each prefix named. A browser sends the cookies only under
// their paths, never here, so the prefixes are those issuance returned.
// It needs no grant, since it only narrows; its preflight is allowed only
// for credentialed origins (internal/cors).
func (s *Server) withdrawEdgeGrants(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	prefixes, err := withdrawPrefixes(r.URL.RawQuery)
	if err != nil {
		writeErr(w, err)
		return
	}
	for _, p := range prefixes {
		http.SetCookie(w, s.cookies.Withdraw(p))
	}
	w.WriteHeader(http.StatusNoContent)
}

// withdrawPrefixes are the prefix parameters of DELETE /edge-grants, at
// least one: the only parameter it takes, and repeatable (§7, §C.5.4). Each
// has a shape issuance returns, /r/{ns}/{name}, /r/{ns} or /ns/{ns};
// repeats are withdrawn once.
func withdrawPrefixes(raw string) ([]string, error) {
	q, err := url.ParseQuery(raw)
	if err != nil {
		return nil, badInput("malformed query string")
	}
	var out []string
	seen := map[string]bool{}
	for k, vs := range q {
		if k != "prefix" {
			return nil, badInput(fmt.Sprintf("unknown query parameter %q (§7)", k))
		}
		for _, p := range vs {
			if _, _, ok := edge.ParsePrefix(p); !ok {
				return nil, badInput(fmt.Sprintf("prefix %q isn't one issuance returns: /r/{ns}/{name}, /r/{ns} or /ns/{ns} (§C.5.4)", p))
			}
			if !seen[p] {
				seen[p] = true
				out = append(out, p)
			}
		}
	}
	if len(out) == 0 {
		return nil, badInput("prefix is required (§C.5.4)")
	}
	return out, nil
}
