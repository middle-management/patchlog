package tree

import (
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/middle-management/patchlog/internal/derived"
)

// Multi serves several tree services, one per catalog, on one origin. Each
// Service keeps its own database, graph and followers; Multi only routes:
//
//	GET /{catalog}/…               that catalog's listings, exactly as its
//	                               Service serves them (§B.5)
//	GET /_status                   every followed namespace once (a content
//	                               namespace trusted by several catalogs is
//	                               followed by each, and listed as the first
//	                               catalog's service sees it), the catalogs,
//	                               and each catalog's own status under
//	                               "byCatalog"
//	GET /_status?catalog={catalog} that catalog's status alone
//
// Anything else is 404. Grants (§B.11) are not routed: a catalog service
// serves exactly one catalog.
func Multi(svcs ...*Service) (http.Handler, error) {
	by := map[string]*Service{}
	var cats []string
	for _, s := range svcs {
		c := s.Catalog()
		if by[c] != nil {
			return nil, fmt.Errorf("tree: catalog %s is served twice", c)
		}
		by[c] = s
		cats = append(cats, c)
	}
	sort.Strings(cats)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		first, _, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, "/"), "/")
		if first == "_status" && r.URL.Path == "/_status" {
			if r.Method != http.MethodGet && r.Method != http.MethodHead {
				w.Header().Set("Allow", "GET, HEAD")
				WriteError(w, http.StatusMethodNotAllowed, "bad_input", "method not allowed")
				return
			}
			if c := r.URL.Query().Get("catalog"); c != "" {
				s := by[c]
				if s == nil {
					WriteError(w, http.StatusNotFound, "not_found", "no such catalog")
					return
				}
				s.serveStatus(w)
				return
			}
			seen := map[string]bool{}
			all := []derived.Status{}
			byCat := map[string]any{}
			for _, c := range cats {
				st := by[c].status()
				byCat[c] = st
				for _, x := range st {
					if !seen[x.NS] {
						seen[x.NS] = true
						all = append(all, x)
					}
				}
			}
			sort.Slice(all, func(i, j int) bool { return all[i].NS < all[j].NS })
			w.Header().Set("Cache-Control", "no-store")
			WriteJSON(w, http.StatusOK, map[string]any{"namespaces": all, "catalogs": cats, "byCatalog": byCat})
			return
		}
		if s := by[first]; s != nil {
			s.serveHTTP(w, r)
			return
		}
		WriteError(w, http.StatusNotFound, "not_found", "not found")
	}), nil
}
