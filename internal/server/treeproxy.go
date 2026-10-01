package server

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/middle-management/patchlog/internal/core"
)

// TreeProxyPrefix is where the playground reaches the tree service (Addendum
// B) through the core's origin: the playground's CSP allows connect-src
// 'self' only, and the tree service is another origin.
const TreeProxyPrefix = "/playground/tree/"

// treeSvc is the tree proxy's side of serviceProxy.
var treeSvc = serviceProxy{prefix: TreeProxyPrefix, name: "tree", timeout: 30 * time.Second, hint: ", optionally as CATALOG=URL"}

// NewTreeProxy returns a read-only reverse proxy to one or more tree services,
// to be mounted at TreeProxyPrefix. Each target is either a plain URL (e.g.
// http://tree:8082), the default, or CATALOG=URL, the tree service for that
// catalog namespace (e.g. topics=http://tree-dag:8082). One tree service may
// serve several catalogs, but a catalog service (§B.11) serves exactly one,
// hence the mapping.
//
//   - GET and HEAD /playground/tree/{catalog}/{path}?{query} go to
//     {target}/{catalog}/{path}?{query}, where target is the one mapped to
//     {catalog}, else the default (404 if there is neither). /_status goes
//     to the target mapped to ?catalog=, else the default. Authorization
//     (and conditional request headers) are forwarded; any other method is
//     405. Cookies are not forwarded.
//   - The tree service's redirects (its head pointers, §B.5) come back
//     rewritten under the prefix, so browsers follow them through the proxy.
//   - GET /playground/tree/ itself answers {"proxy":"tree","catalogs":[…],
//     "default":bool} so a client can tell that the proxy is configured, and
//     which catalogs have a mapping of their own.
//   - An unreachable tree service is 502 (e.g. while it is still starting).
//
// Responses carry a CSP that forbids everything and nosniff: they are data
// on the playground's origin and must never run as a page.
func NewTreeProxy(targets ...string) (http.Handler, error) {
	if len(targets) == 0 {
		return nil, fmt.Errorf("tree proxy: no tree url")
	}
	var def *httputil.ReverseProxy
	byCatalog := map[string]*httputil.ReverseProxy{}
	catalogs := []string{}
	for _, t := range targets {
		cat, target := splitTreeTarget(t)
		rp, err := treeSvc.reverse(target)
		if err != nil {
			return nil, err
		}
		switch {
		case cat == "" && def != nil:
			return nil, fmt.Errorf("tree url %q: more than one default tree service (map the others as CATALOG=URL)", t)
		case cat == "":
			def = rp
		case byCatalog[cat] != nil:
			return nil, fmt.Errorf("tree url %q: catalog %s is mapped twice", t, cat)
		default:
			byCatalog[cat] = rp
			catalogs = append(catalogs, cat)
		}
	}
	sort.Strings(catalogs)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if treeSvc.gate(w, r, func() map[string]any { return map[string]any{"catalogs": catalogs, "default": def != nil} }) {
			return
		}
		cat, _, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, TreeProxyPrefix), "/")
		if cat == "_status" {
			cat = r.URL.Query().Get("catalog")
		}
		rp := byCatalog[cat]
		if rp == nil {
			rp = def
		}
		if rp == nil {
			treeSvc.headers(w.Header())
			writeJSON(w, http.StatusNotFound, map[string]any{"code": "not_found", "message": "no tree service for catalog " + strconv.Quote(cat) + " (-tree-url CATALOG=URL)"})
			return
		}
		rp.ServeHTTP(w, r)
	}), nil
}

// splitTreeTarget splits CATALOG=URL. A plain URL has no catalog: what
// precedes its first "=" (if any) is never a namespace name, since it
// contains the scheme's colon.
func splitTreeTarget(t string) (catalog, target string) {
	if k, v, ok := strings.Cut(t, "="); ok && core.ValidNSName(k) {
		return k, v
	}
	return "", t
}
