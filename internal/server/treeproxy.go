package server

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
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
		rp, err := newTreeReverseProxy(target)
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
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			treeProxyHeaders(w.Header())
			w.Header().Set("Allow", "GET, HEAD")
			writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"code": "bad_input", "message": "the tree proxy is read-only"})
			return
		}
		if !strings.HasPrefix(r.URL.Path, TreeProxyPrefix) {
			http.NotFound(w, r)
			return
		}
		if r.URL.Path == TreeProxyPrefix {
			treeProxyHeaders(w.Header())
			w.Header().Set("Cache-Control", "no-store")
			writeJSON(w, http.StatusOK, map[string]any{"proxy": "tree", "catalogs": catalogs, "default": def != nil})
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
			treeProxyHeaders(w.Header())
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

// newTreeReverseProxy proxies TreeProxyPrefix+{path} to {target}/{path}.
func newTreeReverseProxy(target string) (*httputil.ReverseProxy, error) {
	u, err := url.Parse(target)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("tree url %q: want http(s)://host[:port][/path], optionally as CATALOG=URL", target)
	}
	base := strings.TrimSuffix(u.Path, "/")
	return &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			rest := strings.TrimPrefix(pr.In.URL.Path, TreeProxyPrefix)
			pr.Out.URL.Scheme, pr.Out.URL.Host = u.Scheme, u.Host
			pr.Out.URL.Path, pr.Out.URL.RawPath = base+"/"+rest, ""
			pr.Out.URL.RawQuery = pr.In.URL.RawQuery
			pr.Out.Host = u.Host
			pr.Out.Header.Del("Cookie")
			pr.SetXForwarded()
		},
		Transport: &http.Transport{
			Proxy:                 nil,
			DialContext:           (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
			ResponseHeaderTimeout: 30 * time.Second,
			MaxIdleConnsPerHost:   8,
			IdleConnTimeout:       90 * time.Second,
		},
		ModifyResponse: func(res *http.Response) error {
			if loc := res.Header.Get("Location"); loc != "" {
				res.Header.Set("Location", rewriteTreeLocation(loc, u, base))
			}
			res.Header.Del("Set-Cookie")
			treeProxyHeaders(res.Header)
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			treeProxyHeaders(w.Header())
			writeJSON(w, http.StatusBadGateway, map[string]any{"code": "upstream", "message": "the tree service is not reachable (yet)"})
		},
	}, nil
}

func treeProxyHeaders(h http.Header) {
	h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; sandbox")
	h.Set("X-Content-Type-Options", "nosniff")
}

// rewriteTreeLocation maps a tree service redirect target into the proxy's
// URL space: an absolute path, or an absolute URL on the tree service's own
// origin, below its base path. Anything else is left alone.
func rewriteTreeLocation(loc string, target *url.URL, base string) string {
	l, err := url.Parse(loc)
	if err != nil {
		return loc
	}
	if l.IsAbs() || l.Host != "" {
		if !strings.EqualFold(l.Host, target.Host) {
			return loc
		}
	} else if !strings.HasPrefix(l.Path, "/") {
		return loc
	}
	p := l.Path
	if base != "" {
		if p != base && !strings.HasPrefix(p, base+"/") {
			return loc
		}
		p = strings.TrimPrefix(p, base)
	}
	out := TreeProxyPrefix + strings.TrimPrefix(p, "/")
	if l.RawQuery != "" {
		out += "?" + l.RawQuery
	}
	return out
}
