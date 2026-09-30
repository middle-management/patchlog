package server

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"
)

// TreeProxyPrefix is where the playground reaches the tree service (Addendum
// B) through the core's origin: the playground's CSP allows connect-src
// 'self' only, and the tree service is another origin.
const TreeProxyPrefix = "/playground/tree/"

// NewTreeProxy returns a read-only reverse proxy to the tree service at
// target (e.g. http://tree:8082), to be mounted at TreeProxyPrefix:
//
//   - GET and HEAD /playground/tree/{path}?{query} go to {target}/{path}?{query},
//     with Authorization (and conditional request headers) forwarded; any
//     other method is 405. Cookies are not forwarded.
//   - The tree service's redirects (its head pointers, §B.5) come back
//     rewritten under the prefix, so browsers follow them through the proxy.
//   - GET /playground/tree/ itself answers {"proxy":"tree"} so a client can
//     tell that the proxy is configured.
//   - An unreachable tree service is 502 (e.g. while it is still starting).
//
// Responses carry a CSP that forbids everything and nosniff: they are data
// on the playground's origin and must never run as a page.
func NewTreeProxy(target string) (http.Handler, error) {
	u, err := url.Parse(target)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("tree url %q: want http(s)://host[:port][/path]", target)
	}
	base := strings.TrimSuffix(u.Path, "/")
	rp := &httputil.ReverseProxy{
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
	}
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
			writeJSON(w, http.StatusOK, map[string]any{"proxy": "tree"})
			return
		}
		rp.ServeHTTP(w, r)
	}), nil
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
