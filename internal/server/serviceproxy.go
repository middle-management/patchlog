package server

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/middle-management/patchlog/internal/telemetry"
)

// serviceProxy is what the playground's read-only proxies to the search
// index (IndexProxyPrefix) and the tree service (TreeProxyPrefix) have in
// common. The playground's CSP allows connect-src 'self' only, and those
// services are other origins, so the core relays reads for it:
//
//   - GET and HEAD only; any other method is 405 without reaching the
//     service. Authorization and conditional request headers are forwarded,
//     Cookie is not and Set-Cookie never comes back.
//   - The service's redirects (head pointers, checkpoints) come back
//     rewritten under the prefix, so browsers follow them through the proxy.
//   - Upstream Access-Control-* headers are dropped (the core's own
//     -cors-origin applies), and every response carries a CSP that forbids
//     everything, and nosniff: the bytes are data on the playground's
//     origin and must never run as a page.
//   - An unreachable service is 502 (e.g. while it is still starting).
type serviceProxy struct {
	prefix  string        // e.g. "/playground/tree/"
	name    string        // "tree": the probe's "proxy" and the messages
	timeout time.Duration // how long a service may take to start answering
	hint    string        // appended to the bad-URL message
}

// reverse proxies prefix+{path} to {target}/{path}.
func (s serviceProxy) reverse(target string) (*httputil.ReverseProxy, error) {
	u, err := url.Parse(target)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("%s url %q: want http(s)://host[:port][/path]%s", s.name, target, s.hint)
	}
	base := strings.TrimSuffix(u.Path, "/")
	return &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			rest := strings.TrimPrefix(pr.In.URL.Path, s.prefix)
			pr.Out.URL.Scheme, pr.Out.URL.Host = u.Scheme, u.Host
			pr.Out.URL.Path, pr.Out.URL.RawPath = base+"/"+rest, ""
			pr.Out.URL.RawQuery = pr.In.URL.RawQuery
			pr.Out.Host = u.Host
			pr.Out.Header.Del("Cookie")
			pr.SetXForwarded()
		},
		Transport: telemetry.Transport(&http.Transport{
			Proxy:                 nil,
			DialContext:           (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
			ResponseHeaderTimeout: s.timeout,
			MaxIdleConnsPerHost:   8,
			IdleConnTimeout:       90 * time.Second,
		}),
		ModifyResponse: func(res *http.Response) error {
			if loc := res.Header.Get("Location"); loc != "" {
				res.Header.Set("Location", s.rewriteLocation(loc, u, base))
			}
			res.Header.Del("Set-Cookie")
			s.headers(res.Header)
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			s.headers(w.Header())
			writeJSON(w, http.StatusBadGateway, map[string]any{"code": "upstream", "message": "the " + s.name + " service is not reachable (yet)"})
		},
	}, nil
}

// gate answers what is never proxied: other methods (405), paths outside the
// prefix (404) and the prefix itself, which says that the proxy is there
// (extra adds to that answer). It reports whether it answered.
func (s serviceProxy) gate(w http.ResponseWriter, r *http.Request, extra func() map[string]any) bool {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		s.headers(w.Header())
		w.Header().Set("Allow", "GET, HEAD")
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"code": "bad_input", "message": "the " + s.name + " proxy is read-only"})
		return true
	}
	if !strings.HasPrefix(r.URL.Path, s.prefix) {
		http.NotFound(w, r)
		return true
	}
	if r.URL.Path == s.prefix {
		s.headers(w.Header())
		w.Header().Set("Cache-Control", "no-store")
		body := map[string]any{"proxy": s.name}
		if extra != nil {
			for k, v := range extra() {
				body[k] = v
			}
		}
		writeJSON(w, http.StatusOK, body)
		return true
	}
	return false
}

func (s serviceProxy) headers(h http.Header) {
	// The core's own CORS (-cors-origin) applies to proxied responses,
	// not whatever the service answers with.
	for k := range h {
		if strings.HasPrefix(k, "Access-Control-") {
			h.Del(k)
		}
	}
	h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; sandbox")
	h.Set("X-Content-Type-Options", "nosniff")
}

// rewriteLocation maps a service redirect target into the proxy's URL
// space: an absolute path, or an absolute URL on the service's own origin,
// below its base path. Anything else is left alone.
func (s serviceProxy) rewriteLocation(loc string, target *url.URL, base string) string {
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
	out := s.prefix + strings.TrimPrefix(p, "/")
	if l.RawQuery != "" {
		out += "?" + l.RawQuery
	}
	return out
}
