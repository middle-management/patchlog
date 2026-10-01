// Package cors lets browser pages on other origins call the servers (the
// core, the index and the tree service).
//
// Requests carry their credentials in the Authorization header (Addendum
// C), which a page sets itself, so cross-origin reads and writes need no
// cookies: Access-Control-Allow-Credentials is sent only when configured.
//
// With "*", every origin is allowed and responses are the same for all of
// them, so shared caches (the CDN, §9) keep one copy. With a list, the
// matching origin is echoed and every response carries Vary: Origin, so a
// cache keeps one copy per origin and never serves one origin's allowance
// to another.
package cors

import (
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Config is which origins may call, and how.
type Config struct {
	// Origins are allowed origins, e.g. "https://app.example", or "*" for
	// any. Empty disables CORS.
	Origins []string
	// Credentials sends Access-Control-Allow-Credentials, for pages that
	// send cookies. Not allowed with "*".
	Credentials bool
	// MaxAge is how long browsers may cache a preflight; zero means 10
	// minutes.
	MaxAge time.Duration
}

// Methods are the methods the API uses.
const Methods = "GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS"

// Headers are the request headers the API reads beyond the CORS-safelisted
// ones: credentials (§C.1), preconditions (§7.2), author signatures
// (§C.3), blob uploads and copies (§7.8), ranges and event-stream resumes
// (§9), and X-Author, which names the author when authentication is off
// (serve -dev). The edge's verification header (-edge-header) is left out
// on purpose: a browser has no business sending it.
const Headers = "Authorization, Content-Type, If-Match, If-None-Match, If-Range, Range, Signature, Source-Authorization, Blob-From, Blob-Nonce, Last-Event-ID, X-Author"

// Exposed are the response headers pages may read beyond the safelisted
// ones.
const Exposed = "ETag, Location, Retry-After, Allow, WWW-Authenticate, Accept-Ranges, Content-Range, X-Namespace-Revision, X-Config-Revision, X-Revision, X-Cursor, X-E2E"

// Parse splits comma-separated origins, as given on the command line, and
// checks them: each is "*" or a scheme://host[:port] without a path.
func Parse(values []string) ([]string, error) {
	var out []string
	for _, v := range values {
		for _, o := range strings.Split(v, ",") {
			o = strings.TrimSpace(o)
			if o == "" {
				continue
			}
			if o != "*" {
				o = strings.TrimSuffix(o, "/")
				scheme, host, ok := strings.Cut(o, "://")
				if !ok || (scheme != "http" && scheme != "https") || host == "" || strings.ContainsAny(host, "/?#") {
					return nil, &originError{o}
				}
			}
			out = append(out, o)
		}
	}
	return out, nil
}

type originError struct{ origin string }

func (e *originError) Error() string {
	return "invalid CORS origin " + strconv.Quote(e.origin) + ": want * or scheme://host[:port]"
}

// Wrap adds CORS to h. With no origins configured it returns h.
func Wrap(h http.Handler, c Config) http.Handler {
	if len(c.Origins) == 0 {
		return h
	}
	anyOrigin := slices.Contains(c.Origins, "*")
	maxAge := c.MaxAge
	if maxAge <= 0 {
		maxAge = 10 * time.Minute
	}
	age := strconv.Itoa(int(maxAge.Seconds()))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hd := w.Header()
		if !anyOrigin {
			// Before the handler writes anything: it adds its own Vary
			// values (Authorization) rather than replacing these.
			hd.Add("Vary", "Origin")
		}
		origin := r.Header.Get("Origin")
		allowed := origin != "" && (anyOrigin || slices.Contains(c.Origins, origin))
		if allowed {
			if anyOrigin && !c.Credentials {
				hd.Set("Access-Control-Allow-Origin", "*")
			} else {
				hd.Set("Access-Control-Allow-Origin", origin)
			}
			if c.Credentials {
				hd.Set("Access-Control-Allow-Credentials", "true")
			}
		}
		if r.Method == http.MethodOptions && r.Header.Get("Access-Control-Request-Method") != "" {
			// A preflight: answered here, never by the API.
			if !anyOrigin {
				hd.Add("Vary", "Access-Control-Request-Method")
				hd.Add("Vary", "Access-Control-Request-Headers")
			}
			if allowed {
				hd.Set("Access-Control-Allow-Methods", Methods)
				hd.Set("Access-Control-Allow-Headers", Headers)
				hd.Set("Access-Control-Max-Age", age)
			}
			hd.Set("Cache-Control", "no-store")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if allowed {
			hd.Set("Access-Control-Expose-Headers", Exposed)
		}
		h.ServeHTTP(w, r)
	})
}
