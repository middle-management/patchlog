package cors

import (
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"
)

func api() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Handlers add their own Vary values (index, tree).
		w.Header().Add("Vary", "Authorization")
		w.Header().Set("ETag", `"x"`)
		w.WriteHeader(200)
	})
}

func do(h http.Handler, method, origin string, hdr map[string]string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "/r/ns/a", nil)
	if origin != "" {
		r.Header.Set("Origin", origin)
	}
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestDisabled(t *testing.T) {
	h := api()
	if Wrap(h, Config{}) == nil {
		t.Fatal("nil handler")
	}
	w := do(Wrap(h, Config{}), "GET", "https://a.example", nil)
	if w.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("CORS headers without configuration")
	}
}

func TestAnyOrigin(t *testing.T) {
	h := Wrap(api(), Config{Origins: []string{"*"}})
	w := do(h, "GET", "https://a.example", nil)
	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "*" {
		t.Fatalf("allow-origin %q", got)
	}
	if w.Header().Get("Access-Control-Expose-Headers") != Exposed {
		t.Fatal("exposed headers missing")
	}
	// Same response for every origin: nothing to vary on but the API's own.
	if v := w.Header().Values("Vary"); !slices.Equal(v, []string{"Authorization"}) {
		t.Fatalf("vary %v", v)
	}
	if w.Code != 200 {
		t.Fatalf("status %d", w.Code)
	}
}

func TestOriginList(t *testing.T) {
	h := Wrap(api(), Config{Origins: []string{"https://a.example"}})
	w := do(h, "GET", "https://a.example", nil)
	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "https://a.example" {
		t.Fatalf("allow-origin %q", got)
	}
	if v := w.Header().Values("Vary"); !slices.Equal(v, []string{"Origin", "Authorization"}) {
		t.Fatalf("vary %v", v)
	}
	w = do(h, "GET", "https://evil.example", nil)
	if w.Header().Get("Access-Control-Allow-Origin") != "" || w.Code != 200 {
		t.Fatal("other origin allowed, or the request refused")
	}
	// Vary: Origin even without Origin, so a cache never hands this
	// response to a cross-origin request.
	w = do(h, "GET", "", nil)
	if !slices.Contains(w.Header().Values("Vary"), "Origin") {
		t.Fatal("Vary: Origin missing")
	}
}

func TestPreflight(t *testing.T) {
	h := Wrap(api(), Config{Origins: []string{"https://a.example"}, Credentials: true})
	pre := map[string]string{"Access-Control-Request-Method": "PATCH", "Access-Control-Request-Headers": "authorization, if-match"}
	w := do(h, "OPTIONS", "https://a.example", pre)
	if w.Code != 204 || w.Header().Get("Access-Control-Allow-Methods") != Methods || w.Header().Get("Access-Control-Allow-Headers") != Headers {
		t.Fatalf("preflight %d %v", w.Code, w.Header())
	}
	if w.Header().Get("Access-Control-Allow-Credentials") != "true" || w.Header().Get("Access-Control-Max-Age") != "600" {
		t.Fatalf("preflight %v", w.Header())
	}
	if w.Header().Get("ETag") != "" {
		t.Fatal("preflight reached the API")
	}
	w = do(h, "OPTIONS", "https://evil.example", pre)
	if w.Code != 204 || w.Header().Get("Access-Control-Allow-Methods") != "" {
		t.Fatalf("preflight of another origin %d %v", w.Code, w.Header())
	}
	// A plain OPTIONS isn't a preflight: the API answers it.
	if w = do(h, "OPTIONS", "https://a.example", nil); w.Header().Get("ETag") == "" {
		t.Fatal("plain OPTIONS intercepted")
	}
}

func TestParse(t *testing.T) {
	got, err := Parse([]string{"https://a.example/, http://localhost:3000", "*"})
	if err != nil || !slices.Equal(got, []string{"https://a.example", "http://localhost:3000", "*"}) {
		t.Fatalf("%v %v", got, err)
	}
	for _, bad := range []string{"a.example", "ftp://a.example", "https://a.example/path", "https://"} {
		if _, err := Parse([]string{bad}); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

// Every request header the servers read is allowed, X-Author (serve -dev)
// included; the edge's verification header never is. The lists cover what
// §7 "Browsers" requires: the methods and headers that make requests
// non-simple, plus Blob-Nonce and Blob-From, allowed; the headers clients
// read, X-Log-Next (§7.1 Paging) among them, exposed.
func TestHeaderLists(t *testing.T) {
	allowed := strings.Split(Headers, ", ")
	for _, h := range []string{"Authorization", "Content-Type", "If-Match", "If-None-Match", "If-Range", "Range", "Signature", "Source-Authorization", "Blob-From", "Blob-Nonce", "Last-Event-ID", "X-Author"} {
		if !slices.Contains(allowed, h) {
			t.Errorf("%s not allowed", h)
		}
	}
	if slices.Contains(allowed, "X-Edge-Verified") {
		t.Error("edge header allowed")
	}
	methods := strings.Split(Methods, ", ")
	for _, m := range []string{"GET", "HEAD", "PATCH", "PUT", "POST", "DELETE"} {
		if !slices.Contains(methods, m) {
			t.Errorf("method %s not allowed", m)
		}
	}
	exposed := strings.Split(Exposed, ", ")
	for _, h := range []string{"ETag", "Location", "Retry-After", "Content-Range", "X-Revision", "X-Namespace-Revision", "X-Config-Revision", "X-Cursor", "X-Log-Next", "X-E2E"} {
		if !slices.Contains(exposed, h) {
			t.Errorf("%s not exposed", h)
		}
	}
	// No duplicates, no stray spacing: each list is "A, B, C".
	for name, l := range map[string][]string{"Headers": allowed, "Methods": methods, "Exposed": exposed} {
		seen := map[string]bool{}
		for _, h := range l {
			if h == "" || strings.TrimSpace(h) != h || seen[strings.ToLower(h)] {
				t.Errorf("%s: malformed or repeated entry %q", name, h)
			}
			seen[strings.ToLower(h)] = true
		}
	}
}

// A preflight answer sets Access-Control-Max-Age, every allowed method and
// header, and, for "*" without credentials, the same answer for all.
func TestPreflightAnyOrigin(t *testing.T) {
	h := Wrap(api(), Config{Origins: []string{"*"}, MaxAge: 90 * time.Second})
	w := do(h, "OPTIONS", "https://a.example", map[string]string{"Access-Control-Request-Method": "DELETE", "Access-Control-Request-Headers": "if-match, blob-nonce"})
	if w.Code != 204 || w.Header().Get("Access-Control-Max-Age") != "90" || w.Header().Get("Access-Control-Allow-Origin") != "*" ||
		w.Header().Get("Access-Control-Allow-Methods") != Methods || w.Header().Get("Access-Control-Allow-Headers") != Headers {
		t.Fatalf("preflight %d %v", w.Code, w.Header())
	}
	if v := w.Header().Values("Vary"); len(v) != 0 {
		t.Fatalf("vary %v on an answer the same for every origin", v)
	}
}

// Credentials need the origin named, even with "*" configured: the answer
// then varies by origin and says so (Vary: Origin), so a CDN doesn't serve
// one origin's answer to another (§7 "Browsers").
func TestCredentialsVaryByOrigin(t *testing.T) {
	h := Wrap(api(), Config{Origins: []string{"*"}, Credentials: true})
	w := do(h, "GET", "https://a.example", nil)
	if w.Header().Get("Access-Control-Allow-Origin") != "https://a.example" || w.Header().Get("Access-Control-Allow-Credentials") != "true" {
		t.Fatalf("headers %v", w.Header())
	}
	if !slices.Contains(w.Header().Values("Vary"), "Origin") {
		t.Fatalf("vary %v: the answer names the origin", w.Header().Values("Vary"))
	}
	w = do(h, "OPTIONS", "https://b.example", map[string]string{"Access-Control-Request-Method": "PATCH"})
	if w.Header().Get("Access-Control-Allow-Origin") != "https://b.example" || !slices.Contains(w.Header().Values("Vary"), "Origin") {
		t.Fatalf("preflight %v", w.Header())
	}
}
