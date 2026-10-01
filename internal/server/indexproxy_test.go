package server

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeIndex stands in for the search index: /{ns} redirects to the result at
// a checkpoint (after a wait when ?min= is given), which echoes what it got.
func fakeIndex(t *testing.T) (*httptest.Server, *[]string) {
	var mu sync.Mutex
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Method+" "+r.URL.RequestURI())
		mu.Unlock()
		switch {
		case r.URL.Path == "/demo" || r.URL.Path == "/idx/demo":
			if r.URL.Query().Get("min") != "" {
				time.Sleep(50 * time.Millisecond) // waiting for the index to catch up
			}
			q := r.URL.Query()
			q.Del("min")
			w.Header().Set("Location", r.URL.Path+"/at/1aaa?"+q.Encode())
			w.WriteHeader(http.StatusFound)
		case r.URL.Path == "/g/1xyz/demo":
			w.Header().Set("Location", "http://"+r.Host+"/g/1xyz/demo/at/1aaa")
			w.WriteHeader(http.StatusFound)
		case r.URL.Path == "/elsewhere":
			w.Header().Set("Location", "https://example.com/x")
			w.WriteHeader(http.StatusFound)
		default:
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Set-Cookie", "a=b")
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("X-Namespace-Revision", "1aaa")
			json.NewEncoder(w).Encode(map[string]any{"path": r.URL.Path, "query": r.URL.RawQuery,
				"auth": r.Header.Get("Authorization"), "cookie": r.Header.Get("Cookie")})
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &seen
}

func TestIndexProxy(t *testing.T) {
	idx, seen := fakeIndex(t)
	h, err := NewIndexProxy(idx.URL)
	if err != nil {
		t.Fatal(err)
	}
	front := httptest.NewServer(h)
	defer front.Close()

	// A query is redirected to its checkpoint (waiting for ?min= first); the
	// redirect is followed through the proxy, with Authorization forwarded
	// and cookies dropped.
	req, _ := http.NewRequest("GET", front.URL+"/playground/index/demo?q=derby&min=demo:1aaa", nil)
	req.Header.Set("Authorization", "Bearer tok")
	req.Header.Set("Cookie", "session=secret")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var body map[string]any
	json.NewDecoder(res.Body).Decode(&body)
	res.Body.Close()
	if res.StatusCode != 200 || body["path"] != "/demo/at/1aaa" || body["query"] != "q=derby" || body["auth"] != "Bearer tok" || body["cookie"] != "" {
		t.Fatalf("GET: %d %v", res.StatusCode, body)
	}
	if res.Request.URL.Path != "/playground/index/demo/at/1aaa" || res.Request.URL.RawQuery != "q=derby" {
		t.Fatalf("redirect not rewritten: %s", res.Request.URL)
	}
	if res.Header.Get("Set-Cookie") != "" || res.Header.Get("Access-Control-Allow-Origin") != "" ||
		res.Header.Get("X-Namespace-Revision") != "1aaa" || res.Header.Get("X-Content-Type-Options") != "nosniff" ||
		!strings.Contains(res.Header.Get("Content-Security-Policy"), "default-src 'none'") {
		t.Fatalf("headers: %v", res.Header)
	}

	noFollow := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	for path, want := range map[string]string{
		"/playground/index/demo?q=a+b&min=1aaa": "/playground/index/demo/at/1aaa?q=a+b",
		"/playground/index/g/1xyz/demo":         "/playground/index/g/1xyz/demo/at/1aaa",
		"/playground/index/elsewhere":           "https://example.com/x",
	} {
		res, err := noFollow.Get(front.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if res.StatusCode != 302 || res.Header.Get("Location") != want {
			t.Errorf("%s: %d %q, want %q", path, res.StatusCode, res.Header.Get("Location"), want)
		}
	}

	// HEAD and the status document are allowed.
	for _, p := range []string{"/playground/index/demo/at/1aaa?q=x", "/playground/index/_status"} {
		res, err = http.Head(front.URL + p)
		if err != nil || res.StatusCode != 200 {
			t.Fatalf("HEAD %s: %v %v", p, err, res)
		}
	}

	// Writes are refused without reaching the index.
	n := len(*seen)
	for _, m := range []string{"POST", "PUT", "PATCH", "DELETE"} {
		req, _ := http.NewRequest(m, front.URL+"/playground/index/demo", strings.NewReader(`{}`))
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if res.StatusCode != http.StatusMethodNotAllowed || res.Header.Get("Allow") != "GET, HEAD" {
			t.Errorf("%s: %d", m, res.StatusCode)
		}
	}
	if len(*seen) != n {
		t.Errorf("writes reached the index: %v", (*seen)[n:])
	}

	// The prefix itself tells the playground the proxy is there.
	res, err = http.Get(front.URL + "/playground/index/")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != 200 || !strings.Contains(string(b), `"proxy":"index"`) {
		t.Fatalf("probe: %d %s", res.StatusCode, b)
	}
}

// The index may sit below a path (behind a gateway): its redirects are
// mapped back, and ones that leave that path are left alone.
func TestIndexProxyBasePath(t *testing.T) {
	idx, _ := fakeIndex(t)
	h, err := NewIndexProxy(idx.URL + "/idx/")
	if err != nil {
		t.Fatal(err)
	}
	front := httptest.NewServer(h)
	defer front.Close()
	noFollow := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	res, err := noFollow.Get(front.URL + "/playground/index/demo?q=x")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.Header.Get("Location") != "/playground/index/demo/at/1aaa?q=x" {
		t.Errorf("Location %q", res.Header.Get("Location"))
	}
}

func TestIndexProxyUnreachable(t *testing.T) {
	idx := httptest.NewServer(http.NotFoundHandler())
	url := idx.URL
	idx.Close()
	h, err := NewIndexProxy(url)
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/playground/index/demo?q=x", nil))
	if rec.Code != http.StatusBadGateway || !strings.Contains(rec.Body.String(), "upstream") {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
}

func TestIndexProxyBadURL(t *testing.T) {
	for _, u := range []string{"", "index:8081", "ftp://index", "http://", "http://index?x=1"} {
		if _, err := NewIndexProxy(u); err == nil {
			t.Errorf("%q accepted", u)
		}
	}
}
