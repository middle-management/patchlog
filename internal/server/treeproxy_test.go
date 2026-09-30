package server

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// fakeTree stands in for the tree service: /cat/roots redirects to the
// listing at a checkpoint, which echoes what it received.
func fakeTree(t *testing.T) (*httptest.Server, *[]string) {
	var mu sync.Mutex
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Method+" "+r.URL.RequestURI())
		mu.Unlock()
		switch r.URL.Path {
		case "/tree/cat/roots":
			w.Header().Set("Location", "/tree/cat/at/1aaa/roots?"+r.URL.RawQuery)
			w.WriteHeader(http.StatusFound)
		case "/tree/cat/abs":
			w.Header().Set("Location", "http://"+r.Host+"/tree/cat/at/1bbb/roots")
			w.WriteHeader(http.StatusFound)
		case "/tree/cat/elsewhere":
			w.Header().Set("Location", "https://example.com/x")
			w.WriteHeader(http.StatusFound)
		default:
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Set-Cookie", "a=b")
			json.NewEncoder(w).Encode(map[string]any{"path": r.URL.Path, "query": r.URL.RawQuery,
				"auth": r.Header.Get("Authorization"), "cookie": r.Header.Get("Cookie")})
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &seen
}

func TestTreeProxy(t *testing.T) {
	tree, seen := fakeTree(t)
	h, err := NewTreeProxy(tree.URL + "/tree/")
	if err != nil {
		t.Fatal(err)
	}
	front := httptest.NewServer(h)
	defer front.Close()

	// GET is proxied, following the rewritten redirect through the proxy,
	// with Authorization forwarded and cookies dropped.
	req, _ := http.NewRequest("GET", front.URL+"/playground/tree/cat/roots?min=cat:1x", nil)
	req.Header.Set("Authorization", "Bearer tok")
	req.Header.Set("Cookie", "session=secret")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var body map[string]any
	json.NewDecoder(res.Body).Decode(&body)
	res.Body.Close()
	if res.StatusCode != 200 || body["path"] != "/tree/cat/at/1aaa/roots" || body["query"] != "min=cat:1x" || body["auth"] != "Bearer tok" || body["cookie"] != "" {
		t.Fatalf("GET: %d %v", res.StatusCode, body)
	}
	if res.Request.URL.Path != "/playground/tree/cat/at/1aaa/roots" {
		t.Fatalf("redirect not rewritten: %s", res.Request.URL)
	}
	if res.Header.Get("Set-Cookie") != "" || res.Header.Get("X-Content-Type-Options") != "nosniff" || !strings.Contains(res.Header.Get("Content-Security-Policy"), "default-src 'none'") {
		t.Fatalf("headers: %v", res.Header)
	}

	noFollow := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	for path, want := range map[string]string{
		"/playground/tree/cat/abs":       "/playground/tree/cat/at/1bbb/roots",
		"/playground/tree/cat/elsewhere": "https://example.com/x",
	} {
		res, err := noFollow.Get(front.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if res.StatusCode != 302 || res.Header.Get("Location") != want {
			t.Errorf("%s: %d %q", path, res.StatusCode, res.Header.Get("Location"))
		}
	}

	// HEAD is allowed.
	res, err = http.Head(front.URL + "/playground/tree/cat/at/1aaa/children?of=root")
	if err != nil || res.StatusCode != 200 {
		t.Fatalf("HEAD: %v %v", err, res)
	}

	// Writes are refused without reaching the tree service.
	n := len(*seen)
	for _, m := range []string{"POST", "PUT", "PATCH", "DELETE"} {
		req, _ := http.NewRequest(m, front.URL+"/playground/tree/grants", strings.NewReader(`{}`))
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
		t.Errorf("writes reached the tree service: %v", (*seen)[n:])
	}

	// The prefix itself tells the playground the proxy is there.
	res, err = http.Get(front.URL + "/playground/tree/")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != 200 || !strings.Contains(string(b), `"proxy":"tree"`) {
		t.Fatalf("probe: %d %s", res.StatusCode, b)
	}
}

func TestTreeProxyUnreachable(t *testing.T) {
	tree := httptest.NewServer(http.NotFoundHandler())
	url := tree.URL
	tree.Close()
	h, err := NewTreeProxy(url)
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/playground/tree/cat/roots", nil))
	if rec.Code != http.StatusBadGateway || !strings.Contains(rec.Body.String(), "upstream") {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
}

func TestTreeProxyBadURL(t *testing.T) {
	for _, u := range []string{"", "tree:8082", "ftp://tree", "http://", "http://tree?x=1"} {
		if _, err := NewTreeProxy(u); err == nil {
			t.Errorf("%q accepted", u)
		}
	}
}
