package server

import (
	"encoding/json"
	"fmt"
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
	t.Parallel()
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
	res, err := httpClient.Do(req)
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

	noFollow := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
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
	res, err = httpClient.Head(front.URL + "/playground/tree/cat/at/1aaa/children?of=root")
	if err != nil || res.StatusCode != 200 {
		t.Fatalf("HEAD: %v %v", err, res)
	}

	// Writes are refused without reaching the tree service.
	n := len(*seen)
	for _, m := range []string{"POST", "PUT", "PATCH", "DELETE"} {
		req, _ := http.NewRequest(m, front.URL+"/playground/tree/grants", strings.NewReader(`{}`))
		res, err := httpClient.Do(req)
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
	res, err = httpClient.Get(front.URL + "/playground/tree/")
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
	t.Parallel()
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
	t.Parallel()
	for _, u := range []string{"", "tree:8082", "ftp://tree", "http://", "http://tree?x=1", "cat=ftp://tree", "cat=", "Cat=http://tree"} {
		if _, err := NewTreeProxy(u); err == nil {
			t.Errorf("%q accepted", u)
		}
	}
	for _, us := range [][]string{nil, {"http://a", "http://b"}, {"cat=http://a", "cat=http://b"}} {
		if _, err := NewTreeProxy(us...); err == nil {
			t.Errorf("%q accepted", us)
		}
	}
}

// Several tree services: catalogs mapped with CATALOG=URL go to their own,
// everything else to the plain URL.
func TestTreeProxyMapping(t *testing.T) {
	t.Parallel()
	echo := func(name string) *httptest.Server {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(r.URL.Path, "/"+name+"/roots") {
				w.Header().Set("Location", strings.TrimSuffix(r.URL.Path, "roots")+"at/1ccc/roots")
				w.WriteHeader(http.StatusFound)
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"server": name, "path": r.URL.Path, "query": r.URL.RawQuery})
		}))
		t.Cleanup(srv.Close)
		return srv
	}
	def, topics := echo("cat"), echo("topics")
	h, err := NewTreeProxy(def.URL, "topics="+topics.URL+"/base/")
	if err != nil {
		t.Fatal(err)
	}
	front := httptest.NewServer(h)
	defer front.Close()
	get := func(path string) (int, map[string]any, string) {
		res, err := httpClient.Get(front.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		var m map[string]any
		json.NewDecoder(res.Body).Decode(&m)
		return res.StatusCode, m, res.Request.URL.Path
	}
	for path, want := range map[string]string{
		"/playground/tree/cat/roots":               "cat /cat/at/1ccc/roots",
		"/playground/tree/topics/roots":            "topics /base/topics/at/1ccc/roots",
		"/playground/tree/other/at/1x/roots":       "cat /other/at/1x/roots",
		"/playground/tree/_status":                 "cat /_status",
		"/playground/tree/_status?catalog=topics":  "topics /base/_status",
		"/playground/tree/_status?catalog=unknown": "cat /_status",
	} {
		st, m, _ := get(path)
		if got := fmt.Sprint(m["server"], " ", m["path"]); st != 200 || got != want {
			t.Errorf("%s: %d %s, want %s", path, st, got, want)
		}
	}
	// The redirect of a mapped catalog comes back under the prefix.
	if _, _, final := get("/playground/tree/topics/roots"); final != "/playground/tree/topics/at/1ccc/roots" {
		t.Errorf("mapped redirect: %s", final)
	}
	st, m, _ := get("/playground/tree/")
	if st != 200 || fmt.Sprint(m["catalogs"]) != "[topics]" || m["default"] != true {
		t.Errorf("probe: %d %v", st, m)
	}

	// Without a default, unmapped catalogs are 404 and reach nothing.
	h, err = NewTreeProxy("topics=" + topics.URL)
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/playground/tree/cat/roots", nil))
	if rec.Code != http.StatusNotFound || !strings.Contains(rec.Body.String(), "not_found") {
		t.Fatalf("unmapped: %d %s", rec.Code, rec.Body)
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/playground/tree/", nil))
	if !strings.Contains(rec.Body.String(), `"default":false`) {
		t.Fatalf("probe without default: %s", rec.Body)
	}
}
