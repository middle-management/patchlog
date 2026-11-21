package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/server"
)

// TestHandlerIndexProxy checks where /playground/index/ goes: to the proxy
// when -index-url is set, else the playground's 404; never to the API.
func TestHandlerIndexProxy(t *testing.T) {
	api := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(299) })
	idx := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"at":"1x","ns":"demo","hits":[]}`))
	}))
	defer idx.Close()
	proxy, err := server.NewIndexProxy(idx.URL)
	if err != nil {
		t.Fatal(err)
	}
	get := func(h http.Handler, method, path string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(method, path, nil))
		return rec
	}
	with, without := handler(api, true, proxy), handler(api, true, nil)
	if rec := get(with, "GET", "/playground/index/demo/at/1x?q=a"); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"hits"`) {
		t.Errorf("proxied GET: %d %s", rec.Code, rec.Body)
	}
	if rec := get(with, "GET", "/playground/index/"); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"proxy":"index"`) {
		t.Errorf("probe: %d %s", rec.Code, rec.Body)
	}
	if rec := get(with, "POST", "/playground/index/demo"); rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("proxied POST: %d", rec.Code)
	}
	if rec := get(with, "GET", "/playground/tree/"); rec.Code != 404 {
		t.Errorf("tree prefix without -tree-url: %d", rec.Code)
	}
	for _, p := range []string{"/playground/index/demo/at/1x", "/playground/index/"} {
		if rec := get(without, "GET", p); rec.Code != 404 {
			t.Errorf("unset -index-url %s: %d", p, rec.Code)
		}
	}
	if rec := get(with, "GET", "/ns/demo"); rec.Code != 299 {
		t.Errorf("api: %d", rec.Code)
	}
}
