package playground

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHandler(t *testing.T) {
	h := Handler()
	for path, want := range map[string]string{
		"/playground/":        "text/html",
		"/playground/app.js":  "javascript",
		"/playground/app.css": "text/css",
	} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
		if rec.Code != 200 || !strings.Contains(rec.Header().Get("Content-Type"), want) || rec.Body.Len() == 0 {
			t.Errorf("%s: %d %q", path, rec.Code, rec.Header().Get("Content-Type"))
		}
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/playground", nil))
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/playground/" {
		t.Errorf("redirect: %d %q", rec.Code, rec.Header().Get("Location"))
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/playground/nope", nil))
	if rec.Code != 404 {
		t.Errorf("missing: %d", rec.Code)
	}
}
