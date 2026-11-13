package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/core"
	"github.com/middle-management/patchlog/internal/server"
)

// -max-rate-per-resource and -max-rate-per-principal are the deployment
// maximums of ratePerResource and ratePerPrincipal (§6.6): a namespace may
// set its own up to them, and the raised per-resource rate is the one its
// documents are then held to.
func TestRateMaximumsPerResourceAndPrincipal(t *testing.T) {
	t.Parallel()
	open := func(res, prin string) http.Handler {
		l, m := core.DefaultLimits(), core.DefaultMaximums()
		if err := rateMaximumOf("ratePerResource", res, &l, &m); err != nil {
			t.Fatal(err)
		}
		if err := rateMaximumOf("ratePerPrincipal", prin, &l, &m); err != nil {
			t.Fatal(err)
		}
		if l != core.DefaultLimits() {
			t.Fatalf("raising a maximum changed the defaults: %+v", l)
		}
		e, err := core.Open(core.Options{Path: filepath.Join(t.TempDir(), "p.db"), Origin: "http://localhost", AuthDisabled: true, Limits: l, Maximums: m})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { e.Close() })
		return server.New(e)
	}
	do := func(h http.Handler, method, path, body string, hdr ...string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json-patch+json")
		r.Header.Set("X-Author", "ed")
		for i := 0; i+1 < len(hdr); i += 2 {
			r.Header.Set(hdr[i], hdr[i+1])
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		return rec
	}
	nsDoc := `[{"op":"add","path":"","value":{"read":"public","limits":{"ratePerResource":{"rate":1000,"burst":1000},"ratePerPrincipal":{"rate":1000,"burst":1000}}}}]`

	// At the default maximums a namespace can't raise either.
	if rec := do(open("", ""), "PATCH", "/ns/hot", nsDoc, "If-None-Match", "*"); rec.Code != 422 {
		t.Fatalf("default maximums: %d %s", rec.Code, rec.Body)
	}
	// Only one raised: the other still refuses.
	if rec := do(open("1000,1000", ""), "PATCH", "/ns/hot", nsDoc, "If-None-Match", "*"); rec.Code != 422 || !strings.Contains(rec.Body.String(), "ratePerPrincipal") {
		t.Fatalf("per-principal at its default: %d %s", rec.Code, rec.Body)
	}

	h := open("1000,1000", "1000,1000")
	if rec := do(h, "PATCH", "/ns/hot", nsDoc, "If-None-Match", "*"); rec.Code != 201 {
		t.Fatalf("raised maximums: %d %s", rec.Code, rec.Body)
	}
	// A namespace that doesn't ask keeps the default: 20 writes in a burst.
	if rec := do(h, "PATCH", "/ns/plain", `[{"op":"add","path":"","value":{"read":"public"}}]`, "If-None-Match", "*"); rec.Code != 201 {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	appends := func(ns string, n int) (ok, limited int) {
		rec := do(h, "PATCH", "/r/"+ns+"/doc", `[{"op":"add","path":"","value":{"n":0}}]`, "If-None-Match", "*")
		if rec.Code != 201 {
			t.Fatalf("create in %s: %d %s", ns, rec.Code, rec.Body)
		}
		head := rec.Header().Get("ETag")
		for i := 1; i <= n; i++ {
			rec := do(h, "PATCH", "/r/"+ns+"/doc", fmt.Sprintf(`[{"op":"replace","path":"/n","value":%d}]`, i), "If-Match", head)
			switch rec.Code {
			case 201:
				ok++
				head = rec.Header().Get("ETag")
			case 429:
				limited++
			default:
				t.Fatalf("append %d in %s: %d %s", i, ns, rec.Code, rec.Body)
			}
		}
		return ok, limited
	}
	if ok, limited := appends("hot", 80); ok != 80 || limited != 0 {
		t.Errorf("hot: %d appends, %d rate limited, want 80 and 0", ok, limited)
	}
	if ok, limited := appends("plain", 80); limited == 0 || ok > 40 {
		t.Errorf("plain: %d appends, %d rate limited, want the default burst to stop most", ok, limited)
	}
}
