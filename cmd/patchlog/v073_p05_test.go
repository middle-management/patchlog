package main

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/core"
	"github.com/middle-management/patchlog/internal/server"
)

// -max-rate-per-namespace RATE,BURST is the deployment maximum of
// ratePerNamespace (§6.6), which an allowance's bucket never exceeds: the
// load harness's allowance (cmd/capacity, rate and burst 1e9) is 422 at
// the default maximum and taken under a raised one. A lowered maximum
// holds the default limit too.
func TestV073MaxRatePerNamespace(t *testing.T) {
	for _, s := range []string{"1e9", "0,1", "1,0.5", "x,1"} {
		l, m := core.DefaultLimits(), core.DefaultMaximums()
		if err := rateMaximum(s, &l, &m); err == nil {
			t.Errorf("%q accepted", s)
		}
	}
	create := func(flag string) int {
		t.Helper()
		l, m := core.DefaultLimits(), core.DefaultMaximums()
		if err := rateMaximum(flag, &l, &m); err != nil {
			t.Fatal(err)
		}
		e, err := core.Open(core.Options{Path: filepath.Join(t.TempDir(), "p.db"), Origin: "http://localhost", AuthDisabled: true, Limits: l, Maximums: m})
		if err != nil {
			t.Fatal(err)
		}
		defer e.Close()
		body := `[{"op":"add","path":"","value":{"read":"public","allowances":[{"sub":"capacity","kid":"cap","bucket":{"rate":1e9,"burst":1e9}}]}}]`
		r := httptest.NewRequest("PATCH", "/ns/cap", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json-patch+json")
		r.Header.Set("If-None-Match", "*")
		r.Header.Set("X-Author", "admin")
		rec := httptest.NewRecorder()
		server.New(e).ServeHTTP(rec, r)
		if rec.Code != http.StatusCreated && !strings.Contains(rec.Body.String(), `"ratePerNamespace"`) {
			t.Fatalf("%d %s", rec.Code, rec.Body)
		}
		return rec.Code
	}
	if code := create(""); code != 422 {
		t.Errorf("at the default maximum: %d, want 422", code)
	}
	if code := create("1e9,1e9"); code != 201 {
		t.Errorf("under -max-rate-per-namespace 1e9,1e9: %d, want 201", code)
	}
	l, m := core.DefaultLimits(), core.DefaultMaximums()
	if err := rateMaximum("100, 200", &l, &m); err != nil || m.RatePerNamespace != (core.Rate{Rate: 100, Burst: 200}) || l.RatePerNamespace != m.RatePerNamespace {
		t.Errorf("lowered: limit %v, maximum %v, %v", l.RatePerNamespace, m.RatePerNamespace, err)
	}
}
