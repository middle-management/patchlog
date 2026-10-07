package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"

	"github.com/middle-management/patchlog/internal/core"
	"github.com/middle-management/patchlog/internal/telemetry"
)

// benchCachedRead measures a cached revision read through h(New(e)).
func benchCachedRead(b *testing.B, wrap func(http.Handler) http.Handler) {
	e, err := core.Open(core.Options{Path: ":memory:", BlobDir: b.TempDir(), Origin: "https://cms.example", AuthDisabled: true, Purger: nopPurger{}})
	if err != nil {
		b.Fatal(err)
	}
	defer e.Close()
	h := wrap(New(e))
	do := func(method, path, body string, hdr ...string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		if body != "" {
			r.Header.Set("Content-Type", "application/json-patch+json")
		}
		for i := 0; i+1 < len(hdr); i += 2 {
			r.Header.Set(hdr[i], hdr[i+1])
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	if w := do("PATCH", "/ns/docs", `[{"op":"add","path":"","value":{"read":"public"}}]`, "If-None-Match", "*", "X-Author", "admin"); w.Code != 201 {
		b.Fatalf("ns: %d %s", w.Code, w.Body)
	}
	w := do("PATCH", "/r/docs/a", `[{"op":"add","path":"","value":{"v":1}}]`, "If-None-Match", "*", "X-Author", "admin")
	if w.Code != 201 {
		b.Fatalf("create: %d %s", w.Code, w.Body)
	}
	path := "/r/docs/a/rev/" + strings.Trim(w.Header().Get("ETag"), `"`)
	if w := do("GET", path, ""); w.Code != 200 {
		b.Fatalf("read: %d", w.Code)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if w := do("GET", path, ""); w.Code != 200 {
			b.Fatalf("read: %d", w.Code)
		}
	}
}

// BenchmarkCachedRead is the API as served with telemetry off (the
// default): telemetry.Handler returns the handler itself.
func BenchmarkCachedRead(b *testing.B) {
	benchCachedRead(b, telemetry.Handler)
}

// BenchmarkCachedReadTraced is the same with an SDK tracer provider
// sampling every request and a meter provider, exporting nowhere.
func BenchmarkCachedReadTraced(b *testing.B) {
	tp := sdktrace.NewTracerProvider()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(sdkmetric.NewManualReader()))
	defer telemetry.Use(tp, mp)()
	benchCachedRead(b, telemetry.Handler)
}
