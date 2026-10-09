package server

import (
	"bufio"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"

	"github.com/middle-management/patchlog/internal/cors"
	"github.com/middle-management/patchlog/internal/telemetry"
)

func spanAttr(s sdktrace.ReadOnlySpan, k attribute.Key) string {
	for _, kv := range s.Attributes() {
		if kv.Key == k {
			return kv.Value.Emit()
		}
	}
	return ""
}

// TestTelemetry checks the API's server spans (named by route, with the
// namespace as an attribute), the engine write spans and metrics, and
// that query strictness, CORS preflights and event streams behave as
// without telemetry. Not parallel: telemetry.Use sets the process's
// providers.
func TestTelemetry(t *testing.T) {
	e := newEnv(t)
	e.mkNS("docs", map[string]any{"read": "public"})
	r1 := e.create("docs", "a", map[string]any{"v": 1.0})

	rec := tracetest.NewSpanRecorder()
	reader := sdkmetric.NewManualReader()
	t.Cleanup(telemetry.Use(sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(rec)), sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))))
	ts := httptest.NewServer(telemetry.Handler(cors.Wrap(New(e.e), cors.Config{Origins: []string{"*"}, MaxAge: time.Minute})))
	defer ts.Close()
	traced := *e
	traced.srv = ts

	byName := func(name string) []sdktrace.ReadOnlySpan {
		var out []sdktrace.ReadOnlySpan
		for _, s := range rec.Ended() {
			if s.Name() == name {
				out = append(out, s)
			}
		}
		return out
	}

	// A read: the span is named by the route, the namespace an attribute.
	expect(t, traced.get("/r/docs/a/rev/"+r1), 200)
	ss := byName("GET /r/{ns}/{name}/rev/{id}")
	if len(ss) != 1 {
		t.Fatalf("read spans: %v", names(rec.Ended()))
	}
	if spanAttr(ss[0], "patchlog.ns") != "docs" || spanAttr(ss[0], "http.route") != "/r/{ns}/{name}/rev/{id}" || spanAttr(ss[0], "http.response.status_code") != "200" {
		t.Fatalf("read span attributes %v", ss[0].Attributes())
	}
	for _, s := range rec.Ended() {
		if strings.Contains(s.Name(), r1) || strings.Contains(s.Name(), "docs") {
			t.Fatalf("path value in span name %q", s.Name())
		}
	}

	// Query strictness is untouched: 400, and still named by its route.
	expectCode(t, traced.get("/ns/docs/log?bogus=1"), 400, "bad_input")
	if ss := byName("GET /ns/{ns}/log"); len(ss) != 1 || spanAttr(ss[0], "http.response.status_code") != "400" {
		t.Fatalf("strict query span: %v", names(rec.Ended()))
	}

	// A CORS preflight is answered by the CORS layer as before.
	pf, _ := http.NewRequest("OPTIONS", ts.URL+"/r/docs/a", nil)
	pf.Header.Set("Origin", "https://app.example")
	pf.Header.Set("Access-Control-Request-Method", "PATCH")
	res, err := httpClient.Do(pf)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 204 || res.Header.Get("Access-Control-Allow-Methods") == "" || res.Header.Get("Access-Control-Max-Age") != "60" {
		t.Fatalf("preflight: %d %v", res.StatusCode, res.Header)
	}
	if len(byName("OPTIONS")) != 1 {
		t.Fatalf("preflight span: %v", names(rec.Ended()))
	}

	// A write: core.WriteResource under the server span, a transaction
	// span under it, and patchlog.writes counted by kind and outcome.
	rec.Reset()
	traced.create("docs", "b", map[string]any{"v": 2.0})
	srv := byName("PATCH /r/{ns}/{name}")
	ws := byName("core.WriteResource")
	if len(srv) != 1 || len(ws) != 1 {
		t.Fatalf("write spans: %v", names(rec.Ended()))
	}
	if ws[0].Parent().SpanID() != srv[0].SpanContext().SpanID() {
		t.Fatal("core.WriteResource is not a child of the server span")
	}
	if spanAttr(ws[0], "patchlog.ns") != "docs" || spanAttr(ws[0], "patchlog.outcome") != "created" || spanAttr(ws[0], "patchlog.write.kind") != "resource" {
		t.Fatalf("write span attributes %v", ws[0].Attributes())
	}
	if tx := byName("core.db.update"); len(tx) == 0 || tx[0].SpanContext().TraceID() != srv[0].SpanContext().TraceID() {
		t.Fatalf("no transaction span in the write's trace: %v", names(rec.Ended()))
	}
	// A conflict is an outcome, not a span error.
	expect(t, traced.write("PATCH", "docs", "b", r1, []any{}), 412)
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatal(err)
	}
	counts := map[string]int64{}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != "patchlog.writes" {
				continue
			}
			for _, dp := range m.Data.(metricdata.Sum[int64]).DataPoints {
				if _, ok := dp.Attributes.Value("patchlog.ns"); ok {
					t.Fatal("namespace as a metric attribute")
				}
				k, _ := dp.Attributes.Value("patchlog.write.kind")
				o, _ := dp.Attributes.Value("patchlog.outcome")
				counts[k.AsString()+"/"+o.AsString()] += dp.Value
			}
		}
	}
	if counts["resource/created"] != 1 || counts["resource/stale"] != 1 {
		t.Fatalf("patchlog.writes %v", counts)
	}

	// An event stream still flushes through the instrumented writer.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	q, _ := http.NewRequestWithContext(ctx, "GET", ts.URL+"/ns/docs/events", nil)
	res, err = httpClient.Do(q)
	if err != nil {
		t.Fatal(err)
	}
	if res.Header.Get("Content-Type") != "text/event-stream" {
		t.Fatalf("events: %d %v", res.StatusCode, res.Header)
	}
	if _, err := bufio.NewReader(res.Body).ReadString('\n'); err != nil {
		t.Fatalf("no event before the deadline: %v", err)
	}
	cancel()
	res.Body.Close()
}

func names(spans []sdktrace.ReadOnlySpan) []string {
	var out []string
	for _, s := range spans {
		k := ""
		if s.SpanKind() == trace.SpanKindServer {
			k = " (server)"
		}
		out = append(out, s.Name()+k)
	}
	return out
}
