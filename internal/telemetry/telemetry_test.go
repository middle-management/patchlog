package telemetry

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	semconv "go.opentelemetry.io/otel/semconv/v1.43.0"
	"go.opentelemetry.io/otel/trace"
)

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func TestDisabledByDefault(t *testing.T) {
	sd, err := setup(context.Background(), "patchlog-test", "v0", env(nil), io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	defer sd(context.Background())
	if Enabled() {
		t.Fatal("telemetry enabled without any OTEL_* configuration")
	}
	h := &http.ServeMux{}
	if got := Handler(h); got != http.Handler(h) {
		t.Fatal("Handler wrapped h while telemetry is off")
	}
	// The transport passes requests through untouched: no traceparent.
	var seen http.Header
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { seen = r.Header.Clone() }))
	defer ts.Close()
	res, err := Client(nil).Get(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if seen.Get("Traceparent") != "" {
		t.Fatalf("traceparent sent while off: %v", seen)
	}
	r := httptest.NewRequest("GET", "/x", nil)
	SetRoute(r, "/{ns}")
	if r.Pattern != "" {
		t.Fatal("SetRoute set a pattern while off")
	}
	if NewInstruments("x", func(trace.Tracer, metric.Meter) *int { return new(int) }).Get() != nil {
		t.Fatal("instruments built while off")
	}
}

func TestEnvSelection(t *testing.T) {
	for _, c := range []struct {
		env     map[string]string
		enabled bool
		err     bool
	}{
		{map[string]string{}, false, false},
		{map[string]string{"OTEL_SDK_DISABLED": "true", "OTEL_EXPORTER_OTLP_ENDPOINT": "http://localhost:4318"}, false, false},
		{map[string]string{"OTEL_TRACES_EXPORTER": "none", "OTEL_METRICS_EXPORTER": "none", "OTEL_EXPORTER_OTLP_ENDPOINT": "http://localhost:4318"}, false, false},
		{map[string]string{"OTEL_TRACES_EXPORTER": "console"}, true, false},
		{map[string]string{"OTEL_METRICS_EXPORTER": "console"}, true, false},
		{map[string]string{"OTEL_EXPORTER_OTLP_ENDPOINT": "http://localhost:4318"}, true, false},
		{map[string]string{"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT": "http://localhost:4318/v1/traces"}, true, false},
		{map[string]string{"OTEL_EXPORTER_OTLP_ENDPOINT": "localhost:4317", "OTEL_EXPORTER_OTLP_PROTOCOL": "grpc"}, true, false},
		{map[string]string{"OTEL_EXPORTER_OTLP_ENDPOINT": "http://localhost:4318", "OTEL_EXPORTER_OTLP_PROTOCOL": "http/json"}, false, true},
		{map[string]string{"OTEL_TRACES_EXPORTER": "zipkin"}, false, true},
	} {
		var out bytes.Buffer
		sd, err := setup(context.Background(), "patchlog-test", "v0", env(c.env), &out)
		if (err != nil) != c.err {
			t.Fatalf("%v: err %v", c.env, err)
		}
		if Enabled() != c.enabled {
			t.Fatalf("%v: enabled %v", c.env, Enabled())
		}
		// No collector is listening: the final metric export fails.
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		sd(ctx)
		cancel()
		if Enabled() {
			t.Fatalf("%v: still enabled after shutdown", c.env)
		}
	}
}

func TestResource(t *testing.T) {
	res, err := newResource(context.Background(), "patchlog-serve", "v1.2.3")
	if err != nil {
		t.Fatal(err)
	}
	attrs := res.Set()
	if v, _ := attrs.Value(semconv.ServiceNameKey); v.AsString() != "patchlog-serve" {
		t.Fatalf("service.name %q", v.AsString())
	}
	if v, _ := attrs.Value(semconv.ServiceVersionKey); v.AsString() != "v1.2.3" {
		t.Fatalf("service.version %q", v.AsString())
	}
	if _, ok := attrs.Value(semconv.ProcessCommandArgsKey); ok {
		t.Fatal("process.command_args recorded (flags may carry grants)")
	}
	t.Setenv("OTEL_SERVICE_NAME", "cms-api")
	t.Setenv("OTEL_RESOURCE_ATTRIBUTES", "deployment.environment.name=staging")
	res, err = newResource(context.Background(), "patchlog-serve", "v1.2.3")
	if err != nil {
		t.Fatal(err)
	}
	attrs = res.Set()
	if v, _ := attrs.Value(semconv.ServiceNameKey); v.AsString() != "cms-api" {
		t.Fatalf("OTEL_SERVICE_NAME not applied: %q", v.AsString())
	}
	if v, _ := attrs.Value("deployment.environment.name"); v.AsString() != "staging" {
		t.Fatal("OTEL_RESOURCE_ATTRIBUTES not applied")
	}
}

// install sets up an in-memory span recorder and metric reader.
func install(t *testing.T) (*tracetest.SpanRecorder, *sdkmetric.ManualReader) {
	t.Helper()
	rec := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(rec))
	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	t.Cleanup(Use(tp, mp))
	return rec, reader
}

func spanAttr(s sdktrace.ReadOnlySpan, k attribute.Key) (attribute.Value, bool) {
	for _, kv := range s.Attributes() {
		if kv.Key == k {
			return kv.Value, true
		}
	}
	return attribute.Value{}, false
}

func TestServerSpanNamedByRoute(t *testing.T) {
	rec, reader := install(t)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /r/{ns}/{name}", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(302) })
	// A hand-routed handler declares its route.
	mux.HandleFunc("/idx/", func(w http.ResponseWriter, r *http.Request) {
		r.Pattern = ""
		SetRoute(r, "/idx/{ns}")
		w.WriteHeader(200)
	})
	ts := httptest.NewServer(Handler(mux))
	defer ts.Close()
	for _, p := range []string{"/r/acme-secret/doc-42", "/idx/tenant-7"} {
		res, err := http.Get(ts.URL + p)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
	}
	spans := rec.Ended()
	if len(spans) != 2 {
		t.Fatalf("%d spans", len(spans))
	}
	for i, want := range []struct{ name, route string }{{"GET /r/{ns}/{name}", "/r/{ns}/{name}"}, {"GET /idx/{ns}", "/idx/{ns}"}} {
		s := spans[i]
		if s.Name() != want.name {
			t.Fatalf("span name %q, want %q", s.Name(), want.name)
		}
		if strings.Contains(s.Name(), "acme") || strings.Contains(s.Name(), "tenant") {
			t.Fatalf("path value in span name %q", s.Name())
		}
		if s.SpanKind() != trace.SpanKindServer {
			t.Fatalf("kind %v", s.SpanKind())
		}
		if v, ok := spanAttr(s, semconv.HTTPRouteKey); !ok || v.AsString() != want.route {
			t.Fatalf("http.route %v", v.AsString())
		}
		if v, _ := spanAttr(s, "http.response.status_code"); v.AsInt64() == 0 {
			t.Fatal("no http.response.status_code")
		}
	}
	// http.server.request.duration is labelled with the route, not the path.
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatal(err)
	}
	routes := map[string]bool{}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != "http.server.request.duration" {
				continue
			}
			for _, dp := range m.Data.(metricdata.Histogram[float64]).DataPoints {
				v, _ := dp.Attributes.Value(semconv.HTTPRouteKey)
				routes[v.AsString()] = true
				for _, kv := range dp.Attributes.ToSlice() {
					if strings.Contains(kv.Value.Emit(), "acme") {
						t.Fatalf("path value in metric attribute %v", kv)
					}
				}
			}
		}
	}
	if !routes["/r/{ns}/{name}"] || !routes["/idx/{ns}"] {
		t.Fatalf("metric routes %v", routes)
	}
}

func TestClientPropagation(t *testing.T) {
	rec, _ := install(t)
	var traceparent string
	backend := httptest.NewServer(Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		traceparent = r.Header.Get("Traceparent")
	})))
	defer backend.Close()
	// A client built before telemetry was installed is covered too.
	hc := &http.Client{Transport: Transport(nil)}
	ctx, root := state.Load().tp.Tracer("test").Start(context.Background(), "job")
	req, _ := http.NewRequestWithContext(ctx, "GET", backend.URL+"/x", nil)
	res, err := hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	root.End()
	if traceparent == "" {
		t.Fatal("no traceparent sent")
	}
	var client, server sdktrace.ReadOnlySpan
	for _, s := range rec.Ended() {
		switch s.SpanKind() {
		case trace.SpanKindClient:
			client = s
		case trace.SpanKindServer:
			server = s
		}
	}
	if client == nil || server == nil {
		t.Fatalf("spans: %v", rec.Ended())
	}
	if client.Name() != "GET" {
		t.Fatalf("client span name %q", client.Name())
	}
	tid := root.SpanContext().TraceID()
	if client.SpanContext().TraceID() != tid || server.SpanContext().TraceID() != tid {
		t.Fatal("trace id not propagated")
	}
	if client.Parent().SpanID() != root.SpanContext().SpanID() || server.Parent().SpanID() != client.SpanContext().SpanID() {
		t.Fatal("parent chain job → client → server broken")
	}
	if !strings.Contains(traceparent, tid.String()) {
		t.Fatalf("traceparent %q", traceparent)
	}
}

// DefaultClient, as every Transport given no base, goes over the package's
// own pool, a clone of http.DefaultTransport: closing the default one's
// idle connections leaves its own alone. Its requests are traced.
func TestDefaultClient(t *testing.T) {
	rec, _ := install(t)
	base := DefaultClient.Transport.(*transport).baseRT()
	if base == http.DefaultTransport || base != Transport(nil).(*transport).baseRT() {
		t.Fatal("DefaultClient doesn't go over the package's own pool")
	}
	if ht, ok := base.(*http.Transport); !ok || ht.Proxy == nil || ht.TLSHandshakeTimeout != http.DefaultTransport.(*http.Transport).TLSHandshakeTimeout {
		t.Fatalf("base %T isn't a clone of http.DefaultTransport", base)
	}
	var conns atomic.Int32
	var traceparent atomic.Value
	backend := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		traceparent.Store(r.Header.Get("Traceparent"))
	}))
	backend.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			conns.Add(1)
		}
	}
	backend.Start()
	defer backend.Close()
	for range 2 {
		res, err := DefaultClient.Get(backend.URL)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, res.Body)
		res.Body.Close()
		http.DefaultTransport.(*http.Transport).CloseIdleConnections()
	}
	if n := conns.Load(); n != 1 {
		t.Fatalf("%d connections: closing http.DefaultTransport's idle ones closed DefaultClient's", n)
	}
	if tp, _ := traceparent.Load().(string); tp == "" {
		t.Fatal("no traceparent sent")
	}
	spans := 0
	for _, s := range rec.Ended() {
		if s.SpanKind() == trace.SpanKindClient {
			spans++
		}
	}
	if spans != 2 {
		t.Fatalf("%d client spans", spans)
	}
}
