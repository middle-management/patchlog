package main

import (
	"flag"
	"net/http"
	"net/http/httptest"
	"testing"

	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"github.com/middle-management/patchlog/internal/telemetry"
)

// TestServerTelemetry checks the servers' wiring: requests are traced,
// health probes are not.
func TestServerTelemetry(t *testing.T) {
	rec := tracetest.NewSpanRecorder()
	t.Cleanup(telemetry.Use(sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(rec)), nil))
	mux := http.NewServeMux()
	mux.HandleFunc("GET /x/{id}", func(http.ResponseWriter, *http.Request) {})
	sd := addShutdownFlags(flag.NewFlagSet("t", flag.ContinueOnError))
	ls := sd.server("test", &http.Server{Handler: mux}, nil)
	ts := httptest.NewServer(ls.HTTP.Handler)
	defer ts.Close()
	for _, p := range []string{"/_health", "/_ready", "/x/42"} {
		res, err := http.Get(ts.URL + p)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if res.StatusCode != 200 {
			t.Fatalf("%s: %d", p, res.StatusCode)
		}
	}
	spans := rec.Ended()
	if len(spans) != 1 || spans[0].Name() != "GET /x/{id}" {
		var names []string
		for _, s := range spans {
			names = append(names, s.Name())
		}
		t.Fatalf("spans %v, want only GET /x/{id}", names)
	}
}

func TestBuildVersion(t *testing.T) {
	if v := buildVersion(); v == "" {
		t.Fatal("empty version")
	}
}
