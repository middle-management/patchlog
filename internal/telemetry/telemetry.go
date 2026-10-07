// Package telemetry sets up OpenTelemetry tracing and metrics from the
// standard OTEL_* environment variables, and is off by default: unless an
// exporter is configured, Setup installs nothing, every instrumented path
// checks Enabled (one atomic load) and skips its spans and measurements,
// and the HTTP handlers and transports are left unwrapped.
//
// Exporters are chosen per signal by OTEL_TRACES_EXPORTER and
// OTEL_METRICS_EXPORTER ("otlp", "console" or "none"); unset, a signal is
// exported by OTLP when OTEL_EXPORTER_OTLP_ENDPOINT or its per-signal
// OTEL_EXPORTER_OTLP_{TRACES,METRICS}_ENDPOINT is set, and not at all
// otherwise. OTEL_EXPORTER_OTLP_{,TRACES_,METRICS_}PROTOCOL picks grpc or
// http/protobuf (the default); the OTLP exporters themselves read the
// endpoints, OTEL_EXPORTER_OTLP_HEADERS, _TIMEOUT, _COMPRESSION and the
// certificate variables, the SDK reads OTEL_TRACES_SAMPLER(_ARG),
// OTEL_BSP_* and OTEL_METRIC_EXPORT_INTERVAL, and the resource takes
// OTEL_SERVICE_NAME and OTEL_RESOURCE_ATTRIBUTES. OTEL_SDK_DISABLED=true
// turns everything off. Propagation is W3C tracecontext and baggage.
package telemetry

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/exporters/stdout/stdoutmetric"
	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	"go.opentelemetry.io/otel/metric"
	metricnoop "go.opentelemetry.io/otel/metric/noop"
	"go.opentelemetry.io/otel/propagation"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.43.0"
	"go.opentelemetry.io/otel/trace"
	tracenoop "go.opentelemetry.io/otel/trace/noop"
)

// providers is what Setup (or Use) installed; nil while telemetry is off.
type providers struct {
	tp   trace.TracerProvider
	mp   metric.MeterProvider
	prop propagation.TextMapPropagator
}

var state atomic.Pointer[providers]

// Enabled reports whether telemetry is installed.
func Enabled() bool { return state.Load() != nil }

// Propagator is W3C tracecontext plus baggage.
func Propagator() propagation.TextMapPropagator {
	return propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}, propagation.Baggage{})
}

// Use installs tp and mp (either may be nil: a no-op one) without reading
// the environment, for tests and embedders; the returned function turns
// telemetry off again.
func Use(tp trace.TracerProvider, mp metric.MeterProvider) (reset func()) {
	if tp == nil {
		tp = tracenoop.NewTracerProvider()
	}
	if mp == nil {
		mp = metricnoop.NewMeterProvider()
	}
	p := &providers{tp: tp, mp: mp, prop: Propagator()}
	prev := state.Swap(p)
	return func() { state.CompareAndSwap(p, prev) }
}

// Shutdown flushes and stops what Setup installed.
type Shutdown func(context.Context) error

// Setup configures telemetry from the environment for the service named
// service (OTEL_SERVICE_NAME overrides it) at version. With no exporter
// configured it installs nothing and returns a no-op Shutdown.
func Setup(ctx context.Context, service, version string) (Shutdown, error) {
	return setup(ctx, service, version, os.Getenv, os.Stderr)
}

// exporterFor is the exporter configured for a signal ("otlp", "console"
// or "none"): OTEL_<SIGNAL>_EXPORTER, else otlp when an endpoint is set.
func exporterFor(getenv func(string) string, signal string) (string, error) {
	v := strings.ToLower(strings.TrimSpace(getenv("OTEL_" + signal + "_EXPORTER")))
	if v == "" {
		if getenv("OTEL_EXPORTER_OTLP_ENDPOINT") != "" || getenv("OTEL_EXPORTER_OTLP_"+signal+"_ENDPOINT") != "" {
			return "otlp", nil
		}
		return "none", nil
	}
	// A list names several exporters; one of each kind is supported.
	out := "none"
	for _, e := range strings.Split(v, ",") {
		switch e = strings.TrimSpace(e); e {
		case "none", "":
		case "otlp", "console":
			if out != "none" && out != e {
				return "", fmt.Errorf("OTEL_%s_EXPORTER: only one of otlp and console is supported", signal)
			}
			out = e
		case "logging": // the deprecated name of console
			out = "console"
		default:
			return "", fmt.Errorf("OTEL_%s_EXPORTER: unsupported exporter %q (want otlp, console or none)", signal, e)
		}
	}
	return out, nil
}

// protocolFor is the OTLP protocol of a signal: grpc or http/protobuf.
func protocolFor(getenv func(string) string, signal string) (string, error) {
	p := getenv("OTEL_EXPORTER_OTLP_" + signal + "_PROTOCOL")
	if p == "" {
		p = getenv("OTEL_EXPORTER_OTLP_PROTOCOL")
	}
	switch p = strings.TrimSpace(p); p {
	case "", "http/protobuf":
		return "http/protobuf", nil
	case "grpc":
		return "grpc", nil
	}
	return "", fmt.Errorf("OTEL_EXPORTER_OTLP_PROTOCOL %q: want grpc or http/protobuf (http/json is not supported)", p)
}

func setup(ctx context.Context, service, version string, getenv func(string) string, console io.Writer) (Shutdown, error) {
	noop := func(context.Context) error { return nil }
	if strings.EqualFold(strings.TrimSpace(getenv("OTEL_SDK_DISABLED")), "true") {
		return noop, nil
	}
	traces, err := exporterFor(getenv, "TRACES")
	if err != nil {
		return noop, err
	}
	metrics, err := exporterFor(getenv, "METRICS")
	if err != nil {
		return noop, err
	}
	if traces == "none" && metrics == "none" {
		return noop, nil
	}

	res, err := newResource(ctx, service, version)
	if err != nil {
		return noop, err
	}
	var shutdowns []func(context.Context) error
	p := &providers{prop: Propagator()}
	switch traces {
	case "none":
		p.tp = tracenoop.NewTracerProvider()
	default:
		var exp sdktrace.SpanExporter
		if traces == "console" {
			exp, err = stdouttrace.New(stdouttrace.WithWriter(console))
		} else {
			exp, err = traceExporter(ctx, getenv)
		}
		if err != nil {
			return noop, fmt.Errorf("trace exporter: %w", err)
		}
		// The sampler comes from OTEL_TRACES_SAMPLER(_ARG), default
		// parentbased_always_on; the batcher from OTEL_BSP_*.
		tp := sdktrace.NewTracerProvider(sdktrace.WithResource(res), sdktrace.WithBatcher(exp))
		p.tp = tp
		shutdowns = append(shutdowns, tp.Shutdown)
	}
	switch metrics {
	case "none":
		p.mp = metricnoop.NewMeterProvider()
	default:
		var exp sdkmetric.Exporter
		if metrics == "console" {
			exp, err = stdoutmetric.New(stdoutmetric.WithWriter(console))
		} else {
			exp, err = metricExporter(ctx, getenv)
		}
		if err != nil {
			for _, f := range shutdowns {
				f(ctx)
			}
			return noop, fmt.Errorf("metric exporter: %w", err)
		}
		// The interval comes from OTEL_METRIC_EXPORT_INTERVAL (default 60s).
		mp := sdkmetric.NewMeterProvider(sdkmetric.WithResource(res), sdkmetric.WithReader(sdkmetric.NewPeriodicReader(exp)))
		p.mp = mp
		shutdowns = append(shutdowns, mp.Shutdown)
	}

	otel.SetErrorHandler(otel.ErrorHandlerFunc(func(err error) { log.Printf("otel: %v", err) }))
	otel.SetTracerProvider(p.tp)
	otel.SetMeterProvider(p.mp)
	otel.SetTextMapPropagator(p.prop)
	state.Store(p)
	return func(ctx context.Context) error {
		state.CompareAndSwap(p, nil)
		var errs []error
		for _, f := range shutdowns {
			errs = append(errs, f(ctx))
		}
		return errors.Join(errs...)
	}, nil
}

func traceExporter(ctx context.Context, getenv func(string) string) (sdktrace.SpanExporter, error) {
	proto, err := protocolFor(getenv, "TRACES")
	if err != nil {
		return nil, err
	}
	if proto == "grpc" {
		return otlptracegrpc.New(ctx)
	}
	return otlptracehttp.New(ctx)
}

func metricExporter(ctx context.Context, getenv func(string) string) (sdkmetric.Exporter, error) {
	proto, err := protocolFor(getenv, "METRICS")
	if err != nil {
		return nil, err
	}
	if proto == "grpc" {
		return otlpmetricgrpc.New(ctx)
	}
	return otlpmetrichttp.New(ctx)
}

// newResource describes the process: service.name (OTEL_SERVICE_NAME, else
// service), service.version, OTEL_RESOURCE_ATTRIBUTES, host, OS, runtime
// and pid. Not the command line: flags such as -bearer carry grants.
func newResource(ctx context.Context, service, version string) (*resource.Resource, error) {
	attrs := []resource.Option{
		resource.WithSchemaURL(semconv.SchemaURL),
		resource.WithAttributes(semconv.ServiceName(service)),
	}
	if version != "" {
		attrs = append(attrs, resource.WithAttributes(semconv.ServiceVersion(version)))
	}
	attrs = append(attrs,
		resource.WithTelemetrySDK(),
		resource.WithHost(),
		resource.WithOSType(),
		resource.WithProcessPID(),
		resource.WithProcessExecutableName(),
		resource.WithProcessRuntimeName(),
		resource.WithProcessRuntimeVersion(),
		resource.WithProcessRuntimeDescription(),
		resource.WithFromEnv(), // last: OTEL_SERVICE_NAME and OTEL_RESOURCE_ATTRIBUTES win
	)
	res, err := resource.New(ctx, attrs...)
	if errors.Is(err, resource.ErrPartialResource) {
		log.Printf("otel: resource: %v", err)
		err = nil
	}
	return res, err
}

// ShutdownWithin calls sd with a timeout, logging a failure: what commands
// run on their way out.
func ShutdownWithin(sd Shutdown, d time.Duration) {
	if sd == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	if err := sd(ctx); err != nil {
		log.Printf("otel: shutdown: %v", err)
	}
}
