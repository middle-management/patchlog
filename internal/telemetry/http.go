package telemetry

import (
	"net/http"
	"strings"
	"sync/atomic"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel/attribute"
	semconv "go.opentelemetry.io/otel/semconv/v1.43.0"
	"go.opentelemetry.io/otel/trace"
)

// Handler instruments h with otelhttp when telemetry is on, and returns h
// itself otherwise. Server spans are named "{method} {route}", the route
// being the http.ServeMux pattern that matched (Request.Pattern) or one a
// hand-routed handler declared with SetRoute, so no ids or names from the
// URL path reach span names or metric attributes; without a route the
// span is named by the method alone. Request bodies and headers are not
// recorded (otelhttp records neither by default); url.path is a span
// attribute, the query is not recorded. Wrap h before lifecycle adds its
// health endpoints, so probes are not traced.
func Handler(h http.Handler) http.Handler {
	p := state.Load()
	if p == nil {
		return h
	}
	return otelhttp.NewHandler(routeAttr(h), "",
		otelhttp.WithTracerProvider(p.tp),
		otelhttp.WithMeterProvider(p.mp),
		otelhttp.WithPropagators(p.prop),
	)
}

// routeAttr adds http.route to the server span once the inner handler has
// routed the request (otelhttp renames the span and labels its metrics
// with the route itself, but sets the span attribute only at the start,
// before routing).
func routeAttr(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r)
		if r.Pattern == "" {
			return
		}
		if i := strings.IndexByte(r.Pattern, '/'); i >= 0 {
			trace.SpanFromContext(r.Context()).SetAttributes(semconv.HTTPRoute(r.Pattern[i:]))
		}
	})
}

// SetRoute declares the route of a request a handler routes by hand (not
// through http.ServeMux), e.g. "/{ns}/at/{at}", for span names and the
// http.route attribute. It only does something while telemetry is on and
// no ServeMux pattern is set.
func SetRoute(r *http.Request, route string) {
	if r.Pattern == "" && Enabled() {
		r.Pattern = route
	}
}

// SetAttributes adds attributes to the span of r's context, if any.
func SetAttributes(r *http.Request, kv ...attribute.KeyValue) {
	if Enabled() {
		trace.SpanFromContext(r.Context()).SetAttributes(kv...)
	}
}

// Transport returns a RoundTripper over base (nil: the package's own pool,
// defaultTransport) that, while telemetry is on, makes client spans and
// http.client metrics and injects the trace context (W3C traceparent,
// baggage) into outgoing requests; while it is off it is base. It decides
// per request, so clients built before Setup are covered.
func Transport(base http.RoundTripper) http.RoundTripper {
	if _, ok := base.(*transport); ok {
		return base
	}
	return &transport{base: base}
}

type transport struct {
	base http.RoundTripper
	cur  atomic.Pointer[otelRT]
}

// otelRT is the otelhttp transport built for one set of providers.
type otelRT struct {
	p  *providers
	rt http.RoundTripper
}

// defaultTransport is the base of every Transport given none, so of
// DefaultClient too: a clone of http.DefaultTransport (same proxy, TLS and
// timeouts) with a connection pool of its own, so that whatever closes or
// reconfigures the default one (httptest.Server.Close closes its idle
// connections) doesn't break requests in flight here.
var defaultTransport = func() http.RoundTripper {
	if t, ok := http.DefaultTransport.(*http.Transport); ok {
		return t.Clone()
	}
	return http.DefaultTransport
}()

func (t *transport) baseRT() http.RoundTripper {
	if t.base == nil {
		return defaultTransport
	}
	return t.base
}

func (t *transport) RoundTrip(r *http.Request) (*http.Response, error) {
	p := state.Load()
	if p == nil {
		return t.baseRT().RoundTrip(r)
	}
	o := t.cur.Load()
	if o == nil || o.p != p {
		o = &otelRT{p: p, rt: otelhttp.NewTransport(t.baseRT(),
			otelhttp.WithTracerProvider(p.tp),
			otelhttp.WithMeterProvider(p.mp),
			otelhttp.WithPropagators(p.prop),
			otelhttp.WithSpanNameFormatter(func(_ string, r *http.Request) string { return r.Method }),
		)}
		t.cur.Store(o)
	}
	return o.rt.RoundTrip(r)
}

// CloseIdleConnections passes through to the base transport.
func (t *transport) CloseIdleConnections() {
	if c, ok := t.baseRT().(interface{ CloseIdleConnections() }); ok {
		c.CloseIdleConnections()
	}
}

// Client returns a copy of c (nil: a zero Client) whose transport is
// wrapped by Transport.
func Client(c *http.Client) *http.Client {
	var out http.Client
	if c != nil {
		out = *c
	}
	out.Transport = Transport(out.Transport)
	return &out
}

// DefaultClient is http.DefaultClient with Transport over the package's
// own pool: for code that would otherwise use http.DefaultClient.
var DefaultClient = Client(nil)
