package telemetry

import (
	"sync/atomic"

	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"
)

// ScopePrefix prefixes every instrumentation scope name.
const ScopePrefix = "github.com/middle-management/patchlog/"

// Instruments holds a package's tracer and metric instruments, built from
// the installed providers the first time they are needed (and again if
// other providers are installed, as tests do). Get is nil while telemetry
// is off, so instrumented code costs one atomic load then.
type Instruments[T any] struct {
	scope string
	build func(trace.Tracer, metric.Meter) *T
	cur   atomic.Pointer[built[T]]
}

type built[T any] struct {
	p *providers
	v *T
}

// NewInstruments returns the instruments build makes for scope (a package
// path below ScopePrefix, e.g. "internal/core").
func NewInstruments[T any](scope string, build func(trace.Tracer, metric.Meter) *T) *Instruments[T] {
	return &Instruments[T]{scope: ScopePrefix + scope, build: build}
}

// Get returns the instruments, or nil while telemetry is off.
func (i *Instruments[T]) Get() *T {
	p := state.Load()
	if p == nil {
		return nil
	}
	if b := i.cur.Load(); b != nil && b.p == p {
		return b.v
	}
	v := i.build(p.tp.Tracer(i.scope), p.mp.Meter(i.scope))
	i.cur.Store(&built[T]{p: p, v: v})
	return v
}

// Must drops an instrument constructor's error: the SDK returns a working
// (if misnamed) instrument with it, and reports the error itself.
func Must[I any](i I, _ error) I { return i }
