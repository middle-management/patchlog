package core

import (
	"context"
	"errors"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"

	"github.com/middle-management/patchlog/internal/telemetry"
)

// OpenTelemetry in the engine, kept light: a span per database
// transaction ("core.db.read", "core.db.update": what a request costs
// beyond the read cache), the sizes of group commits and the time spent
// waiting for Postgres advisory locks. Nothing is recorded while telemetry
// is off (telemetry.Instruments.Get is nil). Engine-level spans of writes
// are made by its HTTP caller (internal/server/otel.go).

type coreInst struct {
	tracer    trace.Tracer
	groupSize metric.Int64Histogram
	lockWait  metric.Float64Histogram
}

var inst = telemetry.NewInstruments("internal/core", func(t trace.Tracer, m metric.Meter) *coreInst {
	return &coreInst{
		tracer: t,
		groupSize: telemetry.Must(m.Int64Histogram("patchlog.groupcommit.size",
			metric.WithDescription("Writes committed together in one group commit transaction (Postgres, D.8)"),
			metric.WithUnit("{write}"),
			metric.WithExplicitBucketBoundaries(1, 2, 4, 8, 16, 32, 64, 128))),
		lockWait: telemetry.Must(m.Float64Histogram("patchlog.db.lock.wait",
			metric.WithDescription("Time spent waiting for a Postgres advisory lock (namespace or log lock)"),
			metric.WithUnit("s"),
			metric.WithExplicitBucketBoundaries(0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1, 5))),
	}
})

var (
	attrDBSystem = attribute.Key("db.system.name")
	attrLock     = attribute.Key("patchlog.lock")
)

// dbSpan starts the span of a database transaction (nil while off). Only
// within a trace: background jobs (the tailer's polls, retention, remote
// following) would otherwise start a root trace per transaction.
func (e *Engine) dbSpan(ctx context.Context, name string) (context.Context, trace.Span) {
	in := inst.Get()
	if in == nil || !trace.SpanContextFromContext(ctx).IsValid() {
		return ctx, nil
	}
	sys := "sqlite"
	if e.pg {
		sys = "postgresql"
	}
	return in.tracer.Start(ctx, name, trace.WithSpanKind(trace.SpanKindInternal), trace.WithAttributes(attrDBSystem.String(sys)))
}

// endDBSpan ends span with err: engine errors (*Error: refusals such as
// 404 or 412) are outcomes, not failures.
func endDBSpan(span trace.Span, err error) {
	if span == nil {
		return
	}
	var ce *Error
	if err != nil && !errors.As(err, &ce) {
		span.RecordError(err)
		span.SetStatus(codes.Error, "")
	}
	span.End()
}

// observeGroup records the size of a group commit.
func observeGroup(n int) {
	if in := inst.Get(); in != nil {
		in.groupSize.Record(context.Background(), int64(n))
	}
}

// lockTimer measures an advisory lock wait: defer lockTimer("ns")().
func lockTimer(kind string) func() {
	in := inst.Get()
	if in == nil {
		return func() {}
	}
	start := time.Now()
	return func() {
		in.lockWait.Record(context.Background(), time.Since(start).Seconds(), metric.WithAttributes(attrLock.String(kind)))
	}
}
