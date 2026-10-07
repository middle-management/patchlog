package follow

import (
	"context"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"

	"github.com/middle-management/patchlog/internal/telemetry"
)

// OpenTelemetry metrics of consumers (index, tree and catalog services):
// how many units they apply, and how far behind the log they are when
// they apply them. Namespaces are not metric attributes (tenant-scale).

type followInst struct {
	units metric.Int64Counter
	lag   metric.Float64Histogram
}

var inst = telemetry.NewInstruments("internal/follow", func(_ trace.Tracer, m metric.Meter) *followInst {
	return &followInst{
		units: telemetry.Must(m.Int64Counter("patchlog.follow.units",
			metric.WithDescription("Units (entries, or batches as a whole) a consumer applied"),
			metric.WithUnit("{unit}"))),
		lag: telemetry.Must(m.Float64Histogram("patchlog.follow.lag",
			metric.WithDescription("Consumer lag: time from a namespace entry's creation to the consumer applying it (newest entry of each applied batch; catching up shows as large values)"),
			metric.WithUnit("s"),
			metric.WithExplicitBucketBoundaries(0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60, 300, 3600))),
	}
})

var attrSnapshot = attribute.Key("patchlog.follow.snapshot")

// observeApplied records an applied batch.
func observeApplied(b *Batch) {
	in := inst.Get()
	if in == nil || len(b.Units) == 0 {
		return
	}
	ctx := context.Background()
	in.units.Add(ctx, int64(len(b.Units)), metric.WithAttributes(attrSnapshot.Bool(b.Snapshot)))
	if b.Snapshot {
		return
	}
	if t, err := time.Parse(time.RFC3339Nano, b.Units[len(b.Units)-1].Entry.Created); err == nil {
		in.lag.Record(ctx, max(time.Since(t), 0).Seconds())
	}
}
