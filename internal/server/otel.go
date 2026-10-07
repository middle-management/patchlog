package server

import (
	"context"
	"errors"
	"net/http"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"

	"github.com/middle-management/patchlog/internal/core"
	"github.com/middle-management/patchlog/internal/telemetry"
)

// OpenTelemetry at the engine's write boundary: a span per engine write
// call ("core.<Method>") under the HTTP server span, with the namespace
// (patchlog.ns), the kind of write and its outcome, and the metrics
// patchlog.writes (count) and patchlog.write.duration (seconds) by kind
// and outcome. The namespace is a span attribute only, never a metric
// attribute: namespaces are tenant-scale. Reads are covered by the HTTP
// span, and by the core's database transaction spans when they miss the
// read cache. Nothing is recorded while telemetry is off.

// Attribute keys.
const (
	attrNS      = attribute.Key("patchlog.ns")
	attrKind    = attribute.Key("patchlog.write.kind")
	attrOutcome = attribute.Key("patchlog.outcome")
	attrStatus  = attribute.Key("patchlog.status")
	attrItems   = attribute.Key("patchlog.batch.items")
	attrDryRun  = attribute.Key("patchlog.dry_run")
)

type serverInst struct {
	tracer   trace.Tracer
	writes   metric.Int64Counter
	duration metric.Float64Histogram
}

var inst = telemetry.NewInstruments("internal/server", func(t trace.Tracer, m metric.Meter) *serverInst {
	return &serverInst{
		tracer: t,
		writes: telemetry.Must(m.Int64Counter("patchlog.writes",
			metric.WithDescription("Engine writes by kind and outcome (created, ok, replayed, dry_run, or the error code)"),
			metric.WithUnit("{write}"))),
		duration: telemetry.Must(m.Float64Histogram("patchlog.write.duration",
			metric.WithDescription("Duration of engine writes, authorisation and commit included"),
			metric.WithUnit("s"),
			metric.WithExplicitBucketBoundaries(0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10))),
	}
})

// annotate adds the namespace of a routed request to its server span.
func annotate(r *http.Request) {
	if !telemetry.Enabled() {
		return
	}
	if ns := r.PathValue("ns"); ns != "" {
		trace.SpanFromContext(r.Context()).SetAttributes(attrNS.String(ns))
	}
}

// writeOp is an engine write being observed; nil while telemetry is off.
type writeOp struct {
	in    *serverInst
	span  trace.Span
	kind  string
	start time.Time
}

func startWrite(ctx context.Context, method, kind, ns string, attrs ...attribute.KeyValue) (context.Context, *writeOp) {
	in := inst.Get()
	if in == nil {
		return ctx, nil
	}
	attrs = append(attrs, attrNS.String(ns), attrKind.String(kind))
	ctx, span := in.tracer.Start(ctx, "core."+method, trace.WithAttributes(attrs...))
	return ctx, &writeOp{in: in, span: span, kind: kind, start: time.Now()}
}

// end records the write's outcome: status is the success status (201
// created, 200 replayed or dry run), err the failure.
func (o *writeOp) end(status int, replayed, dryRun bool, err error) {
	if o == nil {
		return
	}
	outcome := "ok"
	switch {
	case err != nil:
		outcome, status = errOutcome(err)
	case dryRun:
		outcome = "dry_run"
	case replayed:
		outcome = "replayed"
	case status == 201:
		outcome = "created"
	}
	if status != 0 {
		o.span.SetAttributes(attrStatus.Int(status))
	}
	o.span.SetAttributes(attrOutcome.String(outcome))
	if err != nil && (status == 0 || status >= 500) {
		o.span.RecordError(err)
		o.span.SetStatus(codes.Error, outcome)
	}
	o.span.End()
	set := metric.WithAttributeSet(attribute.NewSet(attrKind.String(o.kind), attrOutcome.String(outcome)))
	ctx := context.Background()
	o.in.writes.Add(ctx, 1, set)
	o.in.duration.Record(ctx, time.Since(o.start).Seconds(), set)
}

// errOutcome is an engine error's code (§6.2's codes, a bounded set) and
// status.
func errOutcome(err error) (string, int) {
	var ce *core.Error
	if errors.As(err, &ce) {
		if c, ok := ce.Body["code"].(string); ok && c != "" {
			return c, ce.Status
		}
		return "error", ce.Status
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return "canceled", 0
	}
	return "error", 0
}

func (o *writeOp) endResult(res *core.WriteResult, dryRun bool, err error) {
	if o == nil {
		return
	}
	if res == nil {
		o.end(0, false, dryRun, err)
		return
	}
	o.end(res.Status, res.Replayed, dryRun, err)
}

// The engine's writes, observed.

func (s *Server) writeResource(ctx context.Context, req core.Request, item core.Item) (*core.WriteResult, error) {
	kind := "resource"
	if len(item.Steps) == 1 && item.Steps[0].Delete {
		kind = "delete"
	}
	ctx, op := startWrite(ctx, "WriteResource", kind, req.NS)
	res, err := s.e.WriteResource(ctx, req, item)
	op.endResult(res, false, err)
	return res, err
}

func (s *Server) batch(ctx context.Context, req core.Request, items []core.Item, cfg *core.ConfigChange, source any, dryRun bool) (*core.WriteResult, error) {
	ctx, op := startWrite(ctx, "Batch", "batch", req.NS, attrItems.Int(len(items)), attrDryRun.Bool(dryRun))
	res, err := s.e.Batch(ctx, req, items, cfg, source, dryRun)
	op.endResult(res, dryRun, err)
	return res, err
}

func (s *Server) writeConfig(ctx context.Context, req core.Request, cc core.ConfigChange) (*core.WriteResult, error) {
	ctx, op := startWrite(ctx, "WriteConfig", "config", req.NS)
	res, err := s.e.WriteConfig(ctx, req, cc)
	op.endResult(res, false, err)
	return res, err
}

func (s *Server) createBranch(ctx context.Context, req core.Request, br core.BranchRequest) (*core.WriteResult, error) {
	ctx, op := startWrite(ctx, "CreateBranch", "branch", req.NS)
	res, err := s.e.CreateBranch(ctx, req, br)
	op.endResult(res, false, err)
	return res, err
}

func (s *Server) registerRemoteBranch(ctx context.Context, req core.Request, rr core.RemoteRegistration) (*core.RegistrationResult, error) {
	ctx, op := startWrite(ctx, "RegisterRemoteBranch", "remote_registration", req.NS)
	res, err := s.e.RegisterRemoteBranch(ctx, req, rr)
	op.end(0, false, false, err)
	return res, err
}

func (s *Server) purge(ctx context.Context, req core.Request, name, ifMatch string, force bool) (string, error) {
	ctx, op := startWrite(ctx, "Purge", "purge", req.NS)
	id, err := s.e.Purge(ctx, req, name, ifMatch, force)
	op.end(0, false, false, err)
	return id, err
}

func (s *Server) purgeNamespace(ctx context.Context, req core.Request, ifMatch string, force bool) (string, error) {
	ctx, op := startWrite(ctx, "PurgeNamespace", "purge_ns", req.NS)
	id, err := s.e.PurgeNamespace(ctx, req, ifMatch, force)
	op.end(0, false, false, err)
	return id, err
}

func (s *Server) prune(ctx context.Context, req core.Request, name string, pr core.PruneRequest) (*core.PruneResult, error) {
	ctx, op := startWrite(ctx, "Prune", "prune", req.NS)
	res, err := s.e.Prune(ctx, req, name, pr)
	op.end(0, false, false, err)
	return res, err
}

func (s *Server) uploadBlob(ctx context.Context, req core.Request, name, bid string, up core.BlobUpload) error {
	ctx, op := startWrite(ctx, "UploadBlob", "blob", req.NS)
	err := s.e.UploadBlob(ctx, req, name, bid, up)
	op.end(0, false, false, err)
	return err
}
