package ddbstore

// A span per DynamoDB call, under the request's (core's "core.db.read" and
// "core.db.update"), so a trace shows what a read or a write cost on the
// table: the operation, the table, and for a transaction, whether a
// condition failed. Only within a trace, as core's database spans: the
// background jobs would otherwise start a root trace per call. Nothing is
// recorded while telemetry is off (telemetry.Instruments.Get is nil).
//
// A timeout inside the SDK, while the caller still waits, is DynamoDB not
// answering (finish): a 503, logged, rather than a cancelled request.
//
// A failed condition is the store's optimistic concurrency at work (the
// commit finds what its checks read moved: ErrStale, checked again), not
// a failure: it is an attribute, and the span's status stays unset.
//
// A traced call also says what it cost and what it waited for: the
// capacity units it consumed (DynamoDB's ReturnConsumedCapacity, asked for
// only while traced), the SDK's attempts at it, those DynamoDB throttled,
// and a batch read's keys left unprocessed. A partition key takes about
// 3,000 read and 1,000 write units a second, and a namespace is one
// partition key (docs/DYNAMODB.md §3): these say how near a load is to it.

import (
	"context"
	"errors"
	"log"
	"runtime"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/smithy-go/middleware"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"

	"github.com/middle-management/patchlog/internal/ddb"
	"github.com/middle-management/patchlog/internal/telemetry"
)

var inst = telemetry.NewInstruments("internal/ddbstore", func(t trace.Tracer, _ metric.Meter) *trace.Tracer { return &t })

var (
	attrDBSystem       = attribute.String("db.system.name", "aws.dynamodb")
	attrRPCSystem      = attribute.String("rpc.system", "aws-api")
	attrRPCService     = attribute.String("rpc.service", "DynamoDB")
	attrRPCMethod      = attribute.Key("rpc.method")
	attrTables         = attribute.Key("aws.dynamodb.table_names")
	attrIndex          = attribute.Key("aws.dynamodb.index_name")
	attrItems          = attribute.Key("patchlog.dynamodb.items")
	attrConditionFails = attribute.Key("patchlog.dynamodb.condition_failed")
	attrReadUnits      = attribute.Key("patchlog.dynamodb.read_units")
	attrWriteUnits     = attribute.Key("patchlog.dynamodb.write_units")
	attrAttempts       = attribute.Key("patchlog.dynamodb.attempts")
	attrThrottled      = attribute.Key("patchlog.dynamodb.throttled")
	attrUnprocessed    = attribute.Key("patchlog.dynamodb.unprocessed")
	attrFunction       = attribute.Key("code.function.name")
)

var throttles = retry.IsErrorThrottles(retry.DefaultThrottles)

// tracedAPI is the client with a span per call.
type tracedAPI struct {
	API
	table string
}

// call is a traced call: its span, and what it cost and waited for.
type call struct {
	span                trace.Span
	units               float64
	attempts, throttled int
	unprocessed         int
	readCall            bool
}

// start starts the span of a call of op, and returns the call's options
// with a count of its attempts (nil while off or outside a trace).
func (a tracedAPI) start(ctx context.Context, op string, o []func(*dynamodb.Options), attrs ...attribute.KeyValue) (context.Context, *call, []func(*dynamodb.Options)) {
	t := inst.Get()
	if t == nil || !trace.SpanContextFromContext(ctx).IsValid() {
		return ctx, nil, o
	}
	attrs = append(attrs, attrDBSystem, attrRPCSystem, attrRPCService, attrRPCMethod.String(op), attrTables.StringSlice([]string{a.table}),
		attrFunction.String(caller()))
	ctx, span := (*t).Start(ctx, "DynamoDB."+op, trace.WithSpanKind(trace.SpanKindClient), trace.WithAttributes(attrs...))
	c := &call{span: span}
	switch op {
	case "GetItem", "BatchGetItem", "Query", "Scan":
		c.readCall = true
	}
	return ctx, c, append(o[:len(o):len(o)], c.count)
}

// caller is the function that made the call: the first frame above the
// traced client's own, e.g. "ddbstore.(*Store).Heads", so a span says which
// of the store's reads or writes it was.
func caller() string {
	var pcs [8]uintptr
	frames := runtime.CallersFrames(pcs[:runtime.Callers(3, pcs[:])])
	for {
		f, more := frames.Next()
		if !strings.Contains(f.Function, "tracedAPI") {
			return f.Function[strings.LastIndex(f.Function, "/")+1:]
		}
		if !more {
			return ""
		}
	}
}

// count runs a middleware after the retryer's, once per attempt.
func (c *call) count(o *dynamodb.Options) {
	o.APIOptions = append(o.APIOptions, func(s *middleware.Stack) error {
		return s.Finalize.Insert(middleware.FinalizeMiddlewareFunc("patchlog.attempts",
			func(ctx context.Context, in middleware.FinalizeInput, next middleware.FinalizeHandler) (middleware.FinalizeOutput, middleware.Metadata, error) {
				c.attempts++
				out, md, err := next.HandleFinalize(ctx, in)
				if err != nil && (throttles.IsErrorThrottle(err).Bool() || cancelledFor(err, "ThrottlingError")) {
					c.throttled++
				}
				return out, md, err
			}), "Retry", middleware.After)
	})
}

// consumed adds the capacity a call's answer says it consumed.
func (c *call) consumed(ccs ...*types.ConsumedCapacity) {
	if c == nil {
		return
	}
	for _, cc := range ccs {
		if cc != nil && cc.CapacityUnits != nil {
			c.units += *cc.CapacityUnits
		}
	}
}

func (c *call) consumedAll(ccs []types.ConsumedCapacity) {
	for i := range ccs {
		c.consumed(&ccs[i])
	}
}

// done ends the call's span with err, and returns err as the store answers
// it: a timeout of the SDK's own (resolving credentials, a region, a
// connection) while the caller's context is still live is DynamoDB not
// answering, a 503, not the caller going away; the cause is logged, not
// served.
func (c *call) done(ctx context.Context, err error) error {
	if c != nil {
		c.end(err)
	}
	if err != nil && ctx.Err() == nil && (errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled)) {
		log.Printf("ddbstore: DynamoDB didn't answer: %v", err)
		return &ddb.Error{Status: 503, Body: map[string]any{"code": "unavailable", "message": "the storage (DynamoDB) didn't answer in time"}}
	}
	return err
}

// end ends the span with err: a failed condition is an outcome (above).
func (c *call) end(err error) {
	units := attrWriteUnits
	if c.readCall {
		units = attrReadUnits
	}
	c.span.SetAttributes(units.Float64(c.units), attrAttempts.Int(c.attempts), attrThrottled.Int(c.throttled))
	if c.unprocessed > 0 {
		c.span.SetAttributes(attrUnprocessed.Int(c.unprocessed))
	}
	if err != nil {
		if conditionFailed(err) {
			c.span.SetAttributes(attrConditionFails.Bool(true))
		} else {
			c.span.RecordError(err)
			c.span.SetStatus(codes.Error, "")
		}
	}
	c.span.End()
}

// cancelledFor reports a transaction cancelled for code on one of its items.
func cancelledFor(err error, code string) bool {
	var tc *types.TransactionCanceledException
	if !errors.As(err, &tc) {
		return false
	}
	for _, r := range tc.CancellationReasons {
		if deref(r.Code) == code {
			return true
		}
	}
	return false
}

// conditionFailed reports a call refused by its conditions alone: a
// condition that didn't hold, or a transaction cancelled for one (or for
// a concurrent transaction on its items).
func conditionFailed(err error) bool {
	var cc *types.ConditionalCheckFailedException
	if errors.As(err, &cc) {
		return true
	}
	var tc *types.TransactionCanceledException
	if !errors.As(err, &tc) {
		return false
	}
	failed := false
	for _, r := range tc.CancellationReasons {
		switch code := deref(r.Code); code {
		case "", "None":
		case "ConditionalCheckFailed", "TransactionConflict":
			failed = true
		default:
			return false
		}
	}
	return failed
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// total asks for the consumed capacity of a traced call.
const total = types.ReturnConsumedCapacityTotal

func (a tracedAPI) GetItem(ctx context.Context, in *dynamodb.GetItemInput, o ...func(*dynamodb.Options)) (out *dynamodb.GetItemOutput, err error) {
	ctx, c, o := a.start(ctx, "GetItem", o)
	if c != nil {
		cp := *in
		cp.ReturnConsumedCapacity = total
		in = &cp
	}
	defer func() {
		if out != nil {
			c.consumed(out.ConsumedCapacity)
		}
		err = c.done(ctx, err)
	}()
	return a.API.GetItem(ctx, in, o...)
}

func (a tracedAPI) BatchGetItem(ctx context.Context, in *dynamodb.BatchGetItemInput, o ...func(*dynamodb.Options)) (out *dynamodb.BatchGetItemOutput, err error) {
	n := 0
	for _, ka := range in.RequestItems {
		n += len(ka.Keys)
	}
	ctx, c, o := a.start(ctx, "BatchGetItem", o, attrItems.Int(n))
	if c != nil {
		cp := *in
		cp.ReturnConsumedCapacity = total
		in = &cp
	}
	defer func() {
		if out != nil && c != nil {
			c.consumedAll(out.ConsumedCapacity)
			for _, ka := range out.UnprocessedKeys {
				c.unprocessed += len(ka.Keys)
			}
		}
		err = c.done(ctx, err)
	}()
	return a.API.BatchGetItem(ctx, in, o...)
}

func (a tracedAPI) Query(ctx context.Context, in *dynamodb.QueryInput, o ...func(*dynamodb.Options)) (out *dynamodb.QueryOutput, err error) {
	var attrs []attribute.KeyValue
	if in.IndexName != nil {
		attrs = append(attrs, attrIndex.String(*in.IndexName))
	}
	ctx, c, o := a.start(ctx, "Query", o, attrs...)
	if c != nil {
		cp := *in
		cp.ReturnConsumedCapacity = total
		in = &cp
	}
	defer func() {
		if out != nil {
			c.consumed(out.ConsumedCapacity)
			if c != nil {
				c.span.SetAttributes(attrItems.Int(int(out.Count)))
			}
		}
		err = c.done(ctx, err)
	}()
	return a.API.Query(ctx, in, o...)
}

func (a tracedAPI) UpdateItem(ctx context.Context, in *dynamodb.UpdateItemInput, o ...func(*dynamodb.Options)) (out *dynamodb.UpdateItemOutput, err error) {
	ctx, c, o := a.start(ctx, "UpdateItem", o)
	if c != nil {
		cp := *in
		cp.ReturnConsumedCapacity = total
		in = &cp
	}
	defer func() {
		if out != nil {
			c.consumed(out.ConsumedCapacity)
		}
		err = c.done(ctx, err)
	}()
	return a.API.UpdateItem(ctx, in, o...)
}

func (a tracedAPI) DeleteItem(ctx context.Context, in *dynamodb.DeleteItemInput, o ...func(*dynamodb.Options)) (out *dynamodb.DeleteItemOutput, err error) {
	ctx, c, o := a.start(ctx, "DeleteItem", o)
	if c != nil {
		cp := *in
		cp.ReturnConsumedCapacity = total
		in = &cp
	}
	defer func() {
		if out != nil {
			c.consumed(out.ConsumedCapacity)
		}
		err = c.done(ctx, err)
	}()
	return a.API.DeleteItem(ctx, in, o...)
}

func (a tracedAPI) Scan(ctx context.Context, in *dynamodb.ScanInput, o ...func(*dynamodb.Options)) (out *dynamodb.ScanOutput, err error) {
	ctx, c, o := a.start(ctx, "Scan", o)
	if c != nil {
		cp := *in
		cp.ReturnConsumedCapacity = total
		in = &cp
	}
	defer func() {
		if out != nil {
			c.consumed(out.ConsumedCapacity)
		}
		err = c.done(ctx, err)
	}()
	return a.API.Scan(ctx, in, o...)
}

func (a tracedAPI) PutItem(ctx context.Context, in *dynamodb.PutItemInput, o ...func(*dynamodb.Options)) (out *dynamodb.PutItemOutput, err error) {
	ctx, c, o := a.start(ctx, "PutItem", o)
	if c != nil {
		cp := *in
		cp.ReturnConsumedCapacity = total
		in = &cp
	}
	defer func() {
		if out != nil {
			c.consumed(out.ConsumedCapacity)
		}
		err = c.done(ctx, err)
	}()
	return a.API.PutItem(ctx, in, o...)
}

func (a tracedAPI) BatchWriteItem(ctx context.Context, in *dynamodb.BatchWriteItemInput, o ...func(*dynamodb.Options)) (out *dynamodb.BatchWriteItemOutput, err error) {
	n := 0
	for _, ws := range in.RequestItems {
		n += len(ws)
	}
	ctx, c, o := a.start(ctx, "BatchWriteItem", o, attrItems.Int(n))
	if c != nil {
		cp := *in
		cp.ReturnConsumedCapacity = total
		in = &cp
	}
	defer func() {
		if out != nil && c != nil {
			c.consumedAll(out.ConsumedCapacity)
			for _, ws := range out.UnprocessedItems {
				c.unprocessed += len(ws)
			}
		}
		err = c.done(ctx, err)
	}()
	return a.API.BatchWriteItem(ctx, in, o...)
}

func (a tracedAPI) TransactWriteItems(ctx context.Context, in *dynamodb.TransactWriteItemsInput, o ...func(*dynamodb.Options)) (out *dynamodb.TransactWriteItemsOutput, err error) {
	ctx, c, o := a.start(ctx, "TransactWriteItems", o, attrItems.Int(len(in.TransactItems)))
	if c != nil {
		cp := *in
		cp.ReturnConsumedCapacity = total
		in = &cp
	}
	defer func() {
		if out != nil && c != nil {
			c.consumedAll(out.ConsumedCapacity)
		}
		err = c.done(ctx, err)
	}()
	return a.API.TransactWriteItems(ctx, in, o...)
}

func (a tracedAPI) DescribeTable(ctx context.Context, in *dynamodb.DescribeTableInput, o ...func(*dynamodb.Options)) (out *dynamodb.DescribeTableOutput, err error) {
	ctx, c, o := a.start(ctx, "DescribeTable", o)
	defer func() { err = c.done(ctx, err) }()
	return a.API.DescribeTable(ctx, in, o...)
}
