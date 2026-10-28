package ddbstore

// A span per DynamoDB call, under the request's (core's "core.db.read" and
// "core.db.update"), so a trace shows what a read or a write cost on the
// table: the operation, the table, and for a transaction, whether a
// condition failed. Only within a trace, as core's database spans: the
// background jobs would otherwise start a root trace per call. Nothing is
// recorded while telemetry is off (telemetry.Instruments.Get is nil).
//
// A failed condition is the store's optimistic concurrency at work (the
// commit finds what its checks read moved: ErrStale, checked again), not
// a failure: it is an attribute, and the span's status stays unset.

import (
	"context"
	"errors"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"

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
)

// tracedAPI is the client with a span per call.
type tracedAPI struct {
	API
	table string
}

// span starts the span of a call of op (nil while off or outside a
// trace).
func (a tracedAPI) span(ctx context.Context, op string, attrs ...attribute.KeyValue) (context.Context, trace.Span) {
	t := inst.Get()
	if t == nil || !trace.SpanContextFromContext(ctx).IsValid() {
		return ctx, nil
	}
	attrs = append(attrs, attrDBSystem, attrRPCSystem, attrRPCService, attrRPCMethod.String(op), attrTables.StringSlice([]string{a.table}))
	return (*t).Start(ctx, "DynamoDB."+op, trace.WithSpanKind(trace.SpanKindClient), trace.WithAttributes(attrs...))
}

// end ends span with err: a failed condition is an outcome (above).
func end(span trace.Span, err error) {
	if span == nil {
		return
	}
	if err != nil {
		if conditionFailed(err) {
			span.SetAttributes(attrConditionFails.Bool(true))
		} else {
			span.RecordError(err)
			span.SetStatus(codes.Error, "")
		}
	}
	span.End()
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

func (a tracedAPI) GetItem(ctx context.Context, in *dynamodb.GetItemInput, o ...func(*dynamodb.Options)) (out *dynamodb.GetItemOutput, err error) {
	ctx, span := a.span(ctx, "GetItem")
	defer func() { end(span, err) }()
	return a.API.GetItem(ctx, in, o...)
}

func (a tracedAPI) BatchGetItem(ctx context.Context, in *dynamodb.BatchGetItemInput, o ...func(*dynamodb.Options)) (out *dynamodb.BatchGetItemOutput, err error) {
	n := 0
	for _, ka := range in.RequestItems {
		n += len(ka.Keys)
	}
	ctx, span := a.span(ctx, "BatchGetItem", attrItems.Int(n))
	defer func() { end(span, err) }()
	return a.API.BatchGetItem(ctx, in, o...)
}

func (a tracedAPI) Query(ctx context.Context, in *dynamodb.QueryInput, o ...func(*dynamodb.Options)) (out *dynamodb.QueryOutput, err error) {
	var attrs []attribute.KeyValue
	if in.IndexName != nil {
		attrs = append(attrs, attrIndex.String(*in.IndexName))
	}
	ctx, span := a.span(ctx, "Query", attrs...)
	defer func() { end(span, err) }()
	return a.API.Query(ctx, in, o...)
}

func (a tracedAPI) UpdateItem(ctx context.Context, in *dynamodb.UpdateItemInput, o ...func(*dynamodb.Options)) (out *dynamodb.UpdateItemOutput, err error) {
	ctx, span := a.span(ctx, "UpdateItem")
	defer func() { end(span, err) }()
	return a.API.UpdateItem(ctx, in, o...)
}

func (a tracedAPI) DeleteItem(ctx context.Context, in *dynamodb.DeleteItemInput, o ...func(*dynamodb.Options)) (out *dynamodb.DeleteItemOutput, err error) {
	ctx, span := a.span(ctx, "DeleteItem")
	defer func() { end(span, err) }()
	return a.API.DeleteItem(ctx, in, o...)
}

func (a tracedAPI) Scan(ctx context.Context, in *dynamodb.ScanInput, o ...func(*dynamodb.Options)) (out *dynamodb.ScanOutput, err error) {
	ctx, span := a.span(ctx, "Scan")
	defer func() { end(span, err) }()
	return a.API.Scan(ctx, in, o...)
}

func (a tracedAPI) PutItem(ctx context.Context, in *dynamodb.PutItemInput, o ...func(*dynamodb.Options)) (out *dynamodb.PutItemOutput, err error) {
	ctx, span := a.span(ctx, "PutItem")
	defer func() { end(span, err) }()
	return a.API.PutItem(ctx, in, o...)
}

func (a tracedAPI) BatchWriteItem(ctx context.Context, in *dynamodb.BatchWriteItemInput, o ...func(*dynamodb.Options)) (out *dynamodb.BatchWriteItemOutput, err error) {
	n := 0
	for _, ws := range in.RequestItems {
		n += len(ws)
	}
	ctx, span := a.span(ctx, "BatchWriteItem", attrItems.Int(n))
	defer func() { end(span, err) }()
	return a.API.BatchWriteItem(ctx, in, o...)
}

func (a tracedAPI) TransactWriteItems(ctx context.Context, in *dynamodb.TransactWriteItemsInput, o ...func(*dynamodb.Options)) (out *dynamodb.TransactWriteItemsOutput, err error) {
	ctx, span := a.span(ctx, "TransactWriteItems", attrItems.Int(len(in.TransactItems)))
	defer func() { end(span, err) }()
	return a.API.TransactWriteItems(ctx, in, o...)
}

func (a tracedAPI) DescribeTable(ctx context.Context, in *dynamodb.DescribeTableInput, o ...func(*dynamodb.Options)) (out *dynamodb.DescribeTableOutput, err error) {
	ctx, span := a.span(ctx, "DescribeTable")
	defer func() { end(span, err) }()
	return a.API.DescribeTable(ctx, in, o...)
}
