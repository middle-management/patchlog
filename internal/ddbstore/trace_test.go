package ddbstore

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"go.opentelemetry.io/otel/attribute"
	noopmetric "go.opentelemetry.io/otel/metric/noop"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"github.com/middle-management/patchlog/internal/telemetry"
)

// A failed condition is an outcome of optimistic concurrency, not a call
// failure (trace.go); a cancellation for anything else is.
func TestConditionFailed(t *testing.T) {
	reasons := func(codes ...string) error {
		var rs []types.CancellationReason
		for _, c := range codes {
			c := c
			rs = append(rs, types.CancellationReason{Code: &c})
		}
		return fmt.Errorf("commit: %w", &types.TransactionCanceledException{CancellationReasons: rs})
	}
	for _, c := range []struct {
		err  error
		want bool
	}{
		{&types.ConditionalCheckFailedException{}, true},
		{reasons("None", "ConditionalCheckFailed"), true},
		{reasons("TransactionConflict", "None"), true},
		{reasons("None", "ValidationError"), false},
		{reasons("ConditionalCheckFailed", "ThrottlingError"), false},
		{reasons("None"), false},
		{errors.New("connection reset"), false},
	} {
		if got := conditionFailed(c.err); got != c.want {
			t.Errorf("conditionFailed(%v) = %v, want %v", c.err, got, c.want)
		}
	}
}

// A traced call counts the SDK's attempts at it and those DynamoDB
// throttled: here one throttled, retried, then answered.
func TestTracedAttempts(t *testing.T) {
	rec := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(rec))
	t.Cleanup(telemetry.Use(tp, noopmetric.NewMeterProvider()))
	answers := []string{
		`{"__type":"com.amazonaws.dynamodb.v20120810#ProvisionedThroughputExceededException","message":"slow down"}`,
		`{"Item":{"PK":{"S":"a"}},"ConsumedCapacity":{"TableName":"t","CapacityUnits":0.5}}`,
	}
	client := dynamodb.New(dynamodb.Options{
		Region:      "us-east-1",
		Credentials: credentials.NewStaticCredentialsProvider("k", "s", ""),
		Retryer: retry.NewStandard(func(o *retry.StandardOptions) {
			o.Backoff = retry.BackoffDelayerFunc(func(int, error) (time.Duration, error) { return 0, nil })
		}),
		HTTPClient: roundTrip(func(r *http.Request) (*http.Response, error) {
			status, body := 200, answers[0]
			if len(answers) == 2 {
				status = 400
			}
			answers = answers[1:]
			return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": {"application/x-amz-json-1.0"}},
				Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
		}),
	})
	ctx, root := tp.Tracer("test").Start(context.Background(), "request")
	if _, err := (tracedAPI{API: client, table: "t"}).GetItem(ctx, &dynamodb.GetItemInput{TableName: aws.String("t"), Key: map[string]types.AttributeValue{"PK": &types.AttributeValueMemberS{Value: "a"}}}); err != nil {
		t.Fatal(err)
	}
	root.End()
	var attrs map[attribute.Key]string
	for _, s := range rec.Ended() {
		if s.Name() == "DynamoDB.GetItem" {
			attrs = map[attribute.Key]string{}
			for _, kv := range s.Attributes() {
				attrs[kv.Key] = kv.Value.Emit()
			}
		}
	}
	if attrs["patchlog.dynamodb.attempts"] != "2" || attrs["patchlog.dynamodb.throttled"] != "1" || attrs["patchlog.dynamodb.read_units"] != "0.5" {
		t.Fatalf("GetItem span attributes %v", attrs)
	}
}

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) Do(r *http.Request) (*http.Response, error) { return f(r) }
