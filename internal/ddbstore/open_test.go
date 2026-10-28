package ddbstore

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// A retry waits up to 25 ms, doubling to at most 1 s, over ten attempts:
// DynamoDB's throttling clears in milliseconds, and a namespace's commits
// wait behind one backing off.
func TestRetryDelay(t *testing.T) {
	if n := newRetryer().MaxAttempts(); n != retryAttempts {
		t.Fatalf("%d attempts, want %d", n, retryAttempts)
	}
	for attempt, ceil := range map[int]time.Duration{1: 25 * time.Millisecond, 2: 50 * time.Millisecond, 3: 100 * time.Millisecond, 6: 800 * time.Millisecond, 7: time.Second, 12: time.Second} {
		var most time.Duration
		for range 2000 {
			d, err := retryDelay(attempt, nil)
			if err != nil || d < 0 || d > ceil {
				t.Fatalf("attempt %d waits %v (%v), want within [0, %v]", attempt, d, err, ceil)
			}
			most = max(most, d)
		}
		if most < ceil/2 {
			t.Errorf("attempt %d waits at most %v of 2000 draws, want near %v", attempt, most, ceil)
		}
	}
}

// A transaction DynamoDB cancels for throttling alone is tried again; one
// cancelled for a failed condition too comes back: its write is stale.
func TestThrottledTransactionRetried(t *testing.T) {
	cancelled := func(codes ...string) string {
		var rs []string
		for _, c := range codes {
			rs = append(rs, `{"Code":"`+c+`"}`)
		}
		return `{"__type":"com.amazonaws.dynamodb.v20120810#TransactionCanceledException","Message":"cancelled","CancellationReasons":[` + strings.Join(rs, ",") + `]}`
	}
	for _, c := range []struct {
		first    string
		wantErr  bool
		attempts int
	}{
		{cancelled("None", "ThrottlingError"), false, 2},
		{cancelled("ConditionalCheckFailed", "ThrottlingError"), true, 1},
	} {
		answers := []string{c.first, `{}`}
		calls := 0
		client := dynamodb.New(dynamodb.Options{
			Region:      "us-east-1",
			Credentials: credentials.NewStaticCredentialsProvider("k", "s", ""),
			Retryer:     newRetryer(),
			HTTPClient: roundTrip(func(r *http.Request) (*http.Response, error) {
				status := 200
				if calls == 0 {
					status = 400
				}
				body := answers[calls]
				calls++
				return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": {"application/x-amz-json-1.0"}},
					Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
			}),
		})
		_, err := client.TransactWriteItems(context.Background(), &dynamodb.TransactWriteItemsInput{TransactItems: []types.TransactWriteItem{
			{Put: &types.Put{TableName: aws.String("t"), Item: map[string]types.AttributeValue{"PK": &types.AttributeValueMemberS{Value: "a"}}}},
		}})
		if (err != nil) != c.wantErr || calls != c.attempts {
			t.Errorf("first answer %s: %d attempts, %v; want %d attempts, error %v", c.first, calls, err, c.attempts, c.wantErr)
		}
	}
}

// Keys a batch read leaves unprocessed (part of it throttled) are asked
// for again, not taken as absent nor answered as a 503.
func TestPrefetchUnprocessed(t *testing.T) {
	calls := 0
	client := dynamodb.New(dynamodb.Options{
		Region:      "us-east-1",
		Credentials: credentials.NewStaticCredentialsProvider("k", "s", ""),
		Retryer:     newRetryer(),
		HTTPClient: roundTrip(func(r *http.Request) (*http.Response, error) {
			calls++
			body := `{"Responses":{"t":[{"PK":{"S":"NS#n"},"SK":{"S":"#TIP"},"headPos":{"N":"1"},"headId":{"S":"x"}}]},` +
				`"UnprocessedKeys":{"t":{"Keys":[{"PK":{"S":"NS#n"},"SK":{"S":"#META"}}],"ConsistentRead":true}}}`
			if calls > 1 {
				body = `{"Responses":{"t":[{"PK":{"S":"NS#n"},"SK":{"S":"#META"},"configPos":{"N":"1"},"configId":{"S":"c"}}]}}`
			}
			return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/x-amz-json-1.0"}},
				Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
		}),
	})
	s := &Store{Client: client, Table: "t"}
	row, _, err := s.Prefetch(context.Background(), "n", nil)
	if err != nil || row == nil || row.TipPos != 1 || calls != 2 {
		t.Fatalf("prefetch: %+v, %v after %d calls; want the namespace, its tip at 1, after 2", row, err, calls)
	}
}
