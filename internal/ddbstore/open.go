package ddbstore

import (
	"context"
	"fmt"
	"math/rand/v2"
	"net/http"
	"net/url"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/ratelimit"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"

	"github.com/middle-management/patchlog/internal/ddb"
)

func init() {
	ddb.Register(func(ctx context.Context, rawurl string, o ddb.Options) (ddb.Store, error) {
		s, err := Open(ctx, rawurl)
		if err != nil {
			return nil, err
		}
		s.Now, s.Open, s.GroupCommit, s.OnGroup = o.Now, o.OpenValue, o.GroupCommit, o.OnGroup
		return s, nil
	})
}

var _ ddb.Store = (*Store)(nil)

// MaxBatchItems is MaxBatchItems (ddb.Store).
func (s *Store) MaxBatchItems() int { return MaxBatchItems }

// Open connects to the table named by a dynamodb:// URL:
//
//	dynamodb://patchlog?region=eu-west-1
//	dynamodb://patchlog?region=us-east-1&endpoint=http://localhost:8000   (DynamoDB Local)
//
// Credentials come from the default AWS chain (environment, shared config,
// instance profile); endpoint is for development and tests, where static
// "local" credentials stand in (DynamoDB Local ignores them) and checksum
// validation is off (its responses trip the SDK's).
// maxIdleConns is how many idle connections to DynamoDB the client keeps.
const maxIdleConns = 256

func Open(ctx context.Context, rawurl string) (*Store, error) {
	u, err := url.Parse(rawurl)
	if err != nil || u.Scheme != "dynamodb" || u.Host == "" {
		return nil, fmt.Errorf("ddb: a dynamodb URL is dynamodb://<table>?region=…&endpoint=…, got %q", rawurl)
	}
	table := u.Host
	region := u.Query().Get("region")
	endpoint := u.Query().Get("endpoint")
	// The SDK keeps 10 idle connections a host by default: with more
	// requests in flight than that (writers, readers, group commits), the
	// rest open new ones, each a TLS handshake (~10 ms) before its call.
	httpClient := awshttp.NewBuildableClient().WithTransportOptions(func(tr *http.Transport) {
		tr.MaxIdleConns, tr.MaxIdleConnsPerHost = maxIdleConns, maxIdleConns
	})
	opts := []func(*config.LoadOptions) error{config.WithHTTPClient(httpClient), config.WithRetryer(newRetryer)}
	if region != "" {
		opts = append(opts, config.WithRegion(region))
	}
	if endpoint != "" {
		opts = append(opts,
			config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider("local", "local", "")),
			config.WithResponseChecksumValidation(aws.ResponseChecksumValidationUnset))
	}
	cfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, err
	}
	var client *dynamodb.Client
	if endpoint != "" {
		client = dynamodb.NewFromConfig(cfg, func(o *dynamodb.Options) {
			o.BaseEndpoint = aws.String(endpoint)
		})
	} else {
		client = dynamodb.NewFromConfig(cfg)
	}
	return &Store{Client: tracedAPI{client, table}, Table: table}, nil
}

// The SDK's default retries suit a service whose refusals last seconds:
// three attempts, the first retry after up to 2 s, and a client-wide
// budget a burst of throttling drains, after which calls fail unretried.
// DynamoDB's throttling clears in tens of milliseconds, and a namespace's
// commits run one after another (group.go): one commit backing off for a
// second stalls every write of its namespace that long. So: ten attempts,
// full jitter from 25 ms doubling up to 1 s, and no budget.
const (
	retryAttempts = 10
	retryBase     = 25 * time.Millisecond
	retryMax      = time.Second
)

func newRetryer() aws.Retryer {
	return retry.NewStandard(func(o *retry.StandardOptions) {
		o.MaxAttempts = retryAttempts
		o.MaxBackoff = retryMax
		o.Backoff = retry.BackoffDelayerFunc(retryDelay)
		o.RateLimiter = ratelimit.None
	})
}

// retryDelay is attempt's wait: uniform in [0, min(retryMax, retryBase·2^(attempt-1))].
func retryDelay(attempt int, _ error) (time.Duration, error) {
	ceil := retryMax
	if attempt >= 1 && attempt < 7 {
		ceil = min(retryMax, retryBase<<(attempt-1))
	}
	return time.Duration(rand.Int64N(int64(ceil) + 1)), nil
}
