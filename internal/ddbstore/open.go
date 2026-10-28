package ddbstore

import (
	"context"
	"fmt"
	"net/url"

	"github.com/aws/aws-sdk-go-v2/aws"
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
func Open(ctx context.Context, rawurl string) (*Store, error) {
	u, err := url.Parse(rawurl)
	if err != nil || u.Scheme != "dynamodb" || u.Host == "" {
		return nil, fmt.Errorf("ddb: a dynamodb URL is dynamodb://<table>?region=…&endpoint=…, got %q", rawurl)
	}
	table := u.Host
	region := u.Query().Get("region")
	endpoint := u.Query().Get("endpoint")
	opts := []func(*config.LoadOptions) error{}
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
