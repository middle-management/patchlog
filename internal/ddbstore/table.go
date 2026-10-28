package ddbstore

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// CreateTable creates the table a dynamodb:// URL names, with the key
// schema of docs/DYNAMODB.md §3 and GSI1, on demand (PAY_PER_REQUEST), and
// waits until it is ACTIVE. Deployments may create it themselves; tests
// create one each.
func CreateTable(ctx context.Context, rawurl string) error {
	s, err := Open(ctx, rawurl)
	if err != nil {
		return err
	}
	client, ok := sdkClient(s.Client)
	if !ok {
		return fmt.Errorf("ddb: CreateTable needs a *dynamodb.Client")
	}
	if _, err := client.CreateTable(ctx, &dynamodb.CreateTableInput{
		TableName: aws.String(s.Table),
		AttributeDefinitions: []types.AttributeDefinition{
			{AttributeName: aws.String("PK"), AttributeType: types.ScalarAttributeTypeS},
			{AttributeName: aws.String("SK"), AttributeType: types.ScalarAttributeTypeS},
			{AttributeName: aws.String("G1PK"), AttributeType: types.ScalarAttributeTypeS},
		},
		KeySchema: []types.KeySchemaElement{
			{AttributeName: aws.String("PK"), KeyType: types.KeyTypeHash},
			{AttributeName: aws.String("SK"), KeyType: types.KeyTypeRange},
		},
		GlobalSecondaryIndexes: []types.GlobalSecondaryIndex{{
			IndexName:  aws.String(gsiName),
			KeySchema:  []types.KeySchemaElement{{AttributeName: aws.String("G1PK"), KeyType: types.KeyTypeHash}},
			Projection: &types.Projection{ProjectionType: types.ProjectionTypeAll},
		}},
		BillingMode: types.BillingModePayPerRequest,
	}); err != nil {
		return err
	}
	for range 100 {
		out, err := client.DescribeTable(ctx, &dynamodb.DescribeTableInput{TableName: aws.String(s.Table)})
		if err == nil && out.Table.TableStatus == types.TableStatusActive {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
	return fmt.Errorf("ddb: table %s did not become ACTIVE", s.Table)
}

// DeleteTable deletes the table a dynamodb:// URL names (test cleanup).
func DeleteTable(ctx context.Context, rawurl string) error {
	s, err := Open(ctx, rawurl)
	if err != nil {
		return err
	}
	client, ok := sdkClient(s.Client)
	if !ok {
		return fmt.Errorf("ddb: DeleteTable needs a *dynamodb.Client")
	}
	_, err = client.DeleteTable(ctx, &dynamodb.DeleteTableInput{TableName: aws.String(s.Table)})
	return err
}

// sdkClient is the SDK's client under c, traced or not (trace.go): table
// management isn't part of API.
func sdkClient(c API) (*dynamodb.Client, bool) {
	if t, ok := c.(tracedAPI); ok {
		c = t.API
	}
	cl, ok := c.(*dynamodb.Client)
	return cl, ok
}
