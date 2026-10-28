package ddbstore

import (
	"errors"
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
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
