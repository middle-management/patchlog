package ddbstore

import (
	"testing"
	"time"
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
