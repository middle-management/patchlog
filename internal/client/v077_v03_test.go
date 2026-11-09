package client

import (
	"errors"
	"fmt"
	"testing"
)

// 408 is transient (§A.4, §12.1): retried, not a refusal (ENC-3).
func TestV077Transient408(t *testing.T) {
	ae := &APIError{Status: 408, Path: "/ns/x/keys"}
	if !Transient(ae) {
		t.Error("Transient(408) = false")
	}
	if !Transient(fmt.Errorf("%w: x epoch 1: %w", ErrKeyFetch, ae)) {
		t.Error("Transient(ErrKeyFetch 408) = false")
	}
	if transient(ae) == nil {
		t.Error("transient(408) ends a read-through chain")
	}
	for _, s := range []int{400, 403, 404, 410} {
		if Transient(&APIError{Status: s}) || transient(&APIError{Status: s}) != nil {
			t.Errorf("%d is transient", s)
		}
	}
	if !errors.Is(fmt.Errorf("%w: %w", ErrKeyFetch, ae), ErrKeyFetch) {
		t.Fatal("wrapping")
	}
}
