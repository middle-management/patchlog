package grantcheck_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/grantcheck"
)

// GR-20 (§C.8, §C.6, F-C3 default): a grant over grantSize or
// rulesPerGrant is a *LimitError naming the limit, with what was measured
// and the maximum, which a service answers 413 limit as the origin does;
// before its ns check, and unwrapping to the 401 a caller answering only
// grant.AuthError gives it.
func TestV073DecodeLimitError(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	for limit, tok := range map[string]string{
		"grantSize":     f.grant(f.issuer, "user:bob", []string{"other"}, []string{"read"}, map[string]any{"attrs": map[string]any{"x": strings.Repeat("a", 9000)}}),
		"rulesPerGrant": f.grant(f.issuer, "user:bob", []string{"other"}, []string{"read"}, map[string]any{"rules": v073Rules(33)}),
	} {
		_, err := f.ch.Verify(ctx, "sec", tok)
		var le *grantcheck.LimitError
		if !errors.As(err, &le) || le.Limit != limit || le.Measured <= le.Max || le.Max == 0 {
			t.Errorf("%s: %v", limit, err)
		}
		if authStatus(err) != 401 {
			t.Errorf("%s unwraps to %v", limit, err)
		}
	}
	if _, err := f.ch.Verify(ctx, "sec", f.grant(f.issuer, "user:bob", []string{"other"}, []string{"read"}, map[string]any{"rules": v073Rules(32)})); errors.As(err, new(*grantcheck.LimitError)) || authStatus(err) != 403 {
		t.Errorf("32 forms naming another namespace: %v", err)
	}
}
