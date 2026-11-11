package grantcheck_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/grant"
	"github.com/middle-management/patchlog/internal/grantcheck"
)

// SVC-15t (§C.4, §C.5.2 All or nothing): an at a readable chain rejects,
// not in it or not its head within maxLag, is 403 with one text that
// names no namespace: the chain a key names may be one the caller can't
// see.
func TestV082RequireAtNamesNothing(t *testing.T) {
	ctx := context.Background()
	f := newChainFixture(t)
	ch := f.checker(0)
	head := must(f.adminC.NSHead(ctx, "cat-season")).ID
	if _, err := ch.Verify(ctx, "sec", f.grantAt(head)); err != nil {
		t.Fatalf("at at the head: %v", err)
	}
	refused := func(what, tok string) {
		t.Helper()
		_, err := ch.Verify(ctx, "sec", tok)
		var ae *grant.AuthError
		if !errors.As(err, &ae) || ae.Status != 403 {
			t.Fatalf("%s: %v, want 403", what, err)
		}
		if !strings.Contains(ae.Msg, "at rejected by requireAt") {
			t.Errorf("%s: message %q, want the one text of a rejected at", what, ae.Msg)
		}
		if strings.Contains(err.Error(), "cat-season") || strings.Contains(ae.Msg, "cat-season") {
			t.Errorf("%s: the refusal names the chain's namespace: %q", what, ae.Msg)
		}
	}
	// Not in the chain: a well-formed id the chain never held.
	refused("an at in no chain", f.grantAt("1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"))
	// In the chain, but no longer its head within maxLag of issuance.
	h := must(f.adminC.NSHead(ctx, "cat-season"))
	must(f.adminC.PatchConfig(ctx, "cat-season", h.Config, []any{map[string]any{"op": "add", "path": "/x-note", "value": "moved"}}))
	moved := f.s.Now()
	late := f.at.Grant(t, moved, "user:li", []string{"sec"}, []string{"read"}, map[string]any{
		"at": map[string]any{"ns": "cat-season", "id": head}, "nbf": moved.Add(61 * time.Second).Format(time.RFC3339)})
	f.s.Clock.Advance(2 * time.Minute)
	refused("an at beyond maxLag", late)
}

// ACC-5 (§B.11.4 The caller's grant): the two classes the catalog's grant
// endpoints refuse. RefusedByNowRule is a block or key-scope rule on /now
// (or the whole envelope) alone; ReadsNothing is a grant that allows read
// nowhere it verifies in: no read at all, or roles none of which counts
// for read. RefusedByNow, which listings judge by, stays their union less
// the grant without read.
func TestV082NowRuleAndReadsNothing(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	cfgID := must(f.adminC.NSHead(ctx, "sec")).Config
	past := map[string]any{"not": map[string]any{"op": "test", "path": "/now", "value": "2000-01-01T00:00:00.000Z"}}
	whole := map[string]any{"op": "test", "path": "", "exists": true}
	must(f.adminC.PatchConfig(ctx, "sec", cfgID, []any{
		map[string]any{"op": "add", "path": "/roles/clock", "value": map[string]any{"can": []any{"read", "append"}, "rules": []any{past}}},
		map[string]any{"op": "add", "path": "/roles/writer", "value": map[string]any{"can": []any{"append"}}},
	}))
	for _, c := range []struct {
		name                   string
		can                    []string
		extra                  map[string]any
		rule, nothing, refused bool
	}{
		{"plain reader", []string{"read"}, nil, false, false, false},
		{"block rule on /now", []string{"read"}, map[string]any{"rules": []any{past}}, true, false, true},
		{"block rule on the whole envelope", []string{"read", "append"}, map[string]any{"rules": []any{whole}}, true, false, true},
		{"block rule on /now, no read", []string{"append"}, map[string]any{"rules": []any{past}}, true, true, true},
		{"no read at all", []string{"append", "create"}, nil, false, true, false},
		{"every read role on /now", nil, map[string]any{"roles": []any{"clock"}}, false, true, true},
		{"a /now role beside a reader", nil, map[string]any{"roles": []any{"clock", "reader"}}, false, false, false},
		{"roles, none listing read", nil, map[string]any{"roles": []any{"writer"}}, false, true, false},
		{"a /now role beside a writer", nil, map[string]any{"roles": []any{"clock", "writer"}}, false, true, true},
	} {
		v, err := f.ch.Verify(ctx, "sec", f.grant(f.issuer, "user:bob", []string{"sec"}, c.can, c.extra))
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if got := grantcheck.RefusedByNowRule(v); got != c.rule {
			t.Errorf("%s: RefusedByNowRule %v, want %v", c.name, got, c.rule)
		}
		if got := grantcheck.ReadsNothing(v); got != c.nothing {
			t.Errorf("%s: ReadsNothing %v, want %v", c.name, got, c.nothing)
		}
		if got := grantcheck.RefusedByNow(v); got != c.refused {
			t.Errorf("%s: RefusedByNow %v, want %v (unchanged)", c.name, got, c.refused)
		}
	}
}
