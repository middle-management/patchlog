package core

import (
	"errors"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/jsonv"
)

func v073Doc(s string) map[string]any { return jsonv.MustParse([]byte(s)).(map[string]any) }

// v0.73 §6.6 Allowances: the first matching entry whose until hasn't
// passed applies, so an ended entry doesn't hide a later one. While
// authentication is disabled (kid "") an entry matches sub alone.
func TestV073AllowanceAt(t *testing.T) {
	t.Parallel()
	c, err := parseConfig(v073Doc(`{"allowances": [
		{"sub": "svc:i", "kid": "k1", "itemsPerBatch": 10, "until": "2026-01-01T00:00:00Z"},
		{"sub": "svc:i", "kid": "k2", "itemsPerBatch": 20}]}`), DefaultLimits(), DefaultMaximums())
	if err != nil {
		t.Fatal(err)
	}
	before, after := time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC), time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	for _, x := range []struct {
		now  time.Time
		kid  string
		want int // itemsPerBatch of the entry, 0 for none
	}{
		{before, "", 10},
		{after, "", 20}, // the first has ended: the second applies
		{before, "k1", 10},
		{after, "k1", 0},
		{after, "k2", 20},
		{after, "k3", 0},
	} {
		got := 0
		if a := c.allowanceAt(x.now, "svc:i", x.kid); a != nil {
			got = a.ItemsPerBatch
		}
		if got != x.want {
			t.Errorf("allowanceAt(%v, %q) = %d, want %d", x.now, x.kid, got, x.want)
		}
	}
	if a := c.allowanceAt(before, "svc:other", ""); a != nil {
		t.Errorf("another sub matched %+v", a)
	}
}

// v0.73 §6.6 Deployment defaults and maximums, Allowances: a value stored
// before a maximum was lowered is held to it, never refused, so a stored
// document always parses (tx.config panics otherwise); a write that sets
// a value above the maximum is 422 limit, and one that keeps a stored
// value unchanged is held to it.
func TestV073StoredConfigHeldToMaximums(t *testing.T) {
	t.Parallel()
	max := DefaultMaximums()
	max.DocumentSize, max.ItemsPerBatch, max.RulesPerNS = 1<<20, 10, 2
	max.RatePerNamespace, max.BlobRate, max.BlobGrace, max.RetryWindow = Rate{100, 200}, Rate{1000, 2000}, time.Hour, 10*time.Minute
	stored := v073Doc(`{
		"limits": {"documentSize": 3145728, "itemsPerBatch": 1000, "ratePerPrincipal": {"rate": 500, "burst": 1000},
			"blobGrace": "PT2H", "retryWindow": "PT20M", "rulesPerNamespace": 3},
		"allowances": [{"sub": "svc:i", "kid": "k", "itemsPerBatch": 1000, "batchSize": 1073741824,
			"bucket": {"rate": 1000, "burst": 5000}, "blobRate": {"rate": 1e9, "burst": 1e9}, "blobPending": 1099511627776}],
		"rules": [{"all": [{"op": "test", "path": "/action", "exists": true}, {"op": "test", "path": "/action", "exists": true}]}]}`)
	if _, err := parseConfig(stored, DefaultLimits(), max); err == nil {
		t.Fatal("a write of values above the maximums parsed")
	}
	for name, md := range map[string]configMode{"stored": {stored: true}, "kept by a write": {prev: stored}} {
		c, err := parseConfigIn(stored, DefaultLimits(), max, md)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		l, a := c.Limits, c.Allowances[0]
		if l.DocumentSize != 1<<20 || l.ItemsPerBatch != 10 || l.RulesPerNS != 2 || l.RatePerPrincipal != max.RatePerPrincipal ||
			l.RetryWindow != 10*time.Minute || l.BlobGrace != time.Hour {
			t.Errorf("%s: limits %+v", name, l)
		}
		if a.ItemsPerBatch != 10 || a.BatchSize != max.BatchSize || a.Rate != (Rate{100, 200}) || a.BlobRate != (Rate{1000, 2000}) || a.BlobPending != max.BlobPending {
			t.Errorf("%s: allowance %+v", name, a)
		}
		if c.ruleForms != 3 {
			t.Errorf("%s: %d rule forms", name, c.ruleForms)
		}
	}
	// A write that changes a value sets it: above the maximum, 422 limit.
	for _, x := range []struct{ doc, key string }{
		{`{"limits": {"documentSize": 2097152}}`, "documentSize"},
		{`{"limits": {"retryWindow": "PT30M"}}`, "retryWindow"},
		{`{"allowances": [{"sub": "svc:i", "kid": "k", "itemsPerBatch": 11}]}`, "itemsPerBatch"},
		// An allowance's bucket is bounded by ratePerNamespace's maximum
		// (default, F-L3).
		{`{"allowances": [{"sub": "svc:i", "kid": "k", "bucket": {"rate": 101, "burst": 10}}]}`, "ratePerNamespace"},
		{`{"allowances": [{"sub": "svc:i", "kid": "k", "bucket": {"rate": 10, "burst": 201}}]}`, "ratePerNamespace"},
	} {
		_, err := parseConfigIn(v073Doc(x.doc), DefaultLimits(), max, configMode{prev: stored})
		var le *limitError
		if !errors.As(err, &le) || le.key != x.key {
			t.Errorf("%s: %v, want a %s limit", x.doc, err, x.key)
		}
	}
}

// v0.73 §12.2: grantSize and rulesPerGrant are deployment only. A write
// that sets or changes either is 422 invalid; a stored document, or a
// write keeping one unchanged, still parses, and its value is ignored.
func TestV073GrantLimitsNotNamespaceFields(t *testing.T) {
	t.Parallel()
	stored := v073Doc(`{"limits": {"grantSize": 200, "rulesPerGrant": 1}}`)
	for name, md := range map[string]configMode{"stored": {stored: true}, "kept by a write": {prev: stored}} {
		c, err := parseConfigIn(stored, DefaultLimits(), DefaultMaximums(), md)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if c.Limits.GrantSize != DefaultLimits().GrantSize || c.Limits.RulesPerGrant != DefaultLimits().RulesPerGrant {
			t.Errorf("%s: the stored values apply: %+v", name, c.Limits)
		}
	}
	for _, doc := range []string{`{"limits": {"grantSize": 300}}`, `{"limits": {"rulesPerGrant": 2}}`, `{"limits": {"grantSize": 300, "rulesPerGrant": 1}}`} {
		for _, prev := range []map[string]any{nil, stored} {
			_, err := parseConfigIn(v073Doc(doc), DefaultLimits(), DefaultMaximums(), configMode{prev: prev})
			var le *limitError
			if err == nil || errors.As(err, &le) {
				t.Errorf("%s over %v: %v, want invalid", doc, prev, err)
				continue
			}
			if e := configErr(err); e.Code() != "invalid" || messagePointer(err.Error()) != "/limits/grantSize" && messagePointer(err.Error()) != "/limits/rulesPerGrant" {
				t.Errorf("%s over %v: %v", doc, prev, e)
			}
		}
	}
}

// v0.73 §C.4: a key's attrs schema is compiled as a rule's schema when the
// document is written (422 invalid at /keys/{i}/attrs); an entry stored
// before, kept unchanged, still passes.
func TestV073KeyAttrsKeptWhenStored(t *testing.T) {
	t.Parallel()
	bad := map[string]any{"kid": "k", "alg": "ed25519", "pub": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo", "can": []any{"read"},
		"attrs": map[string]any{"pattern": "(?=x)"}}
	doc := map[string]any{"keys": []any{bad}}
	err := checkMembers(jsonv.FromGo(doc).(map[string]any), nil)
	var me *memberError
	if !errors.As(err, &me) || me.pointer != "/keys/0/attrs" {
		t.Fatalf("a new uncompilable attrs schema: %v", err)
	}
	if err := checkMembers(jsonv.FromGo(doc).(map[string]any), jsonv.FromGo(map[string]any{"keys": []any{bad}, "x-old": true}).(map[string]any)); err != nil {
		t.Fatalf("a stored entry kept: %v", err)
	}
	moved := jsonv.FromGo(map[string]any{"keys": []any{map[string]any{"kid": "j", "alg": "ed25519", "pub": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo", "can": []any{"read"}}, bad}}).(map[string]any)
	if err := checkMembers(moved, jsonv.FromGo(doc).(map[string]any)); err != nil {
		t.Fatalf("a stored entry kept at another index: %v", err)
	}
}
