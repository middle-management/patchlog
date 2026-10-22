package core

import (
	"errors"
	"fmt"
	"net/url"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
)

// Spec v0.73, package P14: remote branch creation and registration (§G.3,
// §G.5.2).

// A failed fetch from the base at creation: what A answers is a base B
// can't read (422), but for its 410s; only no answer, or a 5xx, is 502
// upstream (§G.3, §12.1).
func TestV073FetchErr(t *testing.T) {
	t.Parallel()
	api := func(status int, code string) error {
		return &client.APIError{Status: status, Code: code, Method: "GET", Path: "/ns/n"}
	}
	for _, c := range []struct {
		err    error
		status int
		code   string
	}{
		{api(401, "unauthenticated"), 422, "invalid"},
		{api(403, "forbidden"), 422, "invalid"},
		{api(404, "not_found"), 422, "invalid"},
		{api(429, "rate"), 422, "invalid"},
		{api(410, "pruned"), 410, "pruned"},
		{api(410, "gone"), 410, "gone"},
		{api(500, ""), 502, "upstream"},
		{api(503, "behind"), 502, "upstream"},
		{&url.Error{Op: "Get", URL: "https://a.example/", Err: errors.New("connection refused")}, 502, "upstream"},
		{fmt.Errorf("opening: %w", client.ErrNoKeys), 422, "invalid"},
	} {
		got := fetchErr("/ns/n", c.err)
		if got.Status != c.status || got.Code() != c.code {
			t.Errorf("%v: %d %s, want %d %s", c.err, got.Status, got.Code(), c.status, c.code)
		}
	}
	if e := unverified("x %d", 1); e.Status != 502 || e.Code() != "upstream" {
		t.Errorf("unverified: %v", e)
	}
}

// Protection ranks of a schema mirror's source and target (§2.1): sealed is
// private as a source whatever its read, but a sealed public target is
// public; an unknown level is the strictest.
func TestV073MirrorRanks(t *testing.T) {
	t.Parallel()
	enc := func(read, level string) map[string]any {
		d := map[string]any{"read": read}
		if level != "" {
			d["encryption"] = map[string]any{"level": level}
		}
		return d
	}
	for _, c := range []struct {
		doc  map[string]any
		want int
	}{
		{enc("public", ""), rankPublic},
		{enc("public", "at-rest"), rankPublic},
		{enc("grant", ""), rankPrivate},
		{enc("public", "sealed"), rankPrivate},
		{enc("grant", "sealed"), rankPrivate},
		{enc("grant", "e2e"), rankE2E},
		{enc("public", "quantum"), rankE2E},
		{map[string]any{}, rankPrivate},
	} {
		if got := sourceRank(c.doc); got != c.want {
			t.Errorf("source %v: %d, want %d", c.doc, got, c.want)
		}
	}
	for _, c := range []struct {
		cfg  *Config
		want int
	}{
		{&Config{Read: "public"}, rankPublic},
		{&Config{Read: "public", level: levelSealed}, rankPublic},
		{&Config{Read: "grant", level: levelSealed}, rankPrivate},
		{&Config{Read: "grant"}, rankPrivate},
		{&Config{Read: "grant", level: levelE2E}, rankE2E},
	} {
		if got := targetRank(c.cfg); got != c.want {
			t.Errorf("target %+v: %d, want %d", c.cfg, got, c.want)
		}
	}
}
