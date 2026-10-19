package derived_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"syscall"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/derived"
	"github.com/middle-management/patchlog/internal/keystore"
	"github.com/middle-management/patchlog/internal/seal"
)

// A sealed namespace's epoch keys are destroyed with its content, and
// POST /keys is 410 purged once it is purged (§8.5): Check still lets the
// service consume it, so its follower learns of the purge, rather than
// skipping it for want of a key it will never get.
func TestCheckSealedPurged(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ks, err := keystore.New(keystore.Generate())
	if err != nil {
		t.Fatal(err)
	}
	s := clienttest.New(t, clienttest.Options{KeyStore: ks})
	c := s.Client(t, client.WithAuthor("admin"), client.WithKeys(client.NewKeys(nil)))
	if _, err := c.CreateNamespace(ctx, "sec", map[string]any{"read": "public", "encryption": map[string]any{"level": "sealed"}}); err != nil {
		t.Fatal(err)
	}
	ps := append(client.GenesisPatches(map[string]any{}), map[string]any{"op": "add", "path": "/$nonce", "value": seal.NewNonce()})
	if _, err := c.Create(ctx, "sec", "a", ps); err != nil {
		t.Fatal(err)
	}
	k := derived.NewKeys(c, nil)
	// The namespace document read while it lives; its key not yet fetched.
	if in, err := k.Info(ctx, "sec"); err != nil || !in.Protected() {
		t.Fatalf("info %+v %v", in, err)
	}
	h, err := c.NSHead(ctx, "sec")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.PatchConfig(ctx, "sec", h.Config, []any{map[string]any{"op": "add", "path": "/frozen", "value": true}}); err != nil {
		t.Fatal(err)
	}
	if h, err = c.NSHead(ctx, "sec"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.PurgeNamespace(ctx, "sec", h.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := k.EpochKey(ctx, "sec", 1); !client.IsPurged(err) {
		t.Fatalf("epoch key after the purge: %v", err)
	}
	if reason, permanent, retry := k.Check(ctx, "sec", false); reason != "" || permanent || retry || k.Skipped("sec") != "" {
		t.Fatalf("check: %q %v %v", reason, permanent, retry)
	}
}

// Retryable tells a failure to fetch keys that asking again may mend (the
// core unreachable, a 5xx, a 429) from the service's configuration's (no
// key for its grant, none to unwrap one with, a 4xx refusal), which a
// tree service stops waiting for and the other it keeps waiting for.
func TestRetryable(t *testing.T) {
	for _, c := range []struct {
		err  error
		want bool
	}{
		{&url.Error{Op: "Post", URL: "http://core/ns/v/keys", Err: errors.New("connection reset by peer")}, true},
		{fmt.Errorf("fetching: %w", syscall.ECONNRESET), true},
		{io.ErrUnexpectedEOF, true},
		{&client.APIError{Status: http.StatusServiceUnavailable}, true},
		{&client.APIError{Status: http.StatusTooManyRequests}, true},
		{&client.APIError{Status: http.StatusForbidden}, false},
		{&client.APIError{Status: http.StatusNotFound}, false},
		{fmt.Errorf("%w: the grant gets no epoch key v#1", client.ErrNoKeys), false},
		{errors.New("derived: v#1 is wrapped to the grant's enc and no recipient key is configured"), false},
		{nil, false},
	} {
		if got := derived.Retryable(c.err); got != c.want {
			t.Errorf("Retryable(%v) = %v", c.err, got)
		}
	}
}
