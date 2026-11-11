package main

import (
	"context"
	"errors"
	"flag"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
)

// E2E-7 (§7.1 End-to-end namespaces, Levels; scenario 70): the tools'
// -expect-level ns=level configures the level a namespace is known to
// have (client.WithExpectedLevel), so a server that claims a lower one at
// first contact is refused: its plaintext 200 isn't read. A value that
// isn't ns=level with a level this version knows is an error, never
// ignored.
func TestV082ExpectLevelFlag(t *testing.T) {
	t.Parallel()
	id := "1nyv2d2ibcop4nnp4k5niguadz7lvyjad"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/ns/e":
			w.Header().Set("ETag", `"`+id+`"`)
			w.WriteHeader(302)
		case "/ns/e/rev/" + id:
			w.Write([]byte(`{"read":"public"}`)) // no encryption
		case "/r/e/d/rev/" + id:
			w.Write([]byte(`{"title":"forged"}`))
		default:
			w.WriteHeader(404)
			w.Write([]byte(`{"code":"not_found"}`))
		}
	}))
	t.Cleanup(srv.Close)
	tool := func(args ...string) *client.Client {
		t.Helper()
		fs := flag.NewFlagSet("t", flag.ContinueOnError)
		tf := addToolFlags(fs)
		if err := fs.Parse(append([]string{"-api", srv.URL}, args...)); err != nil {
			t.Fatal(err)
		}
		return tf.client()
	}
	ctx := context.Background()
	c := tool("-expect-level", "e=e2e", "-expect-level", "other=sealed")
	if c.HeldLevel("e") != "e2e" || c.HeldLevel("other") != "sealed" {
		t.Fatalf("held %q and %q", c.HeldLevel("e"), c.HeldLevel("other"))
	}
	if d, err := c.E2E(nil).DocE2E(ctx, "e", "d", id); !errors.Is(err, client.ErrLevelLowered) {
		t.Fatalf("a plaintext 200 under -expect-level e=e2e: %+v %v", d, err)
	}
	if lv, err := c.EncryptionLevel(ctx, "e"); !errors.Is(err, client.ErrLevelLowered) {
		t.Fatalf("the lowered document: %q %v", lv, err)
	}
	// Without the flag the first contact is believed.
	if d, err := tool().E2E(nil).DocE2E(ctx, "e", "d", id); err != nil || !d.Plain {
		t.Fatalf("without -expect-level: %+v %v", d, err)
	}
	for _, bad := range []string{"e", "e=", "=e2e", "e=E2E", "e=none", "e=e3", "Bad Name=e2e", "e=e2e=x"} {
		if opts, err := expectLevels([]string{"e=sealed", bad}); err == nil {
			t.Errorf("-expect-level %q: accepted, %d options", bad, len(opts))
		}
	}
	if opts, err := expectLevels([]string{"e=at-rest", "f=sealed", "g=e2e"}); err != nil || len(opts) != 3 {
		t.Fatalf("valid values: %d %v", len(opts), err)
	}
}
