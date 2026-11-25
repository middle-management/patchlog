package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
)

// A partial reader's ls, ns log and watch read its view (§7.9), in a
// namespace that redirects it and in a public one, and say on stderr that
// the answer is filtered; an unrestricted reader's say nothing. verify
// refuses a filtered log, and verifies a public one unfiltered.
func TestV090CLIPartialReader(t *testing.T) {
	t.Parallel()
	for _, read := range []string{"grant", "public"} {
		t.Run(read, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			s := clienttest.New(t, clienttest.Options{Auth: true, EdgeGrants: true})
			k := clienttest.NewKey("k")
			if _, err := s.Client(t, client.WithBearer(s.OperatorGrant(t, "n"))).CreateNamespace(ctx, "n",
				map[string]any{"read": read, "keys": []any{k.Entry("*")}}); err != nil {
				t.Fatal(err)
			}
			admin := k.Grant(t, s.Now(), "user:a", []string{"n"}, []string{"read", "create"})
			ac := s.Client(t, client.WithBearer(admin))
			for name, team := range map[string]string{"a1": "a", "b1": "b"} {
				if _, err := ac.Create(ctx, "n", name, client.GenesisPatches(map[string]any{"team": team})); err != nil {
					t.Fatal(err)
				}
			}
			reader := k.Grant(t, s.Now(), "user:r", []string{"n"}, []string{"read"},
				map[string]any{"rules": []any{map[string]any{"op": "test", "path": "/doc/team", "value": "a"}}})

			for _, who := range []struct {
				bearer   string
				filtered bool
			}{{reader, true}, {admin, false}} {
				noted := func(cmd, errw string) {
					t.Helper()
					if got := strings.Contains(errw, "is filtered for this grant") && strings.Contains(errw, "not chain-verifiable"); got != who.filtered || strings.Count(errw, "\n") > 1 {
						t.Fatalf("%s (filtered %v) said on stderr: %q", cmd, who.filtered, errw)
					}
				}
				shows := func(cmd, out string) {
					t.Helper()
					if !strings.Contains(out, "a1") || strings.Contains(out, "b1") == who.filtered {
						t.Fatalf("%s (filtered %v) printed:\n%s", cmd, who.filtered, out)
					}
				}
				out, errw, err := clientRun(t, ctx, s.URL, "ls", "n", "--bearer", who.bearer)
				if err != nil {
					t.Fatalf("ls: %v", err)
				}
				shows("ls", out)
				noted("ls", errw)
				out, errw, err = clientRun(t, ctx, s.URL, "ns", "log", "n", "--bearer", who.bearer)
				if err != nil {
					t.Fatalf("ns log: %v", err)
				}
				shows("ns log", out)
				noted("ns log", errw)

				wctx, cancel := context.WithTimeout(ctx, 2*time.Second)
				watched, werr := &syncWriter{w: &bytes.Buffer{}}, &syncWriter{w: &bytes.Buffer{}}
				go func() {
					for wctx.Err() == nil && !strings.Contains(watched.String(), "a1") {
						time.Sleep(20 * time.Millisecond)
					}
					time.Sleep(100 * time.Millisecond)
					cancel()
				}()
				cmd := command(t, "watch", "n", "--api", s.URL, "--bearer", who.bearer).(*watchCmd)
				if err := cmd.exec(wctx, watched, werr); err != nil {
					t.Fatalf("watch: %v", err)
				}
				shows("watch", watched.String())
				noted("watch", werr.String())

				out, _, err = clientRun(t, ctx, s.URL, "verify", "n", "--bearer", who.bearer)
				switch {
				case who.filtered && read != "public":
					if err == nil || !strings.Contains(err.Error(), "isn't chain-verifiable") {
						t.Fatalf("verify of a filtered log: %v\n%s", err, out)
					}
				case err != nil || !strings.Contains(out, "entries verified"):
					t.Fatalf("verify: %v\n%s", err, out)
				}
			}
		})
	}
}
