package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/middle-management/patchlog/internal/client/clienttest"
)

// tamper rewrites the body of every resource log a server answers, once
// armed: what a corrupted mirror or cache could do.
type tamper struct {
	armed atomic.Bool
	from  string
	to    string
}

func (tm *tamper) wrap(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !tm.armed.Load() || !strings.HasPrefix(r.URL.Path, "/r/") || !strings.HasSuffix(r.URL.Path, "/log") {
			h.ServeHTTP(w, r)
			return
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		for k, v := range rec.Header() {
			if k != "Content-Length" {
				w.Header()[k] = v
			}
		}
		w.WriteHeader(rec.Code)
		w.Write(bytes.ReplaceAll(rec.Body.Bytes(), []byte(tm.from), []byte(tm.to)))
	})
}

func TestVerifyCommand(t *testing.T) {
	t.Parallel()
	tm := &tamper{from: "evil-target", to: "evil-changed"}
	s := clienttest.New(t, clienttest.Options{Wrap: tm.wrap})
	ctx := context.Background()
	run := func(args ...string) (string, error) {
		t.Helper()
		out, _, err := clientRun(t, ctx, s.URL, append([]string{"verify"}, args...)...)
		return out, err
	}
	must2 := func(args ...string) string {
		t.Helper()
		out, errw, err := clientRun(t, ctx, s.URL, args...)
		if err != nil {
			t.Fatalf("%q: %v\n%s", args, err, errw)
		}
		return strings.TrimSpace(out)
	}
	must2("ns", "create", "docs", `{"read":"public"}`)
	must2("put", "docs/a", `{"v":"evil-target"}`)
	must2("put", "docs/b", `{"v":"one"}`)
	must2("patch", "docs/b", `[{"op":"replace","path":"/v","value":"two"}]`)
	must2("put", "docs/gone", `{"v":1}`)
	must2("rm", "docs/gone")

	out, err := run("docs")
	if err != nil {
		t.Fatalf("verify: %v\n%s", err, out)
	}
	for _, want := range []string{
		"namespace docs: 6 entries verified, genesis to ",
		"ok       docs/a: 1 entries back to genesis",
		"ok       docs/b: 2 entries back to genesis",
		"ok       docs/gone: 2 entries back to genesis",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("verify output lacks %q:\n%s", want, out)
		}
	}

	// --from: the chain after a trusted entry; the logs still go to genesis.
	entries, _, err := clientRun(t, ctx, s.URL, "ns", "log", "docs")
	if err != nil {
		t.Fatal(err)
	}
	third := strings.Fields(strings.Split(entries, "\n")[2])[0]
	out, err = run("docs", "--from", third, "--resource", "b")
	if err != nil || !strings.Contains(out, "3 entries verified, "+third+" to ") || strings.Contains(out, "docs/a") || !strings.Contains(out, "docs/b: 2 entries") {
		t.Errorf("--from --resource: %v\n%s", err, out)
	}
	if _, err = run("docs", "--from", "1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"); err == nil {
		t.Error("--from an entry not in the chain verified")
	}
	if _, err = run("docs", "--resource", "nosuch"); err == nil || !strings.Contains(err.Error(), "docs/nosuch doesn't exist") {
		t.Errorf("unknown resource: %v", err)
	}

	// --json.
	out, err = run("docs", "--json")
	var res struct {
		OK        bool `json:"ok"`
		Entries   int
		Resources []verifyResult
	}
	if jerr := json.Unmarshal([]byte(out), &res); err != nil || jerr != nil || !res.OK || res.Entries != 6 || len(res.Resources) != 3 || res.Resources[0].Status != "ok" {
		t.Errorf("--json: %v %v\n%s", err, jerr, out)
	}

	// A log that doesn't hash to its ids is a mismatch: reported, the
	// others still checked, and the command fails.
	tm.armed.Store(true)
	out, err = run("docs")
	if err == nil || !strings.Contains(err.Error(), "1 mismatch") {
		t.Fatalf("tampered: %v\n%s", err, out)
	}
	if !strings.Contains(out, "MISMATCH docs/a: ") || !strings.Contains(out, "ok       docs/b") {
		t.Errorf("tampered output:\n%s", out)
	}
	out, err = run("docs", "--json")
	if err == nil || !strings.Contains(out, `"ok": false`) || !strings.Contains(out, `"status": "mismatch"`) {
		t.Errorf("tampered --json: %v\n%s", err, out)
	}
}
