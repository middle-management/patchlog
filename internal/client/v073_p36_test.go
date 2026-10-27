package client_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/seal"
)

// p36Server serves e2e branch z of base s (z's document as zdoc), whose
// pre-raise revision id of d it serves as s serves it, sealed under s's
// epoch 1 (kid), and whose /keys gives s#1's key: a branch of a raised
// base serves what it reads through from before the raise as the base
// does, and its /keys gives the base's keys for it (Addendum E Levels).
// keysAt counts /keys requests by namespace.
func p36Server(t *testing.T, zdoc map[string]any, kid string, ke []byte, id string, keysAt map[string]*atomic.Int32) *httptest.Server {
	t.Helper()
	kns, _, _ := seal.ParseKid(kid)
	kr, err := seal.ResourceKey(ke, kns, "d")
	if err != nil {
		t.Fatal(err)
	}
	jwe, err := seal.Seal(kr, kid, seal.ResourcePL(kns, "d", id, seal.KindDoc), []byte(`{"n":1}`))
	if err != nil {
		t.Fatal(err)
	}
	docs := map[string]map[string]any{"z": zdoc, "s": {"encryption": map[string]any{"level": "e2e", "epoch": 2.0}}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		switch {
		case r.Method == "GET" && (p == "/ns/z" || p == "/ns/s"):
			w.Header().Set("ETag", `"`+ids.Revision(nil, []byte(p)).String()+`"`)
			w.WriteHeader(302)
		case r.Method == "GET" && strings.HasPrefix(p, "/ns/") && strings.Contains(p, "/rev/"):
			ns := strings.Split(p, "/")[2]
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(docs[ns])
		case r.Method == "GET" && p == "/r/z/d/rev/"+id:
			w.Header().Set("Content-Type", seal.ContentType)
			w.Write([]byte(jwe))
		case r.Method == "POST" && strings.HasSuffix(p, "/keys"):
			ns := strings.Split(p, "/")[2]
			if c := keysAt[ns]; c != nil {
				c.Add(1)
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{"epoch": 2, "level": "e2e", "pad": false,
				"keys": []any{map[string]any{"kid": "s#1", "key": base64.RawURLEncoding.EncodeToString(ke)}}})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// v0.73 Addendum E Levels, Invariant and Branches of a raised base, §E.2.2
// (ENC-27, E2 half): a reader of an e2e branch accepts a base's ns in the
// pl and kid of a resource document the branch reads through, which it
// serves as the base serves it, sealed under the base's epoch from before
// its raise, and fetches the key from the branch's /keys, which gives the
// base's keys for it. A namespace that isn't a base of the branch, or a
// branch that isn't e2e (a sealed branch reseals what it reads through
// under its own keys, §E.2.5), is still a mismatch.
func TestV073P36ReadThroughBaseNS(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ke := seal.NewKey()
	id := ids.Revision(nil, []byte("d")).String()
	at := ids.Revision(nil, []byte("at")).String()
	e2eBranch := map[string]any{"encryption": map[string]any{"level": "e2e", "epoch": 2.0}, "base": map[string]any{"ns": "s", "at": at}}
	keysAt := map[string]*atomic.Int32{"z": {}, "s": {}}
	srv := p36Server(t, e2eBranch, "s#1", ke, id, keysAt)
	c, err := client.New(srv.URL, client.WithKeys(client.NewKeys(nil)))
	if err != nil {
		t.Fatal(err)
	}
	d, err := c.Doc(ctx, "z", "d", id)
	if err != nil {
		t.Fatalf("a base's pre-raise document read through an e2e branch: %v", err)
	}
	if m, _ := d.Value.(map[string]any); m["n"] != 1.0 {
		t.Fatalf("document %v", d.Value)
	}
	if keysAt["z"].Load() != 1 || keysAt["s"].Load() != 0 {
		t.Fatalf("/keys asked of z %d times and of s %d times, want the branch's only", keysAt["z"].Load(), keysAt["s"].Load())
	}

	// Not a base of the branch.
	srv2 := p36Server(t, e2eBranch, "x#1", ke, id, nil)
	c2, _ := client.New(srv2.URL, client.WithKeys(client.NewKeys(nil)))
	if _, err := c2.Doc(ctx, "z", "d", id); !errors.Is(err, seal.ErrMismatch) {
		t.Fatalf("a document sealed under a namespace that isn't a base: %v, want a mismatch", err)
	}
	// A branch that isn't e2e.
	sealedBranch := map[string]any{"encryption": map[string]any{"level": "sealed"}, "base": map[string]any{"ns": "s", "at": at}}
	srv3 := p36Server(t, sealedBranch, "s#1", ke, id, nil)
	c3, _ := client.New(srv3.URL, client.WithKeys(client.NewKeys(nil)))
	if _, err := c3.Doc(ctx, "z", "d", id); !errors.Is(err, seal.ErrMismatch) {
		t.Fatalf("a base's sealing served by a branch that isn't e2e: %v, want a mismatch", err)
	}
}

// p36KeysServer is p36Server for an e2e branch z of s, with knobs: the
// first failNS GET /ns/z answer 503; branchKeys false makes z's /keys give
// no key (s's /keys still gives s#1).
func p36KeysServer(t *testing.T, ke []byte, id string, failNS int32, branchKeys bool) *httptest.Server {
	t.Helper()
	at := ids.Revision(nil, []byte("at")).String()
	kr, err := seal.ResourceKey(ke, "s", "d")
	if err != nil {
		t.Fatal(err)
	}
	jwe, err := seal.Seal(kr, "s#1", seal.ResourcePL("s", "d", id, seal.KindDoc), []byte(`{"n":1}`))
	if err != nil {
		t.Fatal(err)
	}
	docs := map[string]map[string]any{
		"z": {"encryption": map[string]any{"level": "e2e", "epoch": 2.0}, "base": map[string]any{"ns": "s", "at": at}},
		"s": {"encryption": map[string]any{"level": "e2e", "epoch": 2.0}},
	}
	var fails atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		switch {
		case r.Method == "GET" && p == "/ns/z" && fails.Add(1) <= failNS:
			w.WriteHeader(503)
		case r.Method == "GET" && (p == "/ns/z" || p == "/ns/s"):
			w.Header().Set("ETag", `"`+ids.Revision(nil, []byte(p)).String()+`"`)
			w.WriteHeader(302)
		case r.Method == "GET" && strings.HasPrefix(p, "/ns/") && strings.Contains(p, "/rev/"):
			ns := strings.Split(p, "/")[2]
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(docs[ns])
		case r.Method == "GET" && p == "/r/z/d/rev/"+id:
			w.Header().Set("Content-Type", seal.ContentType)
			w.Write([]byte(jwe))
		case r.Method == "POST" && strings.HasSuffix(p, "/keys"):
			ns := strings.Split(p, "/")[2]
			keys := []any{}
			if ns == "s" || branchKeys {
				keys = append(keys, map[string]any{"kid": "s#1", "key": base64.RawURLEncoding.EncodeToString(ke)})
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{"epoch": 2, "level": "e2e", "pad": false, "keys": keys})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// v0.73 Addendum E Levels (ENC-27): a reader caches the bases an e2e
// branch reads through only once it has read them. A transient failure
// while reading the branch's document is reported as itself, not as a
// kid/pl mismatch, and the next read, after the outage, opens the base's
// pre-raise content.
func TestV073P36ReadThroughTransientError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ke := seal.NewKey()
	id := ids.Revision(nil, []byte("d")).String()
	srv := p36KeysServer(t, ke, id, 1, true)
	c, err := client.New(srv.URL, client.WithKeys(client.NewKeys(nil)))
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Doc(ctx, "z", "d", id) // GET /ns/z answers 503 this once
	var ae *client.APIError
	if !errors.As(err, &ae) || ae.Status != 503 || errors.Is(err, seal.ErrMismatch) {
		t.Fatalf("first read, during the outage: %v, want the 503", err)
	}
	if _, err := c.Doc(ctx, "z", "d", id); err != nil {
		t.Fatalf("second read, after the outage: %v, want the document", err)
	}
}

// v0.73 §F.8.1 (ENC-27): a reader asks the namespace it reads for keys
// first and, only if that fails, the namespace the kid names: a branch's
// /keys that gives no key for a base's pre-raise content (no nbf window,
// say) leaves the reader asking the base.
func TestV073P36ReadThroughKeyFallback(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ke := seal.NewKey()
	id := ids.Revision(nil, []byte("d")).String()
	srv := p36KeysServer(t, ke, id, 0, false)
	c, err := client.New(srv.URL, client.WithKeys(client.NewKeys(nil)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Doc(ctx, "z", "d", id); err != nil {
		t.Errorf("z's /keys gives no s#1, s's does: %v, want the document via the kid's namespace", err)
	}
}
