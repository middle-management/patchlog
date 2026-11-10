package core

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// Security review of v0.26.0: a covered purged namespace's filtered /heads
// (FilteredCurrent, FilteredHeads after purgedHeadsCheck) must answer a
// reader owed 401/403 as the same namespace unpurged does: no 410 that
// shows the purge (or the namespace) to someone the read check refuses.
func TestV0261FilteredPurgedHeadsDifferential(t *testing.T) {
	ctx := context.Background()
	type world struct {
		w      *v75World
		gs, at string
		bo     string // another partial reader's gs
		creds  map[string]Credentials
	}
	mk := func(purge bool) *world {
		w := newV75World(t, v75Opts{})
		w.seed()
		li := w.li()
		bo := w.catGrant("user:bo", []any{"chiefs"})
		x := &world{w: w}
		x.gs = v075GS(t, w, li)
		x.bo = v075GS(t, w, bo)
		red, st := v76fRedirect(t, w, "matches", x.gs, li)
		if red == nil {
			t.Fatalf("redirect: %d", st)
		}
		x.at = red.At
		x.creds = map[string]Credentials{
			"none":        {},
			"garbage":     {Bearer: "not-a-grant"},
			"other-ns":    w.cred(w.kPriv, map[string]any{"kid": "k", "sub": "user:x", "ns": []any{"cat-season"}, "can": []any{"read"}}),
			"no-read":     w.cred(w.kPriv, map[string]any{"kid": "k", "sub": "user:x", "ns": []any{"matches"}, "can": []any{"create"}}),
			"li-wrong-gs": li,
			"bo":          bo,
		}
		if purge {
			v077Purge(t, w, "matches")
		}
		return x
	}
	live, purged := mk(false), mk(true)
	type call func(x *world, c Credentials, gs, at string) error
	calls := map[string]call{
		"current": func(x *world, c Credentials, gs, _ string) error {
			return x.w.e.FilteredCurrent(ctx, "matches", gs, "/heads", c)
		},
		"at": func(x *world, c Credentials, gs, at string) error {
			_, _, err := x.w.e.FilteredHeads(ctx, "matches", gs, at, "", "", c)
			return err
		},
		"bogus-at": func(x *world, c Credentials, gs, _ string) error {
			_, _, err := x.w.e.FilteredHeads(ctx, "matches", gs, "zzzz", "", "", c)
			return err
		},
	}
	for cn, call := range calls {
		for who := range live.creds {
			for _, gsKind := range []string{"li", "bo"} {
				if who == "bo" && gsKind == "bo" || who == "li-wrong-gs" && gsKind == "li" {
					continue // the reader's own gs: admitted, 410 is owed
				}
				g := func(x *world) string {
					if gsKind == "bo" {
						return x.bo
					}
					return x.gs
				}
				el := call(live, live.creds[who], g(live), live.at)
				ep := call(purged, purged.creds[who], g(purged), purged.at)
				sl, sp := v75Status(el), v75Status(ep)
				t.Logf("%-8s %-11s gs=%s: live %d, purged %d", cn, who, gsKind, sl, sp)
				if sp == 410 {
					t.Errorf("%s %s with %s's gs: purged answers 410 (%v), the live namespace %d (%v)", cn, who, gsKind, ep, sl, el)
				}
			}
		}
	}
}

// C4, C-M, C2 (v0.26.1): rawGet follows no redirect, reads at most a small
// error body and at most limit of a 200. (What B takes of the answers,
// since v0.78 only a mirrored snapshot's: mirrorSnapshot.)
func TestV0261RawGet(t *testing.T) {
	ctx := context.Background()
	var hit atomic.Int64
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit.Add(1) }))
	t.Cleanup(other.Close)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/redirect":
			http.Redirect(w, r, other.URL+"/x", http.StatusFound)
		case "/error":
			w.WriteHeader(403)
			w.Write(bytes.Repeat([]byte(" "), 1<<20))
		case "/big":
			w.Write(bytes.Repeat([]byte(" "), 1<<20))
		case "/pruned":
			w.WriteHeader(410)
			io.WriteString(w, `{"code":"pruned"}`)
		}
	}))
	t.Cleanup(srv.Close)
	ep := RemoteEndpoint{BaseURL: srv.URL, HTTPClient: srv.Client(), Bearer: "grant"}
	st, _, body, err := rawGet(ctx, ep, srv.URL, "/redirect", nil, 1<<20)
	if err != nil || st != http.StatusFound || hit.Load() != 0 || len(body) > maxErrBody {
		t.Fatalf("redirect: %d %v, target hit %d times", st, err, hit.Load())
	}
	for _, path := range []string{"/error", "/big"} {
		st, _, body, err := rawGet(ctx, ep, srv.URL, path, nil, 64<<10)
		if !errors.Is(err, errTooLarge) || body != nil {
			t.Fatalf("%s: %d, %d bytes, %v", path, st, len(body), err)
		}
	}
	if _, _, body, err := rawGet(ctx, ep, srv.URL, "/big", nil, 2<<20); err != nil || len(body) != 1<<20 {
		t.Fatalf("a 200 within its cap: %d bytes, %v", len(body), err)
	}
	if st, _, body, err := rawGet(ctx, ep, srv.URL, "/pruned", nil, 1<<20); err != nil || st != 410 || string(body) != `{"code":"pruned"}` {
		t.Fatalf("410: %d %s %v", st, body, err)
	}
}

// v0.26.1 review: migration 015's DELETE, run over seeded rows: it
// deletes the rows of a purged resource and of a purged shadow namespace,
// and keeps those of a live resource and of a tombstoned one. Since v0.81
// a database at migration 014 is seeded directly, and 015 runs on it as
// an upgrade from v0.26.0 would run it (the table goes in 016).
func TestV0261Migration015Delete(t *testing.T) {
	t.Parallel()
	l := newV081Legacy(t)
	o := l.opts()
	o.migrations = migrationsUpTo(t, 14)
	e, err := Open(o)
	if err != nil {
		t.Fatal(err)
	}
	for _, ns := range []string{"s", "q"} {
		mkNS(t, e, ns, map[string]any{})
		for _, name := range []string{"live", "tomb", "gone"} {
			if _, err := put(e, ns, name, "", 1); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := e.update(context.Background(), func(t *tx) error {
		for _, ns := range []string{"s", "q"} {
			n := t.nsByName(ns)
			for _, name := range []string{"live", "tomb", "gone"} {
				_, err := t.Exec(`INSERT INTO remote_pending_sealings (shadow, name, kind, ref, epoch, rev_seq, kid, pl, want, answer, horizon, updated)
					VALUES (?,?,'doc','r',1,1,?,'{}',?,'refused',NULL,0)`, n.id, name, ns+"#1", []byte("w"))
				t.must(err)
			}
			_, err := t.Exec(`UPDATE resources SET state = 1 WHERE ns = ? AND name = 'tomb'`, n.id)
			t.must(err)
			_, err = t.Exec(`UPDATE resources SET state = 2 WHERE ns = ? AND name = 'gone'`, n.id)
			t.must(err)
		}
		_, err := t.Exec(`UPDATE namespaces SET purged = 1 WHERE name = 'q'`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	e.Close()
	// The rows would refuse the Open (legacy_e2e.go): purging their
	// namespaces after migrating leaves them as 015 left them.
	o.migrations, o.PurgeRaisedE2E = migrationsUpTo(t, 15), true
	if e, err = Open(o); err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if err := e.read(context.Background(), func(t *tx) error {
		q, err := t.Query(`SELECT n.name, p.name FROM remote_pending_sealings p JOIN namespaces n ON n.ns = p.shadow ORDER BY 1, 2`)
		t.must(err)
		defer q.Close()
		var got []string
		for q.Next() {
			var a, b string
			t.must(q.Scan(&a, &b))
			got = append(got, a+"/"+b)
		}
		if strings.Join(got, ",") != "s/live,s/tomb" {
			panic("rows left: " + strings.Join(got, ","))
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
