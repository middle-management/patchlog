package core

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/keystore"
	"github.com/middle-management/patchlog/internal/pgtest"
	"github.com/middle-management/patchlog/internal/seal"
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

// v0261JWE is a sealing of entry id of m/w, as A would serve it in a log
// page: only its header is read there.
func v0261JWE(t *testing.T, id string) string {
	t.Helper()
	key := make([]byte, 32)
	jwe, err := seal.Seal(key, "m#1", seal.ResourcePL("m", "w", id, seal.KindRev), []byte(`{"id":"`+id+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	return jwe
}

// v0261Base serves path's pages as page answers, by since.
func v0261Base(t *testing.T, page func(w http.ResponseWriter, since string)) (RemoteEndpoint, *atomic.Int64) {
	t.Helper()
	var n atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		page(w, r.URL.Query().Get("since"))
	}))
	t.Cleanup(srv.Close)
	return RemoteEndpoint{BaseURL: srv.URL, HTTPClient: srv.Client()}, &n
}

func v0261Page(w http.ResponseWriter, next string, items ...any) {
	if next != "" {
		w.Header().Set("X-Log-Next", next)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(items)
}

// C1, C3, C-M (v0.26.1): fetchSealedLog moves through the range, page by
// page, only as far as its mirrored chain goes: X-Log-Next must name an
// entry of the chain on that page after its since. Entries not of the
// chain, and sealings longer than caps.jwe, are dropped; each sealing is
// trimmed.
func TestV0261FetchSealedLogBounds(t *testing.T) {
	ctx := context.Background()
	chain := []string{"a1", "a2", "a3", "a4", "a5"}
	jwe := map[string]string{}
	for _, id := range append(chain, "zz") {
		jwe[id] = v0261JWE(t, id)
	}
	caps := preCaps{page: 1 << 20, jwe: 4 << 10}
	want := map[string]int64{}
	for _, id := range chain {
		want[id] = caps.jwe
	}
	t.Run("honest", func(t *testing.T) {
		ep, n := v0261Base(t, func(w http.ResponseWriter, since string) {
			switch since {
			case "":
				v0261Page(w, "a2", jwe["a1"], jwe["a2"]+"   ")
			case "a2":
				// An entry in the clear, then one A seals.
				v0261Page(w, "a4", map[string]any{"id": "a3"}, jwe["a4"])
			case "a4":
				v0261Page(w, "", jwe["a5"])
			}
		})
		out, ans, _ := fetchSealedLog(ctx, ep, ep.BaseURL, "/r/m/w/rev/a5/log", "", chain, want, caps)
		if ans != "" || len(out) != 4 || out["a2"] != jwe["a2"] || n.Load() != 3 {
			t.Fatalf("honest paging: %d entries, answer %q, %d pages", len(out), ans, n.Load())
		}
	})
	for name, page := range map[string]func(w http.ResponseWriter, since string){
		// A fresh X-Log-Next that isn't an entry of the chain.
		"not in chain": func(w http.ResponseWriter, since string) { v0261Page(w, since+"x", jwe["zz"]) },
		// One of the chain, but not on the page.
		"not on page": func(w http.ResponseWriter, since string) { v0261Page(w, "a3", jwe["a1"]) },
		// Back to an entry before since.
		"backwards": func(w http.ResponseWriter, since string) {
			if since == "" {
				v0261Page(w, "a2", jwe["a1"], jwe["a2"])
				return
			}
			v0261Page(w, "a1", jwe["a1"], jwe["a3"])
		},
		// The same since again.
		"stuck": func(w http.ResponseWriter, since string) {
			if since == "" {
				v0261Page(w, "a2", jwe["a1"], jwe["a2"])
				return
			}
			v0261Page(w, "a2", jwe["a2"])
		},
	} {
		t.Run(name, func(t *testing.T) {
			ep, n := v0261Base(t, page)
			out, ans, _ := fetchSealedLog(ctx, ep, ep.BaseURL, "/r/m/w/rev/a5/log", "", chain, want, caps)
			if ans != pendRefused || n.Load() > 2 {
				t.Fatalf("%d pages, answer %q, want refused within 2 pages", n.Load(), ans)
			}
			if _, ok := out["zz"]; ok {
				t.Fatalf("kept an entry not of the chain")
			}
		})
	}
	t.Run("caps", func(t *testing.T) {
		ep, _ := v0261Base(t, func(w http.ResponseWriter, since string) {
			v0261Page(w, "", jwe["a1"]+strings.Repeat(" ", 8<<10), jwe["a2"], strings.Repeat("A", 8<<10))
		})
		out, ans, _ := fetchSealedLog(ctx, ep, ep.BaseURL, "/r/m/w/rev/a5/log", "", chain, want, caps)
		if ans != "" || len(out) != 2 || out["a1"] != jwe["a1"] {
			t.Fatalf("%d entries, answer %q", len(out), ans)
		}
		// An entry not wanted isn't kept; one longer than its bound
		// isn't either, but still counts as on its page for X-Log-Next.
		ep, _ = v0261Base(t, func(w http.ResponseWriter, since string) {
			switch since {
			case "":
				v0261Page(w, "a2", jwe["a1"], jwe["a2"]+strings.Repeat(" ", 8<<10))
			case "a2":
				v0261Page(w, "", jwe["a3"], jwe["a4"], jwe["a5"])
			}
		})
		some := map[string]int64{"a2": 4 << 10, "a3": 4 << 10, "a5": 16}
		out, ans, _ = fetchSealedLog(ctx, ep, ep.BaseURL, "/r/m/w/rev/a5/log", "", chain, some, caps)
		if ans != "" || len(out) != 2 || out["a2"] != jwe["a2"] || out["a3"] != jwe["a3"] {
			t.Fatalf("wanted a2, a3 and a5 (too long): %d entries, answer %q", len(out), ans)
		}
		ep, _ = v0261Base(t, func(w http.ResponseWriter, since string) {
			switch since {
			case "":
				v0261Page(w, "a2", jwe["a1"], jwe["a2"])
			case "a2":
				v0261Page(w, "", jwe["a3"])
			}
		})
		out, ans, _ = fetchSealedLog(ctx, ep, ep.BaseURL, "/r/m/w/rev/a5/log", "", chain, map[string]int64{"a2": 16, "a3": 4 << 10}, caps)
		if ans != "" || len(out) != 1 || out["a3"] != jwe["a3"] {
			t.Fatalf("a2 too long, on the page X-Log-Next names: %d entries, answer %q", len(out), ans)
		}
		// A page longer than caps.page is a refusal, not a page that
		// isn't an array.
		big := preCaps{page: 4 << 10, jwe: 4 << 10}
		ep, _ = v0261Base(t, func(w http.ResponseWriter, since string) {
			v0261Page(w, "", jwe["a1"], strings.Repeat("A", 8<<10))
		})
		if _, ans, _ := fetchSealedLog(ctx, ep, ep.BaseURL, "/r/m/w/rev/a5/log", "", chain, want, big); ans != pendRefused {
			t.Fatalf("a page over its cap: %q, want refused", ans)
		}
	})
}

// C4, C-M, C2 (v0.26.1): rawGet follows no redirect, reads at most a small
// error body and at most limit of a 200; pendingAnswer counts a redirect
// and an answer over its cap as refusals, and a 410 pruned without a
// horizon too.
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
	if err != nil || st != http.StatusFound || hit.Load() != 0 {
		t.Fatalf("redirect: %d %v, target hit %d times", st, err, hit.Load())
	}
	if a, _ := pendingAnswer(st, body, err); a != pendRefused {
		t.Fatalf("redirect: %s", a)
	}
	for _, path := range []string{"/error", "/big"} {
		st, _, body, err := rawGet(ctx, ep, srv.URL, path, nil, 64<<10)
		if !errors.Is(err, errTooLarge) || body != nil {
			t.Fatalf("%s: %d, %d bytes, %v", path, st, len(body), err)
		}
		if a, _ := pendingAnswer(st, body, err); a != pendRefused {
			t.Fatalf("%s: %s", path, a)
		}
	}
	if _, _, body, err := rawGet(ctx, ep, srv.URL, "/big", nil, 2<<20); err != nil || len(body) != 1<<20 {
		t.Fatalf("a 200 within its cap: %d bytes, %v", len(body), err)
	}
	st, _, body, err = rawGet(ctx, ep, srv.URL, "/pruned", nil, 1<<20)
	if a, _ := pendingAnswer(st, body, err); a != pendRefused {
		t.Fatalf("410 pruned with no horizon: %s", a)
	}
}

// C-B (v0.26.1): the backoff of a pending sealing's failed retries.
func TestV0261PendingBackoff(t *testing.T) {
	for tries, want := range map[int]time.Duration{0: 0, 1: 0, 2: time.Minute, 3: 2 * time.Minute, 4: 4 * time.Minute, 10: maxPendingBackoff, 1000: maxPendingBackoff} {
		if got := pendingBackoff(tries); got != want {
			t.Errorf("pendingBackoff(%d) = %v, want %v", tries, got, want)
		}
	}
}

// C-B (v0.26.1): one sync asks for at most maxPendingPerSync of a shadow's
// pending sealings, the longest due first, counting only those it can
// open: rows whose epoch key it lacks, which never settle, don't starve
// the others. A row recorded 410 pruned before v0.26.1 (due 0) keeps its
// horizon only if it is a revision of the chain at or after the row's;
// otherwise it is a refusal, asked again.
func TestV0261PendingRowsCap(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ks, err := keystore.New(keystore.Generate())
	if err != nil {
		t.Fatal(err)
	}
	now := &p29Clock{t: p36T0}
	e, err := Open(Options{Path: pgtest.DB(t), BlobDir: t.TempDir(), AuthDisabled: true, RetentionInterval: -1, BlobSweepInterval: -1,
		Remote: RemoteOptions{FollowInterval: -1}, Purger: discardPurger{}, KeyStore: ks, Now: now.Now})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close() })
	mkNS(t, e, "s", map[string]any{"encryption": map[string]any{"level": "sealed"}})
	w, err := e.WriteResource(ctx, p29Req("s"), Item{Resource: "d", IfNoneMatch: true,
		Steps: []Step{{Patches: []any{p29Add("", map[string]any{"n": 1.0}), p29Add("/$nonce", seal.NewNonce())}}}})
	if err != nil {
		t.Fatal(err)
	}
	d1 := w.Items[0].IDs[0]
	w, err = e.WriteResource(ctx, p29Req("s"), Item{Resource: "d", IfMatch: d1,
		Steps: []Step{{Patches: []any{map[string]any{"op": "replace", "path": "/n", "value": 2.0}, map[string]any{"op": "replace", "path": "/$nonce", "value": seal.NewNonce()}}}}})
	if err != nil {
		t.Fatal(err)
	}
	d2 := w.Items[0].IDs[0]
	var epoch int
	if err := e.update(ctx, func(t *tx) error {
		n := t.nsByName("s")
		epoch = t.config(n.configSeq).Epoch
		// The rows are d1's; d2 is a horizon after it, d1 none.
		var seq int64
		id1 := mustID(d1)
		t.must(t.QueryRow(`SELECT rv.seq FROM revisions rv JOIN resources r ON r.res = rv.res WHERE r.ns = ? AND r.name = ? AND rv.id = ?`, n.id, "d", id1[:]).Scan(&seq))
		rec := func(ref string, ep int, answer, horizon string) {
			t.recordPending(n.id, "d", seq, pendingSealing{kind: sealDoc, ref: ref, epoch: ep, kid: "s#1", pl: seal.PL{"ns": "s"}, answer: answer, horizon: horizon})
		}
		// Earlier due, under an epoch whose key it lacks.
		for i := range 2 * maxPendingPerSync {
			rec(fmt.Sprintf("nokey%03d", i), epoch+99, pendRefused, "")
		}
		for i := range maxPendingPerSync + 10 {
			rec(fmt.Sprintf("ref%03d", i), epoch, pendRefused, "")
		}
		rec("legacy-junk", epoch, pendPruned, strings.Repeat("A", 1<<10))
		rec("legacy-own", epoch, pendPruned, d1)
		rec("legacy-ok", epoch, pendPruned, d2)
		_, err := t.Exec(`UPDATE remote_pending_sealings SET due = 1 WHERE ref LIKE 'nokey%'`)
		t.must(err)
		_, err = t.Exec(`UPDATE remote_pending_sealings SET due = 0 WHERE ref LIKE 'legacy-%'`)
		t.must(err)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	var rows []*pendingRow
	var fix pendingFixes
	if err := e.read(ctx, func(t *tx) error {
		rows = t.pendingRows(t.nsByName("s"), maxPendingPerSync, &fix)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(rows) != maxPendingPerSync {
		t.Fatalf("%d rows asked for, want %d", len(rows), maxPendingPerSync)
	}
	for _, r := range rows {
		if r.s.epoch != epoch || !strings.HasPrefix(r.s.ref, "ref") {
			t.Fatalf("asked for %s under epoch %d", r.s.ref, r.s.epoch)
		}
	}
	if len(fix.demote) != 2 || fix.demote[0][3] != "legacy-junk" || fix.demote[1][3] != "legacy-own" || len(fix.confirm) != 1 || fix.confirm[0][3] != "legacy-ok" {
		t.Fatalf("legacy pruned rows: demote %v, confirm %v", fix.demote, fix.confirm)
	}
}

// v0.26.1 review: migration 015's DELETE, run over seeded rows: it
// deletes the rows of a purged resource and of a purged shadow namespace,
// and keeps those of a live resource and of a tombstoned one.
func TestV0261Migration015Delete(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ks, err := keystore.New(keystore.Generate())
	if err != nil {
		t.Fatal(err)
	}
	now := &p29Clock{t: p36T0}
	e, err := Open(Options{Path: pgtest.DB(t), BlobDir: t.TempDir(), AuthDisabled: true, RetentionInterval: -1, BlobSweepInterval: -1,
		Remote: RemoteOptions{FollowInterval: -1}, Purger: discardPurger{}, KeyStore: ks, Now: now.Now})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close() })
	mkNS(t, e, "s", map[string]any{"encryption": map[string]any{"level": "sealed"}})
	mkNS(t, e, "q", map[string]any{"encryption": map[string]any{"level": "sealed"}})
	for _, ns := range []string{"s", "q"} {
		for _, name := range []string{"live", "tomb", "gone"} {
			if _, err := e.WriteResource(ctx, p29Req(ns), Item{Resource: name, IfNoneMatch: true,
				Steps: []Step{{Patches: []any{p29Add("", map[string]any{"n": 1.0}), p29Add("/$nonce", seal.NewNonce())}}}}); err != nil {
				t.Fatal(err)
			}
		}
	}
	dialect := "sqlite"
	if e.pg {
		dialect = "postgres"
	}
	body, err := os.ReadFile("migrations/" + dialect + "/015_remote_pending_backoff.sql")
	if err != nil {
		t.Fatal(err)
	}
	del := string(body[strings.Index(string(body), "DELETE FROM"):])
	if err := e.update(ctx, func(t *tx) error {
		for _, ns := range []string{"s", "q"} {
			n := t.nsByName(ns)
			for _, name := range []string{"live", "tomb", "gone"} {
				t.recordPending(n.id, name, 1, pendingSealing{kind: sealDoc, ref: "r", epoch: 1, kid: ns + "#1", pl: seal.PL{"ns": ns}, answer: pendRefused})
			}
			_, err := t.Exec(`UPDATE resources SET state = 1 WHERE ns = ? AND name = 'tomb'`, n.id)
			t.must(err)
			_, err = t.Exec(`UPDATE resources SET state = 2 WHERE ns = ? AND name = 'gone'`, n.id)
			t.must(err)
		}
		_, err := t.Exec(`UPDATE namespaces SET purged = 1 WHERE name = 'q'`)
		t.must(err)
		_, err = t.Exec(del)
		t.must(err)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := e.read(ctx, func(t *tx) error {
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
