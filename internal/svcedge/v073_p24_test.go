package svcedge

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/edge"
	"github.com/middle-management/patchlog/internal/sqlitedsn"
	_ "modernc.org/sqlite"
)

// openDB opens the SQLite database at path as a service does.
func openDB(t *testing.T, path string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", sqlitedsn.DSN(path, "_pragma=journal_mode(WAL)&_pragma=busy_timeout(10000)"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func newStore(t *testing.T, db *sql.DB) *Store {
	t.Helper()
	s, err := NewStore(context.Background(), db)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// TC-16 (§B.11.5, §6.6): a service's exchangeRate buckets are shared by
// every instance on its database. Two instances, each with its own
// connection to one database, draw on one bucket: once one has drained
// it, the other is refused with the wait until it refills, and a draw
// from several buckets draws none while any is empty.
func TestV073BucketsSharedAcrossInstances(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "svc.db")
	a, b := newStore(t, openDB(t, path)), newStore(t, openDB(t, path))
	now := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	r := Rate{Rate: 1, Burst: 2}
	for i := range 2 {
		if wait, err := a.Draw(ctx, now, r, []string{"user:ann\x00k"}); err != nil || wait != 0 {
			t.Fatalf("draw %d on a: %v %v", i, wait, err)
		}
	}
	if wait, err := b.Draw(ctx, now, r, []string{"user:ann\x00k"}); err != nil || wait != time.Second {
		t.Fatalf("b after a drained the bucket: %v %v, want 1s", wait, err)
	}
	// All or nothing: bob's full bucket isn't drawn from while ann's is
	// empty.
	if wait, err := b.Draw(ctx, now, r, []string{"user:bob\x00k", "user:ann\x00k"}); err != nil || wait == 0 {
		t.Fatalf("bob with ann: %v %v", wait, err)
	}
	for i := range 2 {
		if wait, err := a.Draw(ctx, now, r, []string{"user:bob\x00k"}); err != nil || wait != 0 {
			t.Fatalf("bob's draw %d: %v %v, his bucket untouched", i, wait, err)
		}
	}
	// Refilled at Rate, on either instance.
	if wait, err := b.Draw(ctx, now.Add(time.Second), r, []string{"user:ann\x00k"}); err != nil || wait != 0 {
		t.Fatalf("ann a second later: %v %v", wait, err)
	}
}

// TC-16: the check and the draw are one step across instances: of many
// concurrent draws on two connections, exactly Burst succeed.
func TestV073BucketsAtomicDraw(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "svc.db")
	stores := []*Store{newStore(t, openDB(t, path)), newStore(t, openDB(t, path))}
	now := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	r := Rate{Rate: 0.001, Burst: 5}
	var mu sync.Mutex
	var wg sync.WaitGroup
	ok := 0
	for i := range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			wait, err := stores[i%2].Draw(ctx, now, r, []string{"k"})
			if err != nil {
				t.Error(err)
				return
			}
			if wait == 0 {
				mu.Lock()
				ok++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if ok != 5 {
		t.Fatalf("%d draws admitted, want 5", ok)
	}
}

// §B.11.5, §C.5.3: the subjects behind a gs recorded by one instance are
// found by another on the same database, until the last edge grant for
// it expires.
func TestV073SubjectsShared(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "svc.db")
	a, b := newStore(t, openDB(t, path)), newStore(t, openDB(t, path))
	now := time.Now()
	if err := a.Record(ctx, "gs1", []string{"group:eds"}, now.Add(time.Minute), now); err != nil {
		t.Fatal(err)
	}
	if subs, ok := b.Subjects(ctx, "gs1"); !ok || strings.Join(subs, ",") != "group:eds" {
		t.Fatalf("b: %v %v", subs, ok)
	}
	if _, ok := b.Subjects(ctx, "gs2"); ok {
		t.Fatal("a gs nobody recorded")
	}
	// Recorded again later, the expired one is dropped.
	if err := a.Record(ctx, "gs2", []string{"group:x"}, now.Add(3*time.Minute), now.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, ok := newStore(t, openDB(t, path)).Subjects(ctx, "gs1"); ok {
		t.Fatal("gs1 kept after its last edge grant expired")
	}
}

func decodeBody(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
		t.Fatalf("%s: %v", w.Body, err)
	}
	return m
}

// §C.5.2, §3.1, carry-over: an exchange's body is I-JSON without
// noncharacters (400 bad_input), and one larger than 50 grants of
// grantSize can be is 400 bad_input before it is parsed, never 413: no
// grant was measured against grantSize yet.
func TestV073BearersBody(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, body, ct, auth string
		status               int
		code                 string
		bearers              int
	}{
		{"one grant", `{"grants":["abc"]}`, "application/json", "", 0, "", 1},
		{"a noncharacter, raw", "{\"grants\":[\"a﷐\"]}", "application/json", "", 400, "bad_input", 0},
		{"a noncharacter, escaped", `{"grants":["a￿"]}`, "application/json", "", 400, "bad_input", 0},
		{"over 50 grants of grantSize", `{"grants":["` + strings.Repeat("a", BodyMax(DefaultGrantSize)) + `"]}`, "application/json", "", 400, "bad_input", 0},
		{"a body and Authorization", `{"grants":["abc"]}`, "application/json", "Bearer x", 400, "bad_input", 0},
		{"not JSON", `{"grants":["abc"]}`, "text/plain", "", 415, "unsupported_type", 0},
		{"no grants", `{"grants":[]}`, "application/json", "", 400, "bad_input", 0},
		{"Authorization alone", ``, "", "Bearer tok", 0, "", 1},
		{"nothing", ``, "", "", 0, "", 0},
	} {
		r := httptest.NewRequest("POST", "/edge-grants", strings.NewReader(tc.body))
		if tc.ct != "" {
			r.Header.Set("Content-Type", tc.ct)
		}
		if tc.auth != "" {
			r.Header.Set("Authorization", tc.auth)
		}
		bs, e := Bearers(r, DefaultGrantSize)
		switch {
		case tc.status == 0 && (e != nil || len(bs) != tc.bearers):
			t.Errorf("%s: %v %v", tc.name, bs, e)
		case tc.status != 0 && (e == nil || e.Status != tc.status || e.Body["code"] != tc.code):
			t.Errorf("%s: %+v, want %d %s", tc.name, e, tc.status, tc.code)
		}
	}
}

// §C.5.2: prefixes several issues give are merged, lasting as long as the
// longest, in the order first given; the answer's exp is the earliest,
// one cookie per prefix; §C.5.4: withdrawal expires each prefix named
// once, and refuses one that isn't the service's.
func TestV073MintAndWithdraw(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	c := edge.NewCookies("svc", nil)
	c.Vouches = func(p string) bool { return strings.HasPrefix(p, "/cat/g/") }
	merged := Merge([]Issue{{"/cat/g/a", now.Add(5 * time.Minute)}, {"/cat/g/b", now.Add(2 * time.Minute)}, {"/cat/g/a", now.Add(9 * time.Minute)}})
	if len(merged) != 2 || merged[0].Prefix != "/cat/g/a" || !merged[0].Exp.Equal(now.Add(9*time.Minute)) || merged[1].Prefix != "/cat/g/b" {
		t.Fatalf("merged %v", merged)
	}
	w := httptest.NewRecorder()
	Mint(w, c, now, merged)
	b := decodeBody(t, w)
	if w.Code != 200 || len(w.Result().Cookies()) != 2 || b["exp"] != now.Add(2*time.Minute).Format(time.RFC3339) ||
		strings.Join(toStrings(b["prefixes"]), " ") != "/cat/g/a /cat/g/b" || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("mint: %d %v %v", w.Code, b, w.Header())
	}
	ours := func(p string) bool { return strings.HasPrefix(p, "/cat/g/") }
	w = httptest.NewRecorder()
	Withdraw(w, httptest.NewRequest("DELETE", "/edge-grants?prefix=/cat/g/a&prefix=/cat/g/a&prefix=/cat/g/b", nil), c, ours, "/cat/g/{gs}")
	if w.Code != http.StatusNoContent || len(w.Result().Cookies()) != 2 {
		t.Fatalf("withdraw: %d %v", w.Code, w.Result().Cookies())
	}
	for _, q := range []string{"", "?prefix=/r/x", "?other=1"} {
		w = httptest.NewRecorder()
		Withdraw(w, httptest.NewRequest("DELETE", "/edge-grants"+q, nil), c, ours, "/cat/g/{gs}")
		if w.Code != 400 || decodeBody(t, w)["code"] != "bad_input" {
			t.Errorf("withdraw %q: %d", q, w.Code)
		}
	}
	w = httptest.NewRecorder()
	RateLimited(1500 * time.Millisecond).Write(w)
	if b := decodeBody(t, w); w.Code != 429 || w.Header().Get("Retry-After") != "2" || b["limit"] != "exchangeRate" || b["code"] != "rate" || b["retryAfter"] != 1.5 {
		t.Fatalf("rate: %d %v %v", w.Code, b, w.Header())
	}
}

func toStrings(v any) []string {
	var out []string
	for _, x := range v.([]any) {
		out = append(out, x.(string))
	}
	return out
}
