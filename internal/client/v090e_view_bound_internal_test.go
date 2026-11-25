package client

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/middle-management/patchlog/internal/seal"
)

// v0.90 §E.2.2 Protected header ("where the URL names none, with the view
// of the key /keys gave the grant the request carried"; CONFORMANCE
// Filtered reads 87): the view a filtered answer at a resource's URL is
// compared with is the one /keys gave the grant that request carried,
// whatever keys the cache holds. Clients made by With with another
// bearer share their key cache: before, a view key cached for one grant
// let another accept that view's answers, and a K_e cached for one made
// another's answers of its own view fail, /keys never asked for it.
func TestV090EFilteredViewBoundPerGrant(t *testing.T) {
	ctx := context.Background()
	const ns, name = "matches", "derby"
	kid := seal.Kid(ns, 1)
	ke := seal.NewKey()
	viewA, viewB := "1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "1bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	kA, err := seal.FilterViewKey(ke, ns, viewA)
	if err != nil {
		t.Fatal(err)
	}
	kB, err := seal.FilterViewKey(ke, ns, viewB)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	asked := map[string]int{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/ns/"+ns+"/keys" {
			http.NotFound(w, r)
			return
		}
		bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		mu.Lock()
		asked[bearer]++
		mu.Unlock()
		var body struct {
			Resources []string `json:"resources"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		var entry map[string]any
		switch {
		case len(body.Resources) > 0:
			// Asked for resources' keys alone: a partial reader gets
			// none of them, nor its view's.
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{"epoch": 1, "keys": []any{}})
			return
		}
		switch bearer {
		case "grant-a":
			entry = map[string]any{"kid": kid, "view": viewA, "key": base64.RawURLEncoding.EncodeToString(kA)}
		case "grant-b":
			entry = map[string]any{"kid": kid, "view": viewB, "key": base64.RawURLEncoding.EncodeToString(kB)}
		case "grant-full":
			entry = map[string]any{"kid": kid, "key": base64.RawURLEncoding.EncodeToString(ke)}
		default:
			http.Error(w, `{"code":"unauthenticated"}`, 401)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"epoch": 1, "keys": []any{entry}})
	}))
	defer srv.Close()
	since, last := "1ccccccccccccccccccccccccccccccc0", "1dddddddddddddddddddddddddddddddd"
	answer := func(view string, k []byte) string {
		t.Helper()
		pl := seal.WithView(seal.PL{"ns": ns, "name": name, "range": []any{since, last}}, view)
		jwe, err := seal.Seal(k, kid, pl, seal.FilteredPlaintext([]any{}, nil))
		if err != nil {
			t.Fatal(err)
		}
		return jwe
	}

	t.Run("a view cached for another grant", func(t *testing.T) {
		a, err := New(srv.URL, WithKeys(NewKeys(nil)), WithBearer("grant-a"))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := a.openFilteredLog(ctx, ns, name, since, last, answer(viewA, kA)); err != nil {
			t.Fatalf("A's answer of its own view: %v", err)
		}
		b := a.With(WithBearer("grant-b"))
		if _, err := b.openFilteredLog(ctx, ns, name, since, last, answer(viewA, kA)); !errors.Is(err, seal.ErrMismatch) {
			t.Fatalf("B given A's view's answer, A's key cached: %v, want a mismatch", err)
		}
		if _, err := b.openFilteredLog(ctx, ns, name, since, last, answer(viewB, kB)); err != nil {
			t.Fatalf("B's answer of its own view: %v", err)
		}
		if _, err := a.openFilteredLog(ctx, ns, name, since, last, answer(viewB, kB)); !errors.Is(err, seal.ErrMismatch) {
			t.Fatalf("A given B's view's answer, B's key cached: %v, want a mismatch", err)
		}
	})

	t.Run("a resource's keys asked first", func(t *testing.T) {
		b, err := New(srv.URL, WithKeys(NewKeys(nil)), WithBearer("grant-b"))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := b.keys.key(ctx, b, kid, name, ns); !errors.Is(err, ErrNoKeys) {
			t.Fatalf("B's K_r of %s: %v, want none", name, err)
		}
		if _, err := b.openFilteredLog(ctx, ns, name, since, last, answer(viewB, kB)); err != nil {
			t.Fatalf("B's answer of its own view, after asking /keys for a resource's: %v", err)
		}
	})

	t.Run("a K_e cached for another grant", func(t *testing.T) {
		full, err := New(srv.URL, WithKeys(NewKeys(nil)), WithBearer("grant-full"))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := full.keys.key(ctx, full, kid, "", ns); err != nil {
			t.Fatalf("the full reader's K_e: %v", err)
		}
		mu.Lock()
		before := asked["grant-b"]
		mu.Unlock()
		b := full.With(WithBearer("grant-b"))
		if _, err := b.openFilteredLog(ctx, ns, name, since, last, answer(viewB, kB)); err != nil {
			t.Fatalf("B's answer of its own view, a K_e cached: %v", err)
		}
		if _, err := b.openFilteredLog(ctx, ns, name, since, last, answer(viewA, kA)); !errors.Is(err, seal.ErrMismatch) {
			t.Fatalf("B given A's view's answer, a K_e cached that opens it: %v, want a mismatch", err)
		}
		mu.Lock()
		n := asked["grant-b"] - before
		mu.Unlock()
		if n != 1 {
			t.Errorf("B asked /keys %d times, want once: its view is remembered", n)
		}
	})
}
