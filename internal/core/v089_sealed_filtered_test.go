package core

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/seal"
)

// v0.89 (§7.9 Sealed namespaces, §E.2.2): matches is sealed, and li a
// partial reader of it (rules on /resource that fix nothing).

func newV89SealedWorld(t *testing.T) *v75World {
	t.Helper()
	w := newV75World(t, v75Opts{matches: func(doc map[string]any) { doc["encryption"] = map[string]any{"level": "sealed"} }})
	for _, n := range []string{"derby", "shared", "opener", "secret"} {
		v89Put(w, n, map[string]any{"title": n})
	}
	return w
}

// v89Put writes name of matches with a fresh $nonce (§E.2.5).
func v89Put(w *v75World, name string, doc map[string]any) string {
	w.t.Helper()
	ctx := context.Background()
	it := Item{Resource: name}
	ps := []any{map[string]any{"op": "add", "path": "", "value": doc}, map[string]any{"op": "add", "path": "/$nonce", "value": seal.NewNonce()}}
	if h, err := w.e.ResourceHead(ctx, "matches", name, w.admin); err == nil && h.State == Live {
		it.IfMatch = h.Head
		ps[0] = map[string]any{"op": "replace", "path": "", "value": doc}
	} else {
		it.IfNoneMatch = true
	}
	it.Steps = []Step{{Patches: ps}}
	res, err := w.e.WriteResource(ctx, Request{NS: "matches", Cred: w.admin}, it)
	if err != nil {
		w.t.Fatalf("writing %s: %v", name, err)
	}
	return res.Entry.ID
}

// v89Key is the one raw key /keys gives cred in matches, and its view.
func v89Key(t *testing.T, w *v75World, cred Credentials) ([]byte, string) {
	t.Helper()
	ans, err := w.e.Keys(context.Background(), "matches", cred, KeysRequest{})
	if err != nil || len(ans.Keys) != 1 {
		t.Fatalf("/keys: %+v %v", ans, err)
	}
	k, err := base64.RawURLEncoding.DecodeString(ans.Keys[0]["key"].(string))
	if err != nil {
		t.Fatal(err)
	}
	view, _ := ans.Keys[0]["view"].(string)
	return k, view
}

// An unrestricted reader's /ns/{ns} cookie at a view's URL reads every
// revision, its answers sealed under K_n with no keys (§7.9).
func TestV089NSCookieUnderKn(t *testing.T) {
	t.Parallel()
	w := newV89SealedWorld(t)
	ctx := context.Background()
	view := v075ViewID(t, w, w.li())
	at := w.head("matches")
	cookie := Credentials{Edge: &EdgeGrant{NS: "matches", Prefix: "/ns/matches", Exp: w.now().Add(10 * time.Minute)}}
	lg, info, err := w.e.FilteredLog(ctx, "matches", view, at, "", 100, cookie)
	if err != nil || !info.Private || !lg.Sealed || lg.Range == "" {
		t.Fatalf("the cookie's range: %+v %+v %v", lg, info, err)
	}
	ke, _ := v89Key(t, w, w.admin)
	kn, _ := seal.NamespaceKey(ke, "matches")
	pt, err := seal.OpenExpect(lg.Range, kn, "matches#1", seal.FilteredRangePL("matches", view, "", at))
	if err != nil {
		t.Fatalf("under K_n: %v", err)
	}
	body, keys, err := seal.ParseFiltered(pt)
	if err != nil || len(keys) != 0 {
		t.Fatalf("keys %v %v", keys, err)
	}
	heads := 0
	for _, e := range body.([]any) {
		if e.(map[string]any)["kind"] == "head" {
			heads++
		}
	}
	if heads != 4 {
		t.Fatalf("the cookie's range shows %d heads, want every one", heads)
	}
	kv, _ := seal.FilterViewKey(ke, "matches", view)
	if _, err := seal.OpenExpect(lg.Range, kv, "matches#1", seal.FilteredRangePL("matches", view, "", at)); !errors.Is(err, seal.ErrDecrypt) {
		t.Fatalf("the cookie's range under K_view: %v", err)
	}
	// Its /heads page too.
	page, _, err := w.e.FilteredHeads(ctx, "matches", view, at, "", "", cookie)
	if err != nil || page.JWE == "" {
		t.Fatalf("the cookie's /heads: %+v %v", page, err)
	}
	if _, err := seal.OpenExpect(page.JWE, kn, "matches#1", seal.FilteredHeadsPL("matches", view, at, "")); err != nil {
		t.Fatalf("/heads under K_n: %v", err)
	}
}

// A partial reader's resource long-poll at sealed is one JWE under its
// K_view, pl { ns, view, name, range }, carrying the revision's keys
// (§7.9, §E.2.2); a resource it can't see answers as one that doesn't
// exist.
func TestV089ResourceLongPollSealed(t *testing.T) {
	t.Parallel()
	w := newV89SealedWorld(t)
	ctx := context.Background()
	li := w.li()
	kv, view := v89Key(t, w, li)
	if view == "" {
		t.Fatal("li got no view key")
	}
	id := v89Put(w, "derby", map[string]any{"title": "derby", "v": 2})
	lg, err := w.e.ResourceLiveLog(ctx, "matches", "derby", "", 100, li)
	if err != nil || lg.Status != 200 || lg.Range == "" || len(lg.Entries) != 2 {
		t.Fatalf("li's long-poll of derby: %+v %v", lg, err)
	}
	pt, err := seal.OpenExpect(lg.Range, kv, "matches#1", seal.FilteredResourceRangePL("matches", view, "derby", "", id))
	if err != nil {
		t.Fatalf("under K_view: %v", err)
	}
	body, keys, err := seal.ParseFiltered(pt)
	if err != nil || len(keys) != 2 || len(body.([]any)) != 2 {
		t.Fatalf("the answer: %d entries, %d keys, %v", len(body.([]any)), len(keys), err)
	}
	// Each entry with its patches is its stored JWE under its K_log,
	// which the keys carry.
	for i, x := range body.([]any) {
		j, ok := x.(string)
		if !ok {
			t.Fatalf("entry %d in the clear: %v", i, x)
		}
		h, _ := seal.ParseHeader(j)
		eid := h.PL["id"].(string)
		var log []byte
		for _, kj := range keys {
			kh, _ := seal.ParseHeader(kj)
			if kh.PL["id"] == eid {
				kp, err := seal.OpenExpect(kj, kv, "matches#1", seal.ViewKeysPL("matches", view, "derby", eid))
				if err != nil {
					t.Fatal(err)
				}
				vk, _ := seal.ParseViewKeys(kp)
				log = vk.Log
			}
		}
		if _, err := seal.OpenExpect(j, log, "matches#1", seal.ResourcePL("matches", "derby", eid, seal.KindRev)); err != nil {
			t.Fatalf("entry %s under its carried K_log: %v", eid, err)
		}
	}
	if lg, err := w.e.ResourceLiveLog(ctx, "matches", "secret", "", 100, li); err == nil && lg.Status == 200 && len(lg.Entries) > 0 {
		t.Fatalf("li's long-poll of secret: %+v", lg)
	}
}

// A purged sealed namespace's filtered URLs answer 410 once admitted, as
// its unfiltered forms do: its keys are gone (§8.5, §7.9).
func TestV089PurgedSealedFiltered(t *testing.T) {
	t.Parallel()
	w := newV89SealedWorld(t)
	ctx := context.Background()
	li := w.li()
	view := v075ViewID(t, w, li)
	at := w.head("matches")
	v077Purge(t, w, "matches")
	gone := func(what string, err error) {
		t.Helper()
		var e *Error
		if !errors.As(err, &e) || e.Status != 410 {
			t.Errorf("%s: %v, want 410", what, err)
		}
	}
	_, _, err := w.e.FilteredLog(ctx, "matches", view, at, "", 100, li)
	gone("the filtered range", err)
	_, _, err = w.e.FilteredLiveLog(ctx, "matches", view, at, 100, li)
	gone("the filtered long-poll", err)
	_, _, err = w.e.FilteredEventLog(ctx, "matches", view, "", 100, li)
	gone("the filtered events", err)
	_, _, err = w.e.FilteredHeads(ctx, "matches", view, at, "", "", li)
	gone("the filtered /heads", err)
}
