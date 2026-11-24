package core

// Adversarial review of v0.90, kept as regression tests: what a view, a
// public namespace's grant and a sealed namespace's answers must never
// give away (§7 step 1, §7.4, §7.9, §E.2.2, §E.4).

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// v090AdvPublicSealedWorld is a public sealed matches with derby, shared,
// opener and secret written.
func v090AdvPublicSealedWorld(t *testing.T) *v75World {
	t.Helper()
	w := newV75World(t, v75Opts{matches: func(doc map[string]any) {
		doc["encryption"] = map[string]any{"level": "sealed"}
		doc["read"] = "public"
	}})
	for _, n := range []string{"derby", "shared", "opener", "secret"} {
		v89Put(w, n, map[string]any{"title": n})
	}
	return w
}

// v090AdvViewID is the view of cred, a partial reader's grant, under a
// public namespace's view prefix (viewAccess, grantView).
func v090AdvViewID(t *testing.T, w *v75World, cred Credentials) string {
	t.Helper()
	var vid string
	w.inTx(func(t2 *tx) {
		n := t2.nsByName("matches")
		a, kind, err := t2.viewAccess(n, cred)
		if err != nil || kind != accessPartial {
			t.Fatalf("viewAccess: %v %v", kind, err)
		}
		fs := t2.filteredScope(n)
		fv, verr := t2.grantView(fs, t2.filteredCurrent(fs), a)
		if verr != nil {
			t.Fatal(verr)
		}
		vid = fv.View()
	})
	return vid
}

// An anonymous POST /ns/{ns}/keys in a public sealed namespace relays no
// key (§E.2.3).
func TestV090AdvPublicSealedAnonKeys(t *testing.T) {
	w := v090AdvPublicSealedWorld(t)
	ans, err := w.e.Keys(context.Background(), "matches", Credentials{}, KeysRequest{})
	if err == nil && ans != nil && len(ans.Keys) > 0 {
		t.Errorf("anonymous /keys in a public sealed namespace returned keys: %v", ans.Keys)
	}
}

// A partial reader of a public sealed namespace gets no key of a hidden
// revision, no K_log of a visible one whose parent is hidden, no K_blob
// of a blob only hidden revisions reference, and at the view prefix
// neither the hidden revision nor that blob; /keys gives it view keys
// alone (§7.9, §E.2.2).
func TestV090AdvPublicSealedHiddenMiddle(t *testing.T) {
	w := v090AdvPublicSealedWorld(t)
	li := advDocReader(w)
	kv, view := v89Key(t, w, li)
	if view == "" {
		t.Fatal("no view")
	}
	dv, dh := []byte("visible blob"), []byte("hidden blob")
	bv, nv := advUpload(t, w, "derby", dv)
	bh, nh := advUpload(t, w, "derby", dh)
	v1 := v89Put(w, "derby", map[string]any{"team": "a", "title": "v1", "b": advRef(bv, nv, dv)})
	v1b := v89Put(w, "derby", map[string]any{"team": "a", "title": "v1b", "b": advRef(bv, nv, dv)})
	h2 := v89Put(w, "derby", map[string]any{"team": "b", "secret": "S", "b": advRef(bh, nh, dh)})
	v3 := v89Put(w, "derby", map[string]any{"team": "a", "title": "v3"})
	got := advCollect(t, w, li, kv, view, "derby")
	if _, ok := got[h2]; ok {
		t.Errorf("LEAK: keys of hidden %s", h2)
	}
	if k, ok := got[v3]; ok && k.Log != nil {
		t.Errorf("LEAK: K_log of %s whose parent is hidden", v3)
	}
	for id, k := range got {
		if _, ok := k.Blobs[bh]; ok {
			t.Errorf("LEAK: K_blob of hidden-only blob via %s", id)
		}
	}
	if _, ok := got[v1]; !ok {
		t.Errorf("no keys for visible v1")
	}
	if k, ok := got[v1b]; !ok || k.Log == nil {
		t.Errorf("positive control: v1b without K_log: %v", ok)
	}
	ctx := context.Background()
	vc, err := w.e.ViewCredentials(ctx, "matches", view, li)
	if err != nil {
		t.Fatal(err)
	}
	if r, err := w.e.ResourceRev(ctx, "matches", "derby", h2, vc); err == nil && r != nil && r.Status == 200 {
		t.Errorf("LEAK: hidden rev served at the view prefix")
	}
	if b, err := w.e.OpenSealedBlob(ctx, "matches", "derby", bh, "1", vc); err == nil && b.Status == 200 {
		t.Errorf("LEAK: hidden-only blob at the view prefix")
	}
	if b, err := w.e.OpenBlob(ctx, "matches", "derby", bh, vc); err == nil && b.Status != 404 {
		t.Errorf("LEAK: hidden-only blob answered at view prefix: %+v", b)
	}
	ans, err := w.e.Keys(ctx, "matches", li, KeysRequest{Resources: []string{"derby"}})
	if err != nil {
		t.Fatalf("/keys for the partial reader: %v", err)
	}
	for _, k := range ans.Keys {
		if v, _ := k["view"].(string); v == "" {
			t.Errorf("LEAK: /keys gave the partial reader a non-view key: %v", k)
		}
	}
}

// A schema only hidden documents name never appears in a public
// namespace's filtered range or long-poll (§7.4, §7.9 Log entries).
func TestV090AdvPublicSchemaFiltered(t *testing.T) {
	w := newV75World(t, v75Opts{matches: func(doc map[string]any) { doc["read"] = "public" }})
	ctx := context.Background()
	li := advDocReader(w)
	w.put("matches", "sh", map[string]any{"$schema": "https://json-schema.org/draft/2020-12/schema", "type": "object"})
	h, _ := w.e.ResourceHead(ctx, "matches", "sh", w.admin)
	secret := "/r/matches/sh/rev/" + h.Head
	w.put("matches", "derby", map[string]any{"team": "a", "title": "v1"})
	w.put("matches", "derby", map[string]any{"team": "b", "$schema": secret})
	_, err := w.e.Batch(ctx, Request{NS: "matches", Cred: w.admin}, []Item{
		{Resource: "shared", IfNoneMatch: true, Steps: []Step{{Patches: patchTo(map[string]any{"team": "a"})}}},
		{Resource: "opener", IfNoneMatch: true, Steps: []Step{{Patches: patchTo(map[string]any{"team": "b", "$schema": secret})}}},
	}, nil, nil, false)
	if err != nil {
		t.Fatalf("batch: %v", err)
	}
	view := v090AdvViewID(t, w, li)
	at := w.head("matches")
	lg, _, err := w.e.FilteredLog(ctx, "matches", view, at, "", 100, li)
	if err != nil {
		t.Fatal(err)
	}
	b := v090AdvJSON(lg.Entries)
	if strings.Contains(b, h.Head) || strings.Contains(b, `"schemas"`) {
		t.Errorf("LEAK: hidden schema in filtered range: %s", b)
	}
	lg, _, err = w.e.FilteredLiveLog(ctx, "matches", view, "", 100, li)
	if err != nil {
		t.Fatalf("filtered live: %v", err)
	}
	b = v090AdvJSON(lg.Entries)
	if strings.Contains(b, h.Head) || strings.Contains(b, `"schemas"`) {
		t.Errorf("LEAK: hidden schema in filtered live: %s", b)
	}
}

func v090AdvJSON(v any) string { b, _ := json.Marshal(v); return string(b) }

// A hidden revision's schema must not appear in a view once its resource
// is purged (§7.4 schema kept through purge; §7.9 Log entries).
func TestV090AdvSchemaAfterPurge(t *testing.T) {
	for _, pub := range []bool{false, true} {
		for _, rule := range []string{"team", "schema"} {
			t.Run(map[bool]string{false: "grant", true: "public"}[pub]+"-"+rule, func(t *testing.T) {
				w := newV75World(t, v75Opts{matches: func(doc map[string]any) {
					if pub {
						doc["read"] = "public"
					}
				}})
				ctx := context.Background()
				w.put("matches", "sh", map[string]any{"$schema": "https://json-schema.org/draft/2020-12/schema", "type": "object", "title": "secret-schema"})
				sh, _ := w.e.ResourceHead(ctx, "matches", "sh", w.admin)
				ref := "/r/matches/sh/rev/" + sh.Head
				w.put("matches", "sv", map[string]any{"$schema": "https://json-schema.org/draft/2020-12/schema", "type": "object"})
				sv, _ := w.e.ResourceHead(ctx, "matches", "sv", w.admin)
				vref := "/r/matches/sv/rev/" + sv.Head
				var li Credentials
				if rule == "team" {
					li = advDocReader(w)
				} else {
					li = w.li(map[string]any{"rules": []any{map[string]any{"op": "test", "path": "/doc/$schema", "value": vref}}})
				}
				w.put("matches", "derby", map[string]any{"team": "a", "$schema": vref})
				w.put("matches", "derby", map[string]any{"team": "b", "$schema": ref})
				w.put("matches", "kilo", map[string]any{"team": "b", "$schema": ref})
				var view string
				if pub {
					view = v090AdvViewID(t, w, li)
				} else {
					view = v075ViewID(t, w, li)
				}
				read := func(what string) {
					at := w.head("matches")
					lg, _, err := w.e.FilteredLog(ctx, "matches", view, at, "", 100, li)
					if err != nil {
						t.Fatalf("%s: %v", what, err)
					}
					b := v090AdvJSON(lg.Entries)
					if strings.Contains(b, sh.Head) {
						t.Errorf("LEAK %s: hidden schema in filtered range: %s", what, b)
					}
					lg, _, err = w.e.FilteredLiveLog(ctx, "matches", view, "", 100, li)
					if err != nil {
						t.Fatalf("%s: filtered live: %v", what, err)
					}
					if b := v090AdvJSON(lg.Entries); strings.Contains(b, sh.Head) {
						t.Errorf("LEAK %s: hidden schema in filtered live: %s", what, b)
					}
					lg, _, err = w.e.FilteredEventLog(ctx, "matches", view, "", 100, li)
					if err != nil {
						t.Fatalf("%s: filtered events: %v", what, err)
					}
					if b := v090AdvJSON(lg.Entries); strings.Contains(b, sh.Head) {
						t.Errorf("LEAK %s: hidden schema in filtered events: %s", what, b)
					}
				}
				read("before")
				purger := w.cred(w.kPriv, map[string]any{"kid": "k", "sub": "user:root", "ns": []any{"matches"}, "can": []any{"read", "purge"}})
				for _, n := range []string{"kilo", "derby"} {
					h, _ := w.e.ResourceHead(ctx, "matches", n, w.admin)
					if _, err := w.e.Purge(ctx, Request{NS: "matches", Cred: purger}, n, h.Head, false); err != nil {
						t.Fatalf("purge %s: %v", n, err)
					}
				}
				if pub {
					view = v090AdvViewID(t, w, li)
				} else {
					view = v075ViewID(t, w, li)
				}
				read("after purge")
			})
		}
	}
}

// §E.4 / §7.4: in a sealed namespace a head entry's schema is sealed
// with the entry, never in the clear.
func TestV090AdvSealedSchemaPlaintext(t *testing.T) {
	for _, pub := range []bool{false, true} {
		w := newV75World(t, v75Opts{matches: func(doc map[string]any) {
			doc["encryption"] = map[string]any{"level": "sealed"}
			if pub {
				doc["read"] = "public"
			}
		}})
		ctx := context.Background()
		sc := v89Put(w, "sh", map[string]any{"$schema": "https://json-schema.org/draft/2020-12/schema", "type": "object"})
		ref := "/r/matches/sh/rev/" + sc
		v89Put(w, "derby", map[string]any{"$schema": ref, "team": "a"})
		check := func(what string, lg *Log, err error) {
			if err != nil {
				t.Fatalf("pub=%v %s: %v", pub, what, err)
			}
			b := v090AdvJSON(lg.Entries)
			if !lg.Sealed && strings.Contains(b, sc) {
				t.Errorf("LEAK pub=%v %s: schema in the clear: %s", pub, what, b)
			}
		}
		lg, err := w.e.NamespaceLog(ctx, "matches", w.head("matches"), "", 100, w.admin)
		check("log", lg, err)
		lg, err = w.e.NamespaceEvents(ctx, "matches", "", 100, w.admin)
		check("events", lg, err)
		lg, _, err = w.e.NamespaceLiveLog(ctx, "matches", "", 100, w.admin, nil)
		check("live", lg, err)
		lg, err = w.e.NamespaceLog(ctx, "matches", w.head("matches"), "", 100, Credentials{})
		if !pub {
			// A private namespace refuses the anonymous read outright.
			if ae, ok := err.(*Error); !ok || ae.Status != 401 {
				t.Fatalf("anon log of a private namespace: %v, want 401", err)
			}
			continue
		}
		check("anon log", lg, err)
	}
}

// Under a public sealed namespace's view prefix a blob redirects to the
// epoch of a visible revision, and the epoch only a hidden revision has
// answers as one the blob is never served under (§E.2.2 Epochs).
func TestV090AdvPublicSealedBlobEpochs(t *testing.T) {
	w := newV75World(t, v75Opts{matches: func(doc map[string]any) { doc["read"] = "public" }})
	ctx := context.Background()
	w.patchConfig("matches", map[string]any{"op": "add", "path": "/encryption", "value": map[string]any{"level": "sealed"}})
	data := []byte("shared blob")
	bid, nonce := advUpload(t, w, "derby", data)
	v89Put(w, "derby", map[string]any{"team": "a", "title": "v1", "b": advRef(bid, nonce, data)})
	w.patchConfig("matches", map[string]any{"op": "replace", "path": "/encryption", "value": map[string]any{"level": "sealed", "epoch": 2.0}})
	v89Put(w, "derby", map[string]any{"team": "b", "secret": "S", "b": advRef(bid, nonce, data)})
	li := advDocReader(w)
	_, view := v89Key(t, w, li)
	vc, err := w.e.ViewCredentials(ctx, "matches", view, li)
	if err != nil {
		t.Fatal(err)
	}
	if b, err := w.e.OpenBlob(ctx, "matches", "derby", bid, vc); err != nil || b.Status != 302 || b.Epoch != 1 {
		t.Errorf("view: %+v %v, want 302 to epoch 1", b, err)
	}
	b2, e2 := w.e.OpenSealedBlob(ctx, "matches", "derby", bid, "2", vc)
	b99, e99 := w.e.OpenSealedBlob(ctx, "matches", "derby", bid, "99", vc)
	s := func(b *Blob, err error) string {
		if err != nil {
			return "err " + err.Error()
		}
		return v090AdvJSON(map[string]any{"s": b.Status, "c": b.Code, "h": b.Horizon, "n": b.NoStore, "p": b.Public})
	}
	if s(b2, e2) != s(b99, e99) {
		t.Errorf("view e/2 (hidden epoch) %s differs from e/99 %s", s(b2, e2), s(b99, e99))
	}
}
