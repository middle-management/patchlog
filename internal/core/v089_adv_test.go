package core

// Regressions from an adversarial review of v0.88/v0.89: keys of hidden
// revisions (§7.9, §E.2), purge following under a grant that can't purge
// (§G.1), the epoch a blob's 302 names to a reader judged per revision
// (§7.9 Content), and 410 for purged names (§8.3).

import (
	"bytes"
	"context"
	"encoding/base64"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/seal"
)

// advDocReader is li with a /doc rule: a reader judged per revision, who
// reads only documents of team a.
func advDocReader(w *v75World) Credentials {
	return w.li(map[string]any{"rules": []any{map[string]any{"op": "test", "path": "/doc/team", "value": "a"}}})
}

func advUpload(t *testing.T, w *v75World, name string, data []byte) (string, string) {
	t.Helper()
	nonce := seal.NewNonce()
	bid := ids.Blob("text/plain", nonce, data).String()
	up := BlobUpload{Type: "text/plain", Nonce: nonce, NonceSent: true, Body: bytes.NewReader(data), Length: int64(len(data))}
	if err := w.e.UploadBlob(context.Background(), Request{NS: "matches", Cred: w.admin}, name, bid, up); err != nil {
		t.Fatalf("upload: %v", err)
	}
	return bid, nonce
}

func advRef(bid, nonce string, data []byte) map[string]any {
	return map[string]any{"$blob": bid, "type": "text/plain", "size": float64(len(data)), "nonce": nonce}
}

// advCollect opens every keys JWE of every filtered/partial channel and
// returns id -> ViewKeys.
func advCollect(t *testing.T, w *v75World, cred Credentials, kv []byte, view, name string) map[string]seal.ViewKeys {
	t.Helper()
	ctx := context.Background()
	out := map[string]seal.ViewKeys{}
	add := func(src, jwe string, pl seal.PL) {
		if jwe == "" {
			return
		}
		h, err := seal.ParseHeader(jwe)
		if err != nil {
			t.Fatalf("%s: %v", src, err)
		}
		pt, err := seal.OpenExpect(jwe, kv, h.Kid, pl)
		if err != nil {
			// pl mismatch: open with the header's own pl.
			pt, err = seal.OpenExpect(jwe, kv, h.Kid, h.PL)
			if err != nil {
				t.Logf("%s: can't open: %v", src, err)
				return
			}
		}
		_, keys, err := seal.ParseFiltered(pt)
		if err != nil {
			t.Fatalf("%s: %v", src, err)
		}
		for _, kj := range keys {
			kh, _ := seal.ParseHeader(kj)
			id, _ := kh.PL["id"].(string)
			kp, err := seal.OpenExpect(kj, kv, kh.Kid, kh.PL)
			if err != nil {
				t.Logf("%s: keys of %s (kid %s) not opened: %v", src, id, kh.Kid, err)
				continue
			}
			vk, err := seal.ParseViewKeys(kp)
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("%s: keys of %s/%s log=%v blobs=%d", src, kh.PL["name"], id, vk.Log != nil, len(vk.Blobs))
			if prev, ok := out[id]; ok {
				if (prev.Log == nil) != (vk.Log == nil) {
					t.Errorf("%s: keys of %s disagree on log", src, id)
				}
				for b, k := range vk.Blobs {
					prev.Blobs[b] = k
				}
				if vk.Log != nil {
					prev.Log = vk.Log
				}
				out[id] = prev
			} else {
				out[id] = vk
			}
		}
	}
	at := w.head("matches")
	if lg, _, err := w.e.FilteredLog(ctx, "matches", view, at, "", 100, cred); err == nil {
		add("filtered range", lg.Range, nil)
		for _, j := range lg.EntryJWEs {
			add("filtered range entry", j, nil)
		}
	} else {
		t.Logf("filtered range: %v", err)
	}
	if lg, _, err := w.e.FilteredEventLog(ctx, "matches", view, "", 100, cred); err == nil {
		for _, j := range lg.EntryJWEs {
			add("filtered events", j, nil)
		}
		add("filtered events range", lg.Range, nil)
	} else {
		t.Logf("filtered events: %v", err)
	}
	if lg, _, err := w.e.FilteredLiveLog(ctx, "matches", view, "", 100, cred); err == nil {
		add("filtered live", lg.Range, nil)
	} else {
		t.Logf("filtered live: %v", err)
	}
	if page, _, err := w.e.FilteredHeads(ctx, "matches", view, at, "", "", cred); err == nil {
		add("filtered heads", page.JWE, nil)
	} else {
		t.Logf("filtered heads: %v", err)
	}
	if lg, err := w.e.ResourceLog(ctx, "matches", name, "", "", 100, cred); err == nil {
		add("resource log", lg.Range, nil)
		for _, j := range lg.EntryJWEs {
			add("resource log entry", j, nil)
		}
	} else {
		t.Logf("resource log: %v", err)
	}
	if lg, err := w.e.ResourceEventLog(ctx, "matches", name, "", 100, cred); err == nil {
		add("resource events range", lg.Range, nil)
		for _, j := range lg.EntryJWEs {
			add("resource events", j, nil)
		}
	} else {
		t.Logf("resource events: %v", err)
	}
	if lg, err := w.e.ResourceLiveLog(ctx, "matches", name, "", 100, cred); err == nil {
		add("resource live", lg.Range, nil)
	} else {
		t.Logf("resource live: %v", err)
	}
	return out
}

func TestV089AdvHiddenMiddle(t *testing.T) {
	w := newV89SealedWorld(t)
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
	t.Logf("v1=%s h2=%s v3=%s", v1, h2, v3)
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
		t.Errorf("positive control: v1b (visible parent) without K_log: %v", ok)
	}
	vc, err := w.e.ViewCredentials(context.Background(), "matches", view, li)
	if err != nil {
		t.Fatal(err)
	}
	if r, err := w.e.ResourceRev(context.Background(), "matches", "derby", h2, vc); err == nil && r != nil && r.Status == 200 {
		t.Errorf("LEAK: hidden rev served at the view prefix")
	} else {
		t.Logf("view rev h2: %v", err)
	}
	if b, err := w.e.OpenSealedBlob(context.Background(), "matches", "derby", bh, "1", vc); err == nil && b.Status == 200 {
		t.Errorf("LEAK: hidden-only blob at the view prefix")
	} else {
		t.Logf("view blob bh: %v", err)
	}
	if b, err := w.e.OpenSealedBlob(context.Background(), "matches", "derby", bv, "1", vc); err != nil || b.Status != 200 {
		t.Errorf("visible blob at the view prefix: %v", err)
	}
	// Blob of hidden revision at the own URL / epoch URL.
	b, err := w.e.OpenSealedBlob(context.Background(), "matches", "derby", bh, "1", li)
	if err == nil && b.Status == 200 {
		t.Errorf("LEAK: hidden-only blob served sealed to li")
	}
}

// Tombstone between: v1 visible, h2 hidden, deleted (tombstone of h2),
// v4 re-created visible. v4's parent is a tombstone of a hidden doc.
func TestV089AdvTombstoneParent(t *testing.T) {
	w := newV89SealedWorld(t)
	li := advDocReader(w)
	kv, view := v89Key(t, w, li)
	v89Put(w, "derby", map[string]any{"team": "a", "title": "v1"})
	h2 := v89Put(w, "derby", map[string]any{"team": "b", "secret": "S"})
	w.del("matches", "derby")
	// re-create as a patch over the deleted doc (add at path)
	ctx := context.Background()
	h, _ := w.e.ResourceHead(ctx, "matches", "derby", w.admin)
	it := Item{Resource: "derby", IfMatch: h.Head, Steps: []Step{{Patches: []any{
		map[string]any{"op": "add", "path": "", "value": map[string]any{"team": "a", "title": "v4"}},
		map[string]any{"op": "add", "path": "/$nonce", "value": seal.NewNonce()}}}}}
	res, err := w.e.WriteResource(ctx, Request{NS: "matches", Cred: w.admin}, it)
	if err != nil {
		t.Fatal(err)
	}
	v4 := res.Entry.ID
	got := advCollect(t, w, li, kv, view, "derby")
	if _, ok := got[h2]; ok {
		t.Errorf("LEAK: keys of hidden %s", h2)
	}
	if k, ok := got[v4]; ok && k.Log != nil {
		t.Errorf("K_log of %s whose tombstone parent deleted a hidden doc", v4)
	}
}

// §G.1 (v0.88): only import batches "under a grant that may purge the
// names they write" are followed, judged as the purge itself is (§6.2,
// §C.2): step 1, step 2.2 (the head readable under the grant's read rules)
// and step 6 (its rules with the purge envelope, doc null). A grant
// refused at any of them is recorded as no name's importer, and its
// origin's purge of the name isn't applied here.
func TestV088AdvPurgeFollowFullCheck(t *testing.T) {
	cases := []struct {
		name string
		rule map[string]any
	}{
		// Step 6: a rule on /doc, which the purge judges with doc null.
		{"step 6", map[string]any{"any": []any{
			map[string]any{"not": map[string]any{"op": "test", "path": "/action", "value": "purge"}},
			map[string]any{"op": "test", "path": "/doc/purgeable", "value": true}}}},
		// Step 2.2: the grant's read rules hide a's head (team b).
		{"step 2.2", map[string]any{"any": []any{
			map[string]any{"not": map[string]any{"op": "test", "path": "/action", "value": "read"}},
			map[string]any{"op": "test", "path": "/doc/team", "value": "a"}}}},
		// Control: a grant that may purge a is recorded.
		{"may purge", nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := newV75World(t, v75Opts{})
			ctx := context.Background()
			w.put("matches", "a", map[string]any{"title": "a", "team": "b"})
			root := map[string]any{"kid": "k", "sub": "svc:importer", "ns": []any{"matches"},
				"can": []any{"read", "create", "append", "purge"}}
			if c.rule != nil {
				root["rules"] = []any{c.rule}
			}
			imp := w.cred(w.kPriv, root)
			h, _ := w.e.ResourceHead(ctx, "matches", "a", w.admin)
			// The grant's own purge of a is refused.
			mayPurge := c.rule == nil
			if !mayPurge {
				if _, err := w.e.Purge(ctx, Request{NS: "matches", Cred: imp}, "a", h.Head, false); v75Status(err) != 403 {
					t.Fatalf("the importer's own purge of a: %v, want 403", err)
				}
			}
			var rows []string
			if err := w.e.update(ctx, func(t *tx) error {
				n := t.nsByName("matches")
				a, aerr := t.authenticate(n.name, n, t.config(n.configSeq), imp, nil)
				if aerr != nil {
					return aerr
				}
				src := map[string]any{"origin": "https://staging.example", "ns": "matches", "at": "1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "bundle": "1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
				t.recordImport(n, a, src, []*itemState{{Item: Item{Resource: "a"}}})
				q, err := t.Query(`SELECT name, importer FROM purge_follow_names`)
				if err != nil {
					return err
				}
				defer q.Close()
				for q.Next() {
					var a, b string
					t.must(q.Scan(&a, &b))
					rows = append(rows, a+" "+b)
				}
				return q.Err()
			}); err != nil {
				t.Fatal(err)
			}
			if mayPurge {
				if len(rows) != 1 || rows[0] != "a svc:importer" {
					t.Fatalf("a grant that may purge a: recorded %v", rows)
				}
				return
			}
			if len(rows) != 0 {
				t.Fatalf("a grant that may not purge a (403 above) is recorded as its importer: %v", rows)
			}
			// The origin then purges a: following doesn't apply it here.
			var nsID int64
			w.inTx(func(t *tx) { nsID = t.nsByName("matches").id })
			k := followKey{ns: nsID, nsName: "matches", origin: "https://staging.example", srcNS: "matches"}
			po := PurgeOrigin{Importers: []string{"svc:importer"}}
			if err := w.e.applyFollowed(ctx, k, po, []client.NSEntry{{ID: "1bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", Kind: "purge", Resource: "a"}}, nil); err != nil {
				t.Fatal(err)
			}
			if h, err := w.e.ResourceHead(ctx, "matches", "a", w.admin); err != nil || h.State != Live {
				t.Fatalf("a, which the importer's grant may not purge, after following: %+v %v", h, err)
			}
		})
	}
}

// Rotation: a revision of epoch 1 must never get keys sealed under
// epoch 2's K_view (a reader whose window starts at 2 would open them).
func TestV089AdvRotationKeysEpoch(t *testing.T) {
	w := newV89SealedWorld(t)
	ctx := context.Background()
	li := advDocReader(w)
	v1 := v89Put(w, "derby", map[string]any{"team": "a", "title": "v1"})
	v1b := v89Put(w, "derby", map[string]any{"team": "a", "title": "v1b"})
	star := w.admin
	info, err := w.e.NamespaceHead(ctx, "matches", w.admin)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.e.WriteConfig(ctx, Request{NS: "matches", Cred: star}, ConfigChange{IfMatch: info.Config, Patches: []any{
		map[string]any{"op": "replace", "path": "/encryption", "value": map[string]any{"level": "sealed", "epoch": 2.0}}}}); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	v2 := v89Put(w, "derby", map[string]any{"team": "a", "title": "v2"})
	ans, err := w.e.Keys(ctx, "matches", li, KeysRequest{})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("li keys: %v", ans.Keys)
	var kv []byte
	var view string
	for _, k := range ans.Keys {
		if k["kid"] == "matches#2" {
			kv, _ = base64.RawURLEncoding.DecodeString(k["key"].(string))
			view, _ = k["view"].(string)
		}
	}
	if kv == nil {
		t.Fatal("no epoch-2 view key")
	}
	got := advCollect(t, w, li, kv, view, "derby")
	for _, id := range []string{v1, v1b} {
		if _, ok := got[id]; ok {
			t.Errorf("LEAK: keys of epoch-1 revision %s opened under epoch 2's K_view", id)
		}
	}
	if k, ok := got[v2]; !ok || k.Log == nil {
		t.Logf("v2 keys: %v %v", ok, k.Log != nil)
	}
}

// §8.3/v0.88: a purged resource is 410 only to readers whose non-/doc
// rules allow its name. li's key rule (reader-01) allows derby and shared only.
func TestV088AdvPurgedNames(t *testing.T) {
	w := newV75World(t, v75Opts{})
	ctx := context.Background()
	for _, n := range []string{"shared", "secret"} {
		w.put("matches", n, map[string]any{"title": n, "team": "b"})
	}
	li := advDocReader(w)
	for _, n := range []string{"shared", "secret"} {
		h, _ := w.e.ResourceHead(ctx, "matches", n, w.admin)
		if _, err := w.e.Purge(ctx, Request{NS: "matches", Cred: w.admin}, n, h.Head, false); err != nil {
			t.Fatal(err)
		}
	}
	for _, n := range []string{"shared", "secret"} {
		_, herr := w.e.ResourceHead(ctx, "matches", n, li)
		lg, lerr := w.e.ResourceLog(ctx, "matches", n, "", "", 100, li)
		ls := 0
		if lg != nil {
			ls = lg.Status
		}
		b, berr := w.e.OpenBlob(ctx, "matches", n, "1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", li)
		bs := 0
		if b != nil {
			bs = b.Status
		}
		t.Logf("%s: head %v; log %d %v; blob %d %v", n, herr, ls, lerr, bs, berr)
		if n == "secret" && (v75Status(herr) == 410 || ls == 410 || bs == 410 || v75Status(lerr) == 410 || v75Status(berr) == 410) {
			t.Errorf("LEAK: purged %s answered 410 to li, whose /resource rule refuses it", n)
		}
		if n == "shared" && ls != 410 {
			t.Errorf("purged shared, whose name li's rules allow: log %d %v, want 410", ls, lerr)
		}
	}
}

// §7.9 Content, HTTP-76: a blob's 302 to a reader judged per revision names
// an epoch of a revision it may read, never one only hidden revisions have.
// v1, visible, references the blob and was written before matches was
// sealed (no epoch of its own); h2, hidden, references it under epoch 1;
// matches then rotates to epoch 2. The view's reader is sent to the epoch
// its own request fixes for v1 (2), not to h2's (1), and again once fixed;
// a blob only hidden revisions reference is answered as a read-rule
// failure.
func TestV089AdvBlobRedirectHiddenEpoch(t *testing.T) {
	w := newV75World(t, v75Opts{})
	ctx := context.Background()
	data := []byte("shared blob")
	bid, nonce := advUpload(t, w, "derby", data)
	w.put("matches", "derby", map[string]any{"team": "a", "title": "v1", "b": advRef(bid, nonce, data)})
	w.patchConfig("matches", map[string]any{"op": "add", "path": "/encryption", "value": map[string]any{"level": "sealed"}})
	v89Put(w, "derby", map[string]any{"team": "b", "secret": "S", "b": advRef(bid, nonce, data)})
	only := []byte("hidden only")
	hb, hn := advUpload(t, w, "derby", only)
	v89Put(w, "derby", map[string]any{"team": "b", "secret": "S", "b": advRef(bid, nonce, data), "c": advRef(hb, hn, only)})
	v89Put(w, "derby", map[string]any{"team": "a", "title": "v3"})
	w.patchConfig("matches", map[string]any{"op": "replace", "path": "/encryption", "value": map[string]any{"level": "sealed", "epoch": 2.0}})

	// An unrestricted reader is sent to the latest fixed epoch: h2's.
	if b, err := w.e.OpenBlob(ctx, "matches", "derby", bid, w.admin); err != nil || b.Status != 302 || b.Epoch != 1 {
		t.Fatalf("admin: %+v %v, want 302 to epoch 1", b, err)
	}
	li := advDocReader(w)
	ans, err := w.e.Keys(ctx, "matches", li, KeysRequest{})
	if err != nil {
		t.Fatal(err)
	}
	var view string
	for _, k := range ans.Keys {
		if v, _ := k["view"].(string); v != "" {
			view = v
		}
	}
	if view == "" {
		t.Fatalf("no view: %v", ans.Keys)
	}
	vc, err := w.e.ViewCredentials(ctx, "matches", view, li)
	if err != nil {
		t.Fatal(err)
	}
	// Its own URL redirects to the view's (contentRedirect).
	for range 2 {
		b, err := w.e.OpenBlob(ctx, "matches", "derby", bid, vc)
		if err != nil || b.Status != 302 || b.Epoch != 2 {
			t.Fatalf("the blob v1 references: %+v %v, want 302 to epoch 2", b, err)
		}
	}
	if b, err := w.e.OpenSealedBlob(ctx, "matches", "derby", bid, "2", vc); err != nil || b.Status != 200 {
		t.Errorf("the blob under epoch 2 at the view URL: %+v %v", b, err)
	} else {
		b.Close()
	}
	// Nor is it served under the epoch only h2 has.
	if b, err := w.e.OpenSealedBlob(ctx, "matches", "derby", bid, "1", vc); v75Status(err) != 404 {
		if b != nil {
			b.Close()
		}
		t.Errorf("the blob under h2's epoch 1 at the view URL: %+v %v, want 404", b, err)
	}
	if b, err := w.e.OpenBlob(ctx, "matches", "derby", hb, vc); v75Status(err) != 404 && (b == nil || b.Status != 404) {
		t.Errorf("a blob only hidden revisions reference: %+v %v, want 404", b, err)
	}
	// Now v1's epoch is fixed, the latest for every reader.
	if b, err := w.e.OpenBlob(ctx, "matches", "derby", bid, w.admin); err != nil || b.Status != 302 || b.Epoch != 2 {
		t.Errorf("admin, after: %+v %v, want 302 to epoch 2", b, err)
	}
}

// The same through a real import batch: step 2.2 judges the head the
// batch itself wrote, recording a name whose imported document the
// importer's read rules allow, and not one they hide.
func TestV088AdvPurgeFollowImportBatch(t *testing.T) {
	w := newV75World(t, v75Opts{})
	ctx := context.Background()
	imp := w.cred(w.kPriv, map[string]any{"kid": "k", "sub": "svc:importer", "ns": []any{"matches"},
		"can": []any{"read", "create", "append", "purge"}, "rules": []any{map[string]any{"any": []any{
			map[string]any{"not": map[string]any{"op": "test", "path": "/action", "value": "read"}},
			map[string]any{"op": "test", "path": "/doc/team", "value": "a"}}}}})
	src := map[string]any{"origin": "https://staging.example", "ns": "matches", "at": "1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "bundle": "1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	item := func(name, team string) Item {
		return Item{Resource: name, IfNoneMatch: true, Steps: []Step{{Patches: []any{
			map[string]any{"op": "add", "path": "", "value": map[string]any{"team": team}}}}}}
	}
	if _, err := w.e.Batch(ctx, Request{NS: "matches", Cred: imp}, []Item{item("seen", "a"), item("hidden", "b")}, nil, src, false); err != nil {
		t.Fatal(err)
	}
	var rows []string
	w.inTx(func(t *tx) {
		q, err := t.Query(`SELECT name FROM purge_follow_names ORDER BY name`)
		t.must(err)
		defer q.Close()
		for q.Next() {
			var s string
			t.must(q.Scan(&s))
			rows = append(rows, s)
		}
	})
	if len(rows) != 1 || rows[0] != "seen" {
		t.Fatalf("recorded %v, want [seen]", rows)
	}
}
