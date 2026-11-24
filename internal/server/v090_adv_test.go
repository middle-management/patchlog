package server

// Adversarial review of v0.90, kept as regression tests: a public
// namespace ignores a partial reader's grant outside its view prefix, and
// under it hides what the grant's rules hide (§7 step 1, §7.9).

import (
	"strings"
	"testing"
)

// In a public namespace every non-view read with a partial reader's grant
// must answer byte-for-byte and header-for-header as anonymously (§7 step 1).
func TestV090AdvPublicGrantIgnored(t *testing.T) {
	for _, h := range []bool{false, true} {
		t.Run(map[bool]string{false: "visible", true: "hidden"}[h], func(t *testing.T) { v090AdvGrantIgnored(t, h) })
	}
}

func v090AdvGrantIgnored(t *testing.T, hidName bool) {
	w := newV75s(t, v75sOpts{matches: func(doc map[string]any) { doc["read"] = "public" }})
	reader := w.grant(w.k, "user:r", []string{"matches"}, []string{"read"}, map[string]any{"rules": []any{map[string]any{"all": []any{
		map[string]any{"op": "test", "path": "/resource", "schema": map[string]any{"pattern": "^[a-m]"}}, v87TeamA}}}})
	data := []byte("blob")
	bid := w.upload("matches", "doc", "text/plain", data, w.admin)
	ref := map[string]any{"$blob": bid, "type": "text/plain", "size": float64(len(data))}
	visible := w.v87Doc("matches", "doc", map[string]any{"team": "a", "file": ref})
	hidBid := w.upload("matches", "hid", "text/plain", data, w.admin)
	hid := w.v87Doc("matches", "hid", map[string]any{"team": "b", "mark": "HIDDEN-DOC", "file": map[string]any{"$blob": hidBid, "type": "text/plain", "size": float64(len(data))}})
	w.v87Doc("matches", "zzz-name", map[string]any{"team": "a", "mark": "HIDDEN-NAME"})
	nsHead := etagOf(w.get("/ns/matches", w.admin))
	if hidName {
		visible, bid = hid, hidBid
	}
	gid := ""
	for _, e := range w.nsLog("matches", w.admin) {
		if g, ok := e["grant"].(map[string]any); ok {
			gid, _ = g["id"].(string)
		}
	}
	_, view := w.cookie(reader)
	sub := func(p string) string {
		name := "doc"
		if hidName {
			name = "hid"
		}
		return strings.NewReplacer("{ns}", "matches", "{name}", name, "{id}", visible, "{bid}", bid, "{e}", "1", "{view}", view,
			"{at}", nsHead, "{gesture}", "aaaaaaaaaaaaaaaaaaaaaaaaaa", "{gid}", gid, "{$}", "").Replace(p)
	}
	for _, route := range v87Routes(t) {
		if strings.Contains(route, "{view}") || strings.Contains(route, "/events") || route == "/ns" || route == "/ns/{ns}/principal" {
			continue
		}
		path := sub(route)
		a, b := w.get(path, reader), w.get(path, "")
		for _, h := range []string{"Cache-Control", "CDN-Cache-Control", "Surrogate-Control", "ETag", "Location", "Vary", "Cache-Tag"} {
			if a.H.Get(h) != b.H.Get(h) {
				t.Errorf("%s: %s %q with the grant, %q anonymously", route, h, a.H.Get(h), b.H.Get(h))
			}
		}
		if a.Code != b.Code || string(a.Body) != string(b.Body) {
			t.Errorf("%s: %d %.200s with the grant, %d %.200s anonymously", route, a.Code, a.Body, b.Code, b.Body)
		}
	}
}

// Under a public namespace's view prefix a hidden revision, its raw form
// and a blob only it references are refused, never cached as public, and
// neither the view's log nor its heads name them; its long-poll is never
// public either.
func TestV090AdvPublicViewHiddenIDs(t *testing.T) {
	w := newV75s(t, v75sOpts{matches: func(doc map[string]any) { doc["read"] = "public" }})
	reader := w.grant(w.k, "user:r", []string{"matches"}, []string{"read"}, map[string]any{"rules": []any{v87TeamA}})
	data := []byte("blob-shared")
	bid := w.upload("matches", "doc", "text/plain", data, w.admin)
	ref := map[string]any{"$blob": bid, "type": "text/plain", "size": float64(len(data))}
	hdata := []byte("blob-hidden")
	hbid := w.upload("matches", "doc", "text/plain", hdata, w.admin)
	href := map[string]any{"$blob": hbid, "type": "text/plain", "size": float64(len(hdata))}
	w.v87Doc("matches", "doc", map[string]any{"team": "a", "file": ref})
	hid := w.v87Doc("matches", "doc", map[string]any{"team": "b", "mark": "HIDDEN-DOC", "file": ref, "h": href})
	w.upload("matches", "rawh", "text/plain", hdata, w.admin)
	w.v87Doc("matches", "rawh", map[string]any{"$blob": hbid, "type": "text/plain", "size": float64(len(hdata))})
	_, view := w.cookie(reader)
	base := "/ns/matches/view/" + view
	for _, p := range []string{
		base + "/r/doc/rev/" + hid,
		base + "/r/doc/rev/" + hid + "/raw",
		base + "/r/doc/blob/" + hbid,
	} {
		r := w.get(p, reader)
		if r.Code < 300 || r.Code >= 400 && r.Code != 404 {
			t.Errorf("%s: %d %.200s", p, r.Code, r.Body)
		}
		if strings.Contains(string(r.Body), "HIDDEN") || strings.Contains(string(r.Body), "blob-hidden") {
			t.Errorf("%s leaks: %s", p, r.Body)
		}
		if cc := r.H.Get("Cache-Control"); strings.Contains(cc, "public") {
			t.Errorf("%s: public %q", p, cc)
		}
	}
	nsHead := etagOf(w.get("/ns/matches", w.admin))
	r := w.get(base+"/at/"+nsHead+"/log", reader)
	if strings.Contains(string(r.Body), hid) || strings.Contains(string(r.Body), "rawh") {
		t.Errorf("view log leaks: %s", r.Body)
	}
	r = w.get(base+"/at/"+nsHead+"/heads?prefix=raw", reader)
	if strings.Contains(string(r.Body), "rawh") {
		t.Errorf("view heads leaks: %s", r.Body)
	}
	r = w.get(base+"/log?live=long-poll&since="+nsHead, reader)
	if strings.Contains(r.H.Get("Cache-Control"), "public") {
		t.Errorf("long-poll 204 public: %v", r.H)
	}
}

// Raw documents under a public namespace's view: the hidden one never
// redirects to its blob.
func TestV090AdvPublicViewRaw(t *testing.T) {
	w := newV75s(t, v75sOpts{matches: func(doc map[string]any) { doc["read"] = "public" }})
	reader := w.grant(w.k, "user:r", []string{"matches"}, []string{"read"}, map[string]any{"rules": []any{
		map[string]any{"op": "test", "path": "/doc/type", "value": "text/plain"}}})
	vd, hd := []byte("raw-visible"), []byte("raw-hidden")
	vb := w.upload("matches", "rawv", "text/plain", vd, w.admin)
	hb := w.upload("matches", "rawh", "text/html", hd, w.admin)
	vid := w.v87Doc("matches", "rawv", map[string]any{"$blob": vb, "type": "text/plain", "size": float64(len(vd))})
	hid := w.v87Doc("matches", "rawh", map[string]any{"$blob": hb, "type": "text/html", "size": float64(len(hd))})
	_, view := w.cookie(reader)
	base := "/ns/matches/view/" + view
	expect(t, w.get("/r/matches/rawh/rev/"+hid+"/raw"), 302) // anonymous first: warms caches
	expect(t, w.get("/r/matches/rawh/blob/"+hb), 200)
	r := w.get(base+"/r/rawv/rev/"+vid+"/raw", reader)
	if r.Code != 302 || !strings.HasPrefix(r.H.Get("Location"), base+"/") {
		t.Errorf("visible raw: %d %v", r.Code, r.H)
	}
	expect(t, w.get(base+"/r/rawv/blob/"+vb, reader), 200)
	for _, p := range []string{base + "/r/rawh/rev/" + hid + "/raw", base + "/r/rawh/blob/" + hb, base + "/r/rawh/rev/" + hid} {
		r := w.get(p, reader)
		if r.Code != 404 || r.H.Get("Location") != "" || strings.Contains(string(r.Body), "raw-hidden") {
			t.Errorf("%s: %d %v %s", p, r.Code, r.H, r.Body)
		}
	}
}
