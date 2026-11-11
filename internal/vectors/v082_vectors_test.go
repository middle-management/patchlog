package vectors_test

// The candidate vectors of docs/VECTORS-PROPOSED.md for §I.22's list
// (C.1–C.3, computed independently from the v0.82 text), each computed
// here through the reference's production code and compared with the
// candidate. testdata/candidates.json holds the candidates as the document
// gives them (extracted, never computed, and never rewritten by -update);
// a value the reference computes otherwise is a failure here, reported to
// the writer as contested, never a candidate overwritten with ours.

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/bundle"
	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/derived"
	"github.com/middle-management/patchlog/internal/grant"
	"github.com/middle-management/patchlog/internal/grantcheck"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/seal"
	"github.com/middle-management/patchlog/internal/vectors/golden"
)

// candidatesFile is testdata/candidates.json.
type candidatesFile struct {
	C1 struct {
		Plaintexts     map[string]string
		Rows           []struct{ Payload, Key, PL, Plaintext, Tag, PaddedTag string }
		NamespaceEvent string
		Closing        string
	} `json:"C.1"`
	C2 struct {
		Q, Sort, CanonicalQuery, View string
		ViewKeyKn, ViewKeyKr          string
		Whole, Item                   struct{ Header, Plaintext, JWE, PaddedTag string }
		Served, Rejected              string
	} `json:"C.2"`
	C3 struct {
		Grant string
		Rows  []struct{ Change, SHA256, Rule string }
	} `json:"C.3"`
}

// loadCandidates reads testdata/candidates.json. It only reads: the file
// is the candidates' text, and no run of the reference writes it.
func loadCandidates(t *testing.T) candidatesFile {
	t.Helper()
	var f candidatesFile
	if !golden.Load(t, "candidates", &f) {
		t.Fatal("testdata/candidates.json is missing")
	}
	return f
}

// v081NamespaceEventTag is the tag v0.81's candidate P.5 gave the
// namespace event for ns_id₂ under the range form, pl
// {"ns":"demo","range":[ns_id₁,ns_id₂]}, which v0.27.0 reproduced and
// v0.82 no longer accepts (§E.2.2).
const v081NamespaceEventTag = "yXiFzJA38ZWcmOAZrHWjWA"

// v82vecSSE answers GET path with the SSE events given, each "type", "id"
// and data, and then ends the stream.
func v82vecSSE(t *testing.T, path string, events ...[3]string) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != path {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-store")
		for _, ev := range events {
			if ev[0] != "" {
				fmt.Fprintf(w, "event: %s\n", ev[0])
			}
			if ev[1] != "" {
				fmt.Fprintf(w, "id: %s\n", ev[1])
			}
			fmt.Fprintf(w, "data: %s\n\n", ev[2])
		}
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

// C.1 (§E.2.2), keys and bytes: the resource purge and prune events under
// K_r with the pl of seal.ResourceEventPL, {kind, name, ns} as v0.81 had
// it, and the namespace event for ns_id₂ under K_n with the pl of
// seal.NamespaceEventPL, {event, ns} (v0.82), each with I.7's K_e, kid
// demo#3 and the IV c0 … cb through seal.SealWithIV, unpadded and padded;
// the namespace event's JWE in full. Then the reference's reader, the
// client with demo#3's epoch key and nothing else, is given the vectors as
// a stream serves them: it opens all three, and refuses v0.81's range form
// of the namespace event, with the entry and with the range's own
// plaintext.
func TestV082C1Events(t *testing.T) {
	t.Parallel()
	p := loadCandidates(t).C1
	i19 := loadAddendumI(t).I19
	kr, err := seal.ResourceKey(seq(0x00), "demo", "derby")
	if err != nil {
		t.Fatal(err)
	}
	kn, err := seal.NamespaceKey(seq(0x00), "demo")
	if err != nil {
		t.Fatal(err)
	}
	nsentry2 := i19.Plaintexts["nsentry₂"]
	cases := []struct {
		key []byte
		pl  seal.PL
		pt  string
	}{
		{kr, seal.ResourceEventPL("demo", "derby", seal.KindPurge), p.Plaintexts["purge"]},
		{kr, seal.ResourceEventPL("demo", "derby", seal.KindPrune), p.Plaintexts["prune"]},
		{kn, seal.NamespaceEventPL("demo", nsID2), nsentry2},
	}
	if len(p.Rows) != len(cases) || p.Rows[2].Plaintext != "§I.19's `nsentry₂`" {
		t.Fatalf("%d rows in candidates.json, want %d, the last of §I.19's nsentry₂", len(p.Rows), len(cases))
	}
	jwes := make([]string, len(cases))
	for i, r := range p.Rows {
		c := cases[i]
		if got := string(jsonv.Canonical(jsonv.FromGo(map[string]any(c.pl)))); got != r.PL {
			t.Errorf("%s: pl %s, want %s", r.Payload, got, r.PL)
		}
		if want := map[string][]byte{"K_r": kr, "K_n": kn}[r.Key]; !bytes.Equal(want, c.key) {
			t.Errorf("%s: the candidate's key is %s", r.Payload, r.Key)
		}
		jwe, tag, padded := sealedTags(t, c.key, c.pl, []byte(c.pt))
		jwes[i] = jwe
		if tag != r.Tag || padded != r.PaddedTag {
			t.Errorf("%s: tags %s and %s padded, want %s and %s", r.Payload, tag, padded, r.Tag, r.PaddedTag)
		}
	}
	if jwes[2] != p.NamespaceEvent {
		t.Errorf("the namespace event is\n%s\nwant\n%s", jwes[2], p.NamespaceEvent)
	}
	// A resource event's plaintext is its namespace entry without id and
	// prev (§7.3).
	for _, k := range []string{"purge", "prune"} {
		m := jsonv.MustParse([]byte(p.Plaintexts[k])).(map[string]any)
		if _, has := m["id"]; has || m["kind"] != k || m["resource"] != "derby" {
			t.Errorf("the %s plaintext: %s", k, p.Plaintexts[k])
		}
		if _, has := m["prev"]; has {
			t.Errorf("the %s plaintext carries prev", k)
		}
	}

	// The reader: the client, holding demo#3's K_e alone.
	keys := client.StaticKeys()
	keys.Add("demo#3", seq(0x00))
	nsEvents := func(jwe string) ([]client.NSEntry, error) {
		c, err := client.New(v82vecSSE(t, "/ns/demo/events", [3]string{"head", nsID2, jwe}), client.WithKeys(keys))
		if err != nil {
			t.Fatal(err)
		}
		var got []client.NSEntry
		err = c.NSEvents(ctx, "demo", nsID1, func(e client.NSEntry) error { got = append(got, e); return nil })
		return got, err
	}
	if got, err := nsEvents(p.NamespaceEvent); err != nil || len(got) != 1 || got[0].ID != nsID2 || got[0].Prev != nsID1 || got[0].Kind != "head" || got[0].Resource != "derby" || got[0].Target != idG {
		t.Errorf("the candidate's namespace event: %+v %v, want nsentry₂", got, err)
	}
	// v0.81's form: the same entry, and the range's own plaintext, under
	// the range [ns_id₁, ns_id₂]. The first is v0.81's vector.
	old, tag, _ := sealedTags(t, kn, seal.RangePL("demo", nsID1, nsID2), []byte(nsentry2))
	if tag != v081NamespaceEventTag {
		t.Fatalf("v0.81's namespace event has tag %s, want %s", tag, v081NamespaceEventTag)
	}
	oldRange, _, _ := sealedTags(t, kn, seal.RangePL("demo", nsID1, nsID2), []byte("["+nsentry2+"]"))
	for what, jwe := range map[string]string{"v0.81's namespace event": old, "a one-entry range as an event": oldRange} {
		if got, err := nsEvents(jwe); !errors.Is(err, seal.ErrMismatch) || len(got) != 0 {
			t.Errorf("%s: %+v %v, want a mismatch", what, got, err)
		}
	}
	// Resource events keep {kind, name, ns} (§E.2.2's table and C.1's own
	// rows; C.1's closing sentence reads as if that form were refused):
	// the client opens the candidate's rows, and no namespace event's.
	resEvents := func(typ, jwe string) (client.Event, error) {
		c, err := client.New(v82vecSSE(t, "/r/demo/derby/events", [3]string{typ, "", jwe}), client.WithKeys(keys))
		if err != nil {
			t.Fatal(err)
		}
		var got client.Event
		err = c.ResourceEvents(ctx, "demo", "derby", idT, func(e client.Event) error { got = e; return nil })
		return got, err
	}
	for i, k := range []string{"purge", "prune"} {
		ev, err := resEvents(k, jwes[i])
		if err != nil || ev.Type != k || ev.ID != "" || !bytes.Equal(jsonv.Canonical(ev.Data), []byte(p.Plaintexts[k])) {
			t.Errorf("the candidate's %s event: %+v %v", k, ev, err)
		}
	}
	if ev, err := resEvents("prune", jwes[0]); err == nil {
		t.Errorf("the purge event served as a prune event: %+v, want refused", ev)
	}
	if ev, err := resEvents("purge", p.NamespaceEvent); err == nil {
		t.Errorf("the namespace event served as a purge event: %+v, want refused", ev)
	}
	if !strings.Contains(p.Closing, `{"kind":…,"name":…,"ns":…}`) {
		t.Errorf("C.1's closing sentence changed: %s", p.Closing)
	}
}

// TestV082C1EventsServed (C.1, §E.2.2, §7.3), forms: in sealedDemo, bob
// prunes at c and purges. The namespace event for the last entry is served
// under K_n with pl {ns, event: id}, its plaintext that entry as the range
// gives it, and under no range's pl; the reference's client reads the same
// stream as that entry. The purge and prune events are served under K_r
// with pl {kind, name, ns}, their plaintext the namespace entry without id
// and prev, with the members of C.1's purge and prune.
func TestV082C1EventsServed(t *testing.T) {
	t.Parallel()
	p := loadCandidates(t).C1
	d := newSealedDemo(t, loadAddendumI(t).I19.Plaintexts["nsdoc"], p.Plaintexts)

	// The resource's events after the tombstone, streamed live: the
	// prune's, read before the purge, then the purge's.
	resEvents := d.stream(t, "/r/demo/derby/events", d.tomb)
	d.s.Clock.Advance(50 * time.Minute)
	if _, err := d.bc.Prune(ctx, "demo", "derby", client.PruneRequest{Horizon: d.c}); err != nil {
		t.Fatal(err)
	}
	_, pruneData := resEvents()
	if _, err := d.bc.Purge(ctx, "demo", "derby", d.tomb, false); err != nil {
		t.Fatal(err)
	}
	_, purgeData := resEvents()
	h, err := d.bc.NSHead(ctx, "demo")
	if err != nil {
		t.Fatal(err)
	}
	pt := d.open(t, "the range from the start", string(d.get(t, "/ns/demo/rev/"+h.ID+"/log")), d.kn, seal.RangePL("demo", "", h.ID))
	entries, _ := jsonv.MustParse(pt).([]any)
	var purge, prune map[string]any
	for _, e := range entries {
		switch m := e.(map[string]any); m["kind"] {
		case "purge":
			purge = m
		case "prune":
			prune = m
		}
	}
	if purge == nil || prune == nil {
		t.Fatalf("the namespace log lacks a prune or purge entry: %s", pt)
	}

	// A namespace event: its one entry, under K_n, with its own pl,
	// {ns, event: id} (§E.2.2, v0.82), and not v0.81's range.
	last := entries[len(entries)-1].(map[string]any)
	prev := last["prev"].(string)
	id, data := d.stream(t, "/ns/demo/events", prev)()
	if id != last["id"] {
		t.Fatalf("the event after %s is %s, want %v", prev, id, last["id"])
	}
	if pt := d.open(t, "a namespace event", data, d.kn, seal.NamespaceEventPL("demo", id)); !bytes.Equal(pt, jsonv.Canonical(last)) {
		t.Errorf("the namespace event is\n%s\nthe range's entry\n%s", pt, jsonv.Canonical(last))
	}
	if _, err := seal.OpenExpect(data, d.kn, "demo#3", seal.RangePL("demo", prev, id)); !errors.Is(err, seal.ErrMismatch) {
		t.Errorf("the namespace event under v0.81's range pl: %v, want a mismatch", err)
	}
	if hd, err := seal.ParseHeader(data); err != nil || string(jsonv.Canonical(jsonv.FromGo(map[string]any(hd.PL)))) != `{"event":"`+id+`","ns":"demo"}` {
		t.Errorf("the namespace event's pl: %+v %v", hd, err)
	}
	// The reference's client reads the stream as that entry.
	ectx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	stop := errors.New("read")
	var got client.NSEntry
	if err := d.bc.NSEvents(ectx, "demo", prev, func(e client.NSEntry) error { got = e; return stop }); !errors.Is(err, stop) || got.ID != id || got.Prev != prev || got.Kind != last["kind"] {
		t.Errorf("the client's NSEvents: %+v %v, want entry %s", got, err, id)
	}

	// Resource events under K_r: the purge and prune entries without id
	// and prev (§7.3).
	for _, ev := range []struct {
		kind, data string
		e          map[string]any
	}{{"prune", pruneData, prune}, {"purge", purgeData, purge}} {
		want := map[string]any{}
		for k, v := range ev.e {
			if k != "id" && k != "prev" {
				want[k] = v
			}
		}
		pt := d.open(t, ev.kind+" event", ev.data, d.kr, seal.ResourceEventPL("demo", "derby", ev.kind))
		if !bytes.Equal(pt, jsonv.Canonical(want)) {
			t.Errorf("the %s event is\n%s\nwant its entry without id and prev\n%s", ev.kind, pt, jsonv.Canonical(want))
		}
		d.like(t, ev.kind+" event", pt, ev.kind, false)
	}
}

// C.2 (SERVICES §E.2.6, §A.5): the view string an index on its own origin
// serves demo at, for I.8's gs and ns_id₂ and the query q = "a b", sort =
// "/title", built as the index builds it (the path, then
// derived.CanonicalQuery without min); the view keys of K_n and K_r
// (seal.ViewKey); the whole response and the hit's values sealed under
// them with the pl of derived.View, kid demo#3 and the IV c0 … cb, in full
// and by their padded tags; derived.SealView and SealItem, which draw
// their own IVs, give the same headers and plaintexts; derived.OpenView
// and OpenItem open the candidate's JWEs, and reject each under the four
// altered views, as they reject a JWE sealed for any of those. No view
// carries min.
func TestV082C2ViewKey(t *testing.T) {
	t.Parallel()
	p := loadCandidates(t).C2
	gs := grantcheck.SubjectSetID([]string{"group:match-desk", "user:anna"}) // I.8's
	// The premise is illustrative, like §I.19's plaintexts: I.8's gs is a
	// set of two principals, and the reference serves a response sealed
	// whole only at a gs every reader of which reads the namespace whole,
	// that of reads:demo (SERVICES §E.2.6 Whole-response sealing, §A.4).
	// The bytes don't depend on it.
	if whole := grantcheck.SubjectSetID([]string{"reads:demo"}); whole == gs {
		t.Fatalf("I.8's gs is that of reads:demo")
	}
	vals := url.Values{"q": {p.Q}, "sort": {p.Sort}, "min": {nsID2}}
	cq := derived.CanonicalQuery(vals, "min")
	if cq != "?"+p.CanonicalQuery {
		t.Errorf("the canonical query is %s, want ?%s", cq, p.CanonicalQuery)
	}
	view := "/demo/g/" + gs + "/at/" + nsID2 + cq
	if view != p.View {
		t.Fatalf("view\n%s\nwant\n%s", view, p.View)
	}
	if strings.Contains(view, "min") {
		t.Errorf("the view carries min: %s", view)
	}
	kn, _ := seal.NamespaceKey(seq(0x00), "demo")
	kr, _ := seal.ResourceKey(seq(0x00), "demo", "derby")
	vkn, err := seal.ViewKey(kn, view)
	if err != nil || hex.EncodeToString(vkn) != p.ViewKeyKn {
		t.Errorf("the view key of K_n is %x %v, want %s", vkn, err, p.ViewKeyKn)
	}
	vkr, err := seal.ViewKey(kr, view)
	if err != nil || hex.EncodeToString(vkr) != p.ViewKeyKr {
		t.Errorf("the view key of K_r is %x %v, want %s", vkr, err, p.ViewKeyKr)
	}

	v := derived.View{NS: "demo", Target: view}
	key := derived.Key{NS: "demo", Epoch: 3, K: seq(0x00)}
	keyOf := func(kid string) []byte {
		if kid == "demo#3" {
			return seq(0x00)
		}
		return nil
	}
	itemKey := derived.ItemKey(keyOf, "demo", "derby")
	header := func(jwe string) string {
		b, err := base64.RawURLEncoding.DecodeString(jwe[:strings.IndexByte(jwe, '.')])
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	tag := func(jwe string) string { return jwe[strings.LastIndexByte(jwe, '.')+1:] }
	for _, c := range []struct {
		what string
		want struct{ Header, Plaintext, JWE, PaddedTag string }
		vk   []byte
		pl   seal.PL
		seal func(derived.Key, any) (string, error)
		open func(string, derived.View) ([]byte, error)
	}{
		{"the whole response", p.Whole, vkn, v.PL(),
			func(k derived.Key, body any) (string, error) { return derived.SealView(k, v, body) },
			func(jwe string, v derived.View) ([]byte, error) { return derived.OpenView(jwe, keyOf, v) }},
		{"the hit", p.Item, vkr, v.ItemPL("demo", "derby"),
			func(k derived.Key, body any) (string, error) { return derived.SealItem(k, v, "derby", body) },
			func(jwe string, v derived.View) ([]byte, error) {
				return derived.OpenItem(jwe, itemKey, v, "demo", "derby")
			}},
	} {
		pt := []byte(c.want.Plaintext)
		if !bytes.Equal(jsonv.Canonical(jsonv.MustParse(pt)), pt) {
			t.Errorf("%s: the plaintext isn't canonical JSON", c.what)
		}
		jwe, err := seal.SealWithIV(c.vk, "demo#3", c.pl, pt, fixedIV)
		if err != nil {
			t.Fatal(err)
		}
		if jwe != c.want.JWE || header(jwe) != c.want.Header {
			t.Errorf("%s seals as\n%s\nwant\n%s", c.what, jwe, c.want.JWE)
		}
		padded, err := seal.SealWithIV(c.vk, "demo#3", c.pl, seal.Pad(pt), fixedIV)
		if err != nil {
			t.Fatal(err)
		}
		if tag(padded) != c.want.PaddedTag {
			t.Errorf("%s padded: tag %s, want %s", c.what, tag(padded), c.want.PaddedTag)
		}
		// The services' sealing, IV apart: the same header, the same
		// plaintext, padded or not.
		for _, pad := range []bool{false, true} {
			k := key
			k.Pad = pad
			own, err := c.seal(k, jsonv.MustParse(pt))
			if err != nil {
				t.Fatal(err)
			}
			if header(own) != c.want.Header {
				t.Errorf("%s: the service's header is %s, want %s", c.what, header(own), c.want.Header)
			}
			want := pt
			if pad {
				want = seal.Pad(pt) // padding is the reader's to trim (§E.2.2)
			}
			if got, err := c.open(own, v); err != nil || !bytes.Equal(got, want) {
				t.Errorf("%s as the service seals it (pad %v) opens to %s %v, want %s", c.what, pad, got, err, want)
			}
		}
		// The reader opens the candidate's JWE at the URL fetched, and at
		// no other spelling of it.
		if got, err := c.open(c.want.JWE, v); err != nil || !bytes.Equal(got, pt) {
			t.Errorf("%s: the candidate opens to %s %v, want %s", c.what, got, err, pt)
		}
		path, _, _ := strings.Cut(view, "?")
		altered := map[string]string{
			"+ for the space":                 path + "?q=a+b&sort=%2Ftitle",
			"lowercase hex":                   path + "?q=a%20b&sort=%2ftitle",
			"the parameters in another order": path + "?sort=%2Ftitle&q=a%20b",
			"a scheme and host":               "https://index.example" + view,
		}
		if len(altered) != 4 || !strings.Contains(p.Rejected, "`+` for the space, lowercase hex (`%2ftitle`) or the parameters in another order, or with a scheme and host") {
			t.Fatalf("C.2's rejected views changed: %s", p.Rejected)
		}
		for what, target := range altered {
			av := derived.View{NS: "demo", Target: target}
			// A JWE whose pl.view is the altered form, however it was
			// keyed, doesn't match the URL fetched.
			avk, _ := seal.ViewKey(map[bool][]byte{true: kn, false: kr}[c.what == "the whole response"], target)
			apl := seal.PL{}
			for k, x := range c.pl {
				apl[k] = x
			}
			apl["view"] = target
			for keyed, k := range map[string][]byte{"the altered view's key": avk, "the fetched view's key": c.vk} {
				aj, err := seal.SealWithIV(k, "demo#3", apl, pt, fixedIV)
				if err != nil {
					t.Fatal(err)
				}
				if got, err := c.open(aj, v); !errors.Is(err, seal.ErrMismatch) {
					t.Errorf("%s with pl.view with %s, under %s: %s %v, want a mismatch", c.what, what, keyed, got, err)
				}
			}
			// And the candidate's JWE isn't that of the altered URL.
			if got, err := c.open(c.want.JWE, av); !errors.Is(err, seal.ErrMismatch) {
				t.Errorf("%s read as the view with %s: %s %v, want a mismatch", c.what, what, got, err)
			}
			// The service never serves a 200 there: each altered query
			// canonicalises to the view's (§A.5).
			if _, q, ok := strings.Cut(target, "?"); ok {
				qv, err := url.ParseQuery(q)
				if err != nil || derived.CanonicalQuery(qv, "min") != cq {
					t.Errorf("the query with %s canonicalises to %s %v, want %s", what, derived.CanonicalQuery(qv, "min"), err, cq)
				}
			}
		}
	}
	// The hit as served per entry: its clear members, and sealed.
	served := fmt.Sprintf(p.Served, p.Item.JWE)
	m, ok := jsonv.MustParse([]byte(served)).(map[string]any)
	if !ok || !bytes.Equal(jsonv.Canonical(m), []byte(served)) || m["sealed"] != p.Item.JWE || m["resource"] != "derby" || m["id"] != idC {
		t.Errorf("the served hit: %s", served)
	}
	whole := jsonv.MustParse([]byte(p.Whole.Plaintext)).(map[string]any)
	hit := whole["hits"].([]any)[0].(map[string]any)
	vals2 := jsonv.MustParse([]byte(p.Item.Plaintext)).(map[string]any)
	for k, x := range hit {
		if _, clear := m[k]; clear {
			if !jsonv.Equal(m[k], x) {
				t.Errorf("the served hit's %s is %v, the whole response's %v", k, m[k], x)
			}
		} else if !jsonv.Equal(vals2[k], x) {
			t.Errorf("the hit's sealed %s is %v, the whole response's %v", k, vals2[k], x)
		}
	}
	if len(hit) != len(m)-1+len(vals2) {
		t.Errorf("the hit's members split into %d clear and %d sealed, of %d", len(m)-1, len(vals2), len(hit))
	}
}

// v82vecAuthority is the authority block of a Biscuit token, cut out of
// its bytes (Biscuit { rootKeyId? = 1; authority = 2; … }) in base64url
// without padding, the stored form of §C.3.1: for a token the grant
// package refuses to decode, whose block it therefore never encodes.
func v82vecAuthority(t *testing.T, token string) string {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(token, "="))
	if err != nil {
		t.Fatal(err)
	}
	for len(b) > 0 {
		tagv, n := binary.Uvarint(b)
		if n <= 0 {
			t.Fatal("token: bad tag")
		}
		b = b[n:]
		switch tagv & 7 {
		case 0:
			_, n := binary.Uvarint(b)
			if n <= 0 {
				t.Fatal("token: bad varint")
			}
			b = b[n:]
		case 2:
			l, n := binary.Uvarint(b)
			if n <= 0 || uint64(len(b)-n) < l {
				t.Fatal("token: bad length")
			}
			if tagv>>3 == 2 {
				return base64.RawURLEncoding.EncodeToString(b[n : n+int(l)])
			}
			b = b[n+int(l):]
		default:
			t.Fatalf("token: wire type %d", tagv&7)
		}
	}
	t.Fatal("token: no authority block")
	return ""
}

// C.3 (§G.4.1): three changes to §I.20's bundle, each matched to the
// candidate's sha-256 and then rejected whole by the bundle Reader, at the
// line and for the rule the candidate names: a grant line whose grant
// isn't the id of its root (the id of §I.21's ops-2027 root block, in the
// grant line and both history lines); one whose stored block's grant_block
// isn't canonical(root) (the authority block of §I.21's token with sub
// first, validly signed); and a header member §G.4.1 doesn't define. The
// Writer refuses to write the first two.
func TestV082C3BundleRejections(t *testing.T) {
	t.Parallel()
	p := loadCandidates(t).C3
	ai := loadAddendumI(t)
	b := ai.I20.Bundle
	if d, err := readBundle(b); err != nil || d != ai.I20.Digest {
		t.Fatalf("§I.20's bundle, the control: %s %v", d, err)
	}
	token := func(prefix string) string {
		for _, tk := range ai.I21 {
			if strings.HasPrefix(tk.Change, prefix) {
				return tk.Token
			}
		}
		t.Fatalf("no token of §I.21 starts %q", prefix)
		return ""
	}
	if len(p.Rows) != 3 {
		t.Fatalf("%d rows in candidates.json, want 3", len(p.Rows))
	}
	ls := strings.SplitAfter(b, "\n")

	// Row 1: the grant id, in three places.
	g27, err := grant.Decode(token("The root block names `kid` `ops-2027`"), 0)
	if err != nil {
		t.Fatal(err)
	}
	if g27.ID().String() != p.Grant {
		t.Errorf("the id of §I.21's ops-2027 root block is %s, the candidate's %s", g27.ID(), p.Grant)
	}
	if n := strings.Count(b, i4GrantID); n != 3 {
		t.Fatalf("§I.20's bundle names its grant %d times, want 3", n)
	}
	row1 := strings.ReplaceAll(b, i4GrantID, p.Grant)

	// Row 2: stored is another, validly signed authority block, whose
	// grant_block string has the root's members with sub first.
	stored := v82vecAuthority(t, token("The root block's string isn't canonical (`sub` first)"))
	old := i14Authority(t)
	if strings.Count(ls[1], `"stored":"`+old+`"`) != 1 {
		t.Fatal("§I.20's grant line doesn't carry I.14's authority block as stored")
	}
	row2 := ls[0] + strings.Replace(ls[1], `"stored":"`+old+`"`, `"stored":"`+stored+`"`, 1) + ls[2] + ls[3]

	// Row 3: the header with "x-note":"hi", canonical, after origin.
	if !strings.HasSuffix(ls[0], `"origin":"https://staging.example"}`+"\n") {
		t.Fatal("§I.20's header doesn't end with origin")
	}
	row3 := strings.TrimSuffix(ls[0], "}\n") + `,"x-note":"hi"}` + "\n" + ls[1] + ls[2] + ls[3]
	if hdr := strings.TrimSuffix(strings.SplitAfter(row3, "\n")[0], "\n"); string(jsonv.Canonical(jsonv.MustParse([]byte(hdr)))) != hdr {
		t.Fatal("the header with x-note isn't canonical")
	}

	for i, c := range []struct {
		rule string // the row's rule, which keeps the rows in step
		b    string
		line int
		msg  []string // what the Reader's reason says
	}{
		{"a grant line whose `grant` isn't the id of its `root`", row1, 2, []string{"grant is not the id of its root", i4GrantID}},
		{"a grant line whose `stored` block's `grant_block` isn't `canonical(root)`", row2, 2, []string{"stored block", "canonical(root)"}},
		{"a member §G.4.1 doesn't define", row3, 1, []string{"x-note"}},
	} {
		row := p.Rows[i]
		if row.Rule != c.rule {
			t.Fatalf("row %d (%s) is no %q row", i, row.Rule, c.rule)
		}
		if got := sha256Hex([]byte(c.b)); got != row.SHA256 {
			t.Errorf("%s: the bundle is sha-256 %s, want %s", row.Change, got, row.SHA256)
			continue
		}
		d, err := readBundle(c.b)
		var be *bundle.Error
		if err == nil || !errors.As(err, &be) {
			t.Errorf("%s: read with digest %s, %v; want rejected (%s)", row.Change, d, err, row.Rule)
			continue
		}
		if be.Line != c.line {
			t.Errorf("%s: rejected at line %d (%v), want line %d", row.Change, be.Line, err, c.line)
		}
		for _, m := range c.msg {
			if !strings.Contains(err.Error(), m) {
				t.Errorf("%s: rejected with %q, which doesn't say %q", row.Change, err, m)
			}
		}
	}

	// The Writer holds a grant line to its root too.
	for what, gl := range map[string]bundle.GrantLine{
		"another grant id":        {ID: p.Grant, Stored: old},
		"another stored block":    {ID: i4GrantID, Stored: stored},
		"I.4's line, the control": {ID: i4GrantID, Stored: old},
	} {
		var buf bytes.Buffer
		w, err := bundle.NewWriter(&buf, bundle.Header{Origin: "https://staging.example", Created: "2026-10-04T14:00:00Z", Authors: true,
			At: map[string]string{"matches": nsID2}, Docs: map[string]bundle.DocInfo{"matches/derby": {History: bundle.Full, Head: idC}},
			Access: map[string]string{"matches": bundle.AccessPrivate}})
		if err != nil {
			t.Fatal(err)
		}
		gl.Root = jsonv.MustParse([]byte(i4Root)).(map[string]any)
		gl.Key = bundle.KeyEntry{Kid: "ops-2026", Alg: "Ed25519", Pub: "A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg"}
		err = w.Line(bundle.Line{NS: "matches", GrantLine: &gl})
		if control := strings.HasSuffix(what, "the control"); control != (err == nil) {
			t.Errorf("the Writer, a grant line with %s: %v", what, err)
		}
	}
}
