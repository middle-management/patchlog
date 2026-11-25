package client_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/seal"
)

// v0.89: filtered reads and /doc read rules at sealed, through derived
// keys (§E.2.1, §E.2.2, §E.2.3, §7.9). In sealed namespace s:
//
//	a1  team a, references a blob        visible
//	b1  team b                           hidden
//	x   genesis team b, then team a      x1 hidden, x2 visible (its parent hidden)
//
// The partial reader's grant reads /doc/team "a". It gets only its view's
// K_view from /keys; its filtered range and /heads are JWEs under it that
// carry the K_rev of a1 and x2, a1's K_log (genesis) but not x2's (hidden
// parent), and a1's blob's K_blob. With those it opens a1's and x2's
// documents and a1's blob, and nothing of b1 or x1, nor x2's patches.
// Unrestricted and fixed-name readers keep K_e and K_r.
func TestV089SealedPartialReader(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{Auth: true, KeyStore: keyStore(t)})
	k := clienttest.NewKey("k")
	must(s.Client(t, client.WithBearer(s.OperatorGrant(t, "s"))).CreateNamespace(ctx, "s",
		map[string]any{"read": "grant", "keys": []any{k.Entry("*")}, "encryption": map[string]any{"level": "sealed"}}))
	adminGrant := k.Grant(t, s.Now(), "user:a", []string{"s"}, []string{"read", "create", "append"})
	admin := s.Client(t, client.WithBearer(adminGrant), client.WithKeys(client.NewKeys(nil)))

	data := []byte("the blob of a1")
	bid := must(admin.UploadBlob(ctx, "s", "a1", "text/plain", "", data))
	ref := map[string]any{"$blob": bid, "type": "text/plain", "size": float64(len(data))}
	a1 := must(admin.Create(ctx, "s", "a1", nonced(client.GenesisPatches(map[string]any{"team": "a", "file": ref, "mark": "A1"})))).ID
	b1 := must(admin.Create(ctx, "s", "b1", nonced(client.GenesisPatches(map[string]any{"team": "b", "mark": "HIDDEN-B1"})))).ID
	x1 := must(admin.Create(ctx, "s", "x", nonced(client.GenesisPatches(map[string]any{"team": "b", "mark": "HIDDEN-X1"})))).ID
	x2 := must(admin.Append(ctx, "s", "x", x1, nonced(ops(op("replace", "/team", "a"), op("replace", "/mark", "X2"))))).ID

	readerGrant := k.Grant(t, s.Now(), "user:r", []string{"s"}, []string{"read"},
		map[string]any{"rules": []any{map[string]any{"op": "test", "path": "/doc/team", "value": "a"}}})
	reader := s.Client(t, client.WithBearer(readerGrant), client.WithKeys(client.NewKeys(nil)))

	// /keys: the view's K_view alone (§E.2.3).
	ka := must(reader.FetchKeysAnswer(ctx, "s", nil, nil))
	if len(ka.Keys) != 1 || ka.Keys[0].View == "" || ka.Keys[0].Resource != "" || ka.Keys[0].Kid != "s#1" {
		t.Fatalf("the partial reader's keys: %+v", ka.Keys)
	}
	view, kview := ka.Keys[0].View, ka.Keys[0].Key

	// The filtered range and /heads, through the client.
	es, fa, err := reader.FilteredLog(ctx, "s", "")
	if err != nil || fa.View != view {
		t.Fatalf("FilteredLog: %v %+v (view %s)", err, fa, view)
	}
	var shown []string
	for _, e := range es {
		if e.Kind == "head" {
			shown = append(shown, e.Resource+"@"+e.Target)
		}
	}
	if want := []string{"a1@" + a1, "x@" + x2}; !slices.Equal(shown, want) {
		t.Fatalf("visible heads in the range %v, want %v", shown, want)
	}
	heads, hfa, err := reader.HeadsPrefix(ctx, "s", fa.End, "")
	if err != nil || hfa.View != view || len(heads) != 2 || heads[0].Resource != "a1" || heads[1].Resource != "x" || heads[1].Target != x2 {
		t.Fatalf("HeadsPrefix: %+v %+v %v", heads, hfa, err)
	}

	// The same answers on the wire are JWEs under K_view, with view in pl.
	raw := func(path, bearer string) (*http.Response, []byte) {
		t.Helper()
		req, _ := http.NewRequest("GET", s.URL+path, nil)
		req.Header.Set("Authorization", "Bearer "+bearer)
		res, err := (&http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		b, _ := io.ReadAll(res.Body)
		return res, b
	}
	rangePath := "/ns/s/view/" + view + "/at/" + fa.At + "/log"
	res, body := raw(rangePath, readerGrant)
	if res.StatusCode != 200 || res.Header.Get("Content-Type") != seal.ContentType {
		t.Fatalf("the filtered range: %d %s", res.StatusCode, res.Header.Get("Content-Type"))
	}
	for _, leak := range []string{"HIDDEN", "team"} {
		if bytes.Contains(body, []byte(leak)) {
			t.Fatalf("the sealed range shows %s", leak)
		}
	}
	pt, err := seal.OpenExpect(string(body), kview, "s#1", seal.FilteredRangePL("s", view, "", fa.End))
	if err != nil {
		t.Fatalf("the range under K_view: %v", err)
	}
	_, keys, err := seal.ParseFiltered(pt)
	if err != nil || len(keys) != 2 {
		t.Fatalf("the range's keys: %d %v", len(keys), err)
	}
	carried := map[string]seal.ViewKeys{}
	for _, kj := range keys {
		h := must(seal.ParseHeader(kj))
		id, _ := h.PL["id"].(string)
		name, _ := h.PL["name"].(string)
		kpt, err := seal.OpenExpect(kj, kview, "s#1", seal.ViewKeysPL("s", view, name, id))
		if err != nil {
			t.Fatalf("view keys of %s: %v", id, err)
		}
		carried[id] = must(seal.ParseViewKeys(kpt))
	}
	ka1, kx2 := carried[a1], carried[x2]
	if len(carried) != 2 || ka1.Key == nil || kx2.Key == nil {
		t.Fatalf("keys carried for %v, want a1 and x2", carried)
	}
	if ka1.Log == nil || kx2.Log != nil {
		t.Fatalf("K_log carried: a1 %v (a genesis), x2 %v (its parent hidden)", ka1.Log != nil, kx2.Log != nil)
	}
	if len(ka1.Blobs) != 1 || ka1.Blobs[bid] == nil || len(kx2.Blobs) != 0 {
		t.Fatalf("K_blob carried: a1 %v, x2 %v", ka1.Blobs, kx2.Blobs)
	}
	hres, hbody := raw("/ns/s/view/"+view+"/at/"+fa.At+"/heads", readerGrant)
	if hres.StatusCode != 200 || hres.Header.Get("Content-Type") != seal.ContentType {
		t.Fatalf("the filtered /heads: %d %s", hres.StatusCode, hres.Header.Get("Content-Type"))
	}
	if _, err := seal.OpenExpect(string(hbody), kview, "s#1", seal.FilteredHeadsPL("s", view, fa.At, "")); err != nil {
		t.Fatalf("/heads under K_view: %v", err)
	}
	// Neither opens under K_n or K_r, which the reader doesn't hold.
	ke := adminKe(t, admin)
	kn := must(seal.NamespaceKey(ke, "s"))
	if _, err := seal.OpenExpect(string(body), kn, "s#1", seal.FilteredRangePL("s", view, "", fa.End)); !errors.Is(err, seal.ErrDecrypt) {
		t.Fatalf("the filtered range under K_n: %v", err)
	}

	// Visible documents and blobs open with what the answers carried.
	for id, name := range map[string]string{a1: "a1", x2: "x"} {
		d, err := reader.Doc(ctx, "s", name, id)
		if err != nil || d.Kid != "s#1" {
			t.Fatalf("Doc %s@%s: %v", name, id, err)
		}
	}
	b, err := reader.GetBlobRef(ctx, "s", "a1", ref)
	if err != nil || !bytes.Equal(b.Data, data) {
		t.Fatalf("the blob of a1: %v", err)
	}
	// Hidden documents are read-rule failures, and their sealed bytes
	// (as an unrestricted reader fetches them) open under nothing the
	// reader holds.
	for id, name := range map[string]string{b1: "b1", x1: "x"} {
		if _, err := reader.Doc(ctx, "s", name, id); !client.IsNotFound(err) {
			t.Fatalf("hidden %s@%s: %v, want 404", name, id, err)
		}
		_, jwe := raw("/r/s/"+name+"/rev/"+id, adminGrant)
		for what, key := range map[string][]byte{"K_view": kview, "a1's K_rev": ka1.Key, "x2's K_rev": kx2.Key} {
			if _, _, err := seal.Open(string(jwe), key); err == nil {
				t.Fatalf("hidden %s opens under %s", id, what)
			}
		}
	}
	// x2's patches: its log entry, under K_log(x2), opens under nothing
	// the reader holds, and the reader's own log shows x2 without them.
	_, lb := raw("/r/s/x/rev/"+x2+"/log?since="+x1, adminGrant)
	var entries []string
	if err := jsonUnmarshal(lb, &entries); err != nil || len(entries) != 1 {
		t.Fatalf("x2's sealed entry: %s %v", lb, err)
	}
	for what, key := range map[string][]byte{"K_view": kview, "x2's K_rev": kx2.Key, "a1's K_log": ka1.Log} {
		if _, _, err := seal.Open(entries[0], key); err == nil {
			t.Fatalf("x2's entry opens under %s", what)
		}
	}
	kr := must(seal.ResourceKey(ke, "s", "x"))
	if _, err := seal.OpenExpect(entries[0], must(seal.LogKey(kr, x2)), "s#1", seal.ResourcePL("s", "x", x2, seal.KindRev)); err != nil {
		t.Fatalf("x2's entry under K_log(x2): %v", err)
	}
	log := must(reader.Log(ctx, "s", "x", x2, ""))
	if len(log) != 1 || log[0].ID != x2 || log[0].HasPatches {
		t.Fatalf("the reader's log of x: %+v", log)
	}
	lres, lbody := raw("/r/s/x/rev/"+x2+"/log", readerGrant)
	if lres.Header.Get("Content-Type") != seal.ContentType || bytes.Contains(lbody, []byte("HIDDEN")) {
		t.Fatalf("the reader's log of x on the wire: %s", lres.Header.Get("Content-Type"))
	}
	alog := must(reader.Log(ctx, "s", "a1", a1, ""))
	if len(alog) != 1 || !alog[0].HasPatches {
		t.Fatalf("the reader's log of a1, a genesis with its patches: %+v", alog)
	}

	// Long-poll: the filtered log from the start, sealed the same way.
	lp, err := reader.LongPoll(ctx, "s", "", "")
	if err != nil || len(lp.Entries) == 0 || lp.View != view {
		t.Fatalf("LongPoll: %+v %v", lp, err)
	}

	// Events: the view's, one JWE each under K_view, and a resource's,
	// x2 shown without its patches.
	stop := errors.New("stop")
	var evs []string
	err = reader.FilteredNSEvents(ctx, "s", view, "", func(e client.NSEntry) error {
		evs = append(evs, e.Kind+":"+e.Resource)
		if e.Resource == "x" {
			return stop
		}
		return nil
	})
	if !errors.Is(err, stop) || slices.Contains(evs, "head:b1") {
		t.Fatalf("FilteredNSEvents: %v %v", evs, err)
	}
	err = reader.ResourceEvents(ctx, "s", "x", "", func(ev client.Event) error {
		m, _ := ev.Data.(map[string]any)
		if ev.Type != "revision" || ev.ID != x2 || m["patches"] != nil || m["id"] != x2 {
			t.Errorf("x's first event as the reader sees it: %s %s %v", ev.Type, ev.ID, m)
		}
		return stop
	})
	if !errors.Is(err, stop) {
		t.Fatalf("ResourceEvents: %v", err)
	}

	// A partial reader's grant moves no content out: a blob copy with it
	// as the source grant is refused, as with the fixed-name grant with
	// /doc rules below (§E.2.3: K_view opens nothing for a copy); an
	// unrestricted source grant copies.
	must(s.Client(t, client.WithBearer(s.OperatorGrant(t, "p"))).CreateNamespace(ctx, "p",
		map[string]any{"read": "grant", "keys": []any{k.Entry("*")}}))
	pw := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:w", []string{"p"}, []string{"read", "create"})))
	if err := pw.CopyBlob(ctx, "p", "c", bid, "s", "a1", readerGrant); err == nil {
		t.Fatal("a blob copied out of a sealed namespace with a partial reader's grant")
	}
	if err := pw.CopyBlob(ctx, "p", "c", bid, "s", "a1", adminGrant); err != nil {
		t.Fatalf("a blob copied with an unrestricted grant: %v", err)
	}

	// An unrestricted reader keeps K_e, a fixed-name reader without /doc
	// rules K_r, and both read as before.
	if aks := must(admin.FetchKeys(ctx, "s", nil, nil)); len(aks) != 1 || aks[0].View != "" || aks[0].Resource != "" {
		t.Fatalf("the unrestricted reader's keys: %+v", aks)
	}
	fixed := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:f", []string{"s"}, []string{"read"},
		map[string]any{"rules": []any{map[string]any{"op": "test", "path": "/resource", "value": "b1"}}})), client.WithKeys(client.NewKeys(nil)))
	if fks := must(fixed.FetchKeys(ctx, "s", nil, nil)); len(fks) != 1 || fks[0].Resource != "b1" || fks[0].View != "" {
		t.Fatalf("the fixed-name reader's keys: %+v", fks)
	}
	if d, err := fixed.Doc(ctx, "s", "b1", b1); err != nil || !strings.Contains(string(d.Raw), "HIDDEN-B1") {
		t.Fatalf("the fixed-name reader's document: %v", err)
	}
	if d, err := admin.Doc(ctx, "s", "x", x1); err != nil || !strings.Contains(string(d.Raw), "HIDDEN-X1") {
		t.Fatalf("the unrestricted reader's document: %v", err)
	}
	// A fixed-name grant with /doc rules is a partial reader: K_view.
	fixedDocGrant := k.Grant(t, s.Now(), "user:g", []string{"s"}, []string{"read"},
		map[string]any{"rules": []any{map[string]any{"op": "test", "path": "/resource", "value": "a1"}, map[string]any{"op": "test", "path": "/doc/team", "value": "a"}}})
	fixedDoc := s.Client(t, client.WithBearer(fixedDocGrant))
	if fks := must(fixedDoc.FetchKeys(ctx, "s", nil, nil)); len(fks) != 1 || fks[0].View == "" || fks[0].Resource != "" {
		t.Fatalf("the fixed-name reader with /doc rules: %+v", fks)
	}
	if err := pw.CopyBlob(ctx, "p", "c2", bid, "s", "a1", fixedDocGrant); err == nil {
		t.Fatal("a blob copied out of a sealed namespace with a fixed-name grant with /doc rules")
	}

	// After a rotation, a fresh partial reader (no nbf: the current epoch
	// alone) reads the filtered range under K_view of epoch 2; the keys
	// of epoch-1 revisions are skipped, and a revision of epoch 2 opens.
	config := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:c", []string{"s"}, []string{"read", "config"})))
	must(config.PatchConfig(ctx, "s", must(config.NSHead(ctx, "s")).Config, ops(op("add", "/encryption/epoch", 2))))
	a1b := must(admin.Append(ctx, "s", "a1", a1, nonced(ops(op("replace", "/mark", "A1B"))))).ID
	fresh := s.Client(t, client.WithBearer(readerGrant), client.WithKeys(client.NewKeys(nil)))
	if _, _, err := fresh.FilteredLog(ctx, "s", ""); err != nil {
		t.Fatalf("FilteredLog after the rotation: %v", err)
	}
	if d, err := fresh.Doc(ctx, "s", "a1", a1b); err != nil || d.Kid != "s#2" {
		t.Fatalf("a1's epoch-2 revision: %v", err)
	}
	if _, err := fresh.Doc(ctx, "s", "a1", a1); !errors.Is(err, client.ErrNoKeys) {
		t.Fatalf("a1's epoch-1 revision, outside the window: %v, want ErrNoKeys", err)
	}
}

// adminKe is K_e of s#1 as an unrestricted grant's /keys gives it.
func adminKe(t *testing.T, c *client.Client) []byte {
	t.Helper()
	ks := must(c.FetchKeys(context.Background(), "s", []int{1}, nil))
	if len(ks) != 1 || ks[0].Key == nil {
		t.Fatalf("K_e: %+v", ks)
	}
	return ks[0].Key
}

func jsonUnmarshal(b []byte, v *[]string) error {
	x, err := jsonv.Parse(b)
	if err != nil {
		return err
	}
	arr, ok := x.([]any)
	if !ok {
		return errors.New("not an array")
	}
	for _, e := range arr {
		s, _ := e.(string)
		*v = append(*v, s)
	}
	return nil
}
