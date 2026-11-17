package client_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/seal"
)

// v85BaseSealed serves branch z of base s (z's namespace document as
// zdoc), whose revision id of d and whose blob it serves in the §E.2.2
// forms sealed under s's epoch 1 and bound to s, as no conforming
// deployment does, and whose /keys gives s#1's key. asked lists the
// requests.
func v85BaseSealed(t *testing.T, zdoc map[string]any, ke []byte, id string) (srv *httptest.Server, asked func() []string) {
	t.Helper()
	kr, err := seal.ResourceKey(ke, "s", "d")
	if err != nil {
		t.Fatal(err)
	}
	jwe, err := seal.Seal(kr, "s#1", seal.ResourcePL("s", "d", id, seal.KindDoc), []byte(`{"n":1}`))
	if err != nil {
		t.Fatal(err)
	}
	entry, err := seal.Seal(kr, "s#1", seal.ResourcePL("s", "d", id, seal.KindRev), []byte(`{"id":"`+id+`","kind":"rev","parent":"","patches":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	docs := map[string]map[string]any{"z": zdoc, "s": {"encryption": zdoc["encryption"]}}
	var mu sync.Mutex
	var reqs []string
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		mu.Lock()
		reqs = append(reqs, r.Method+" "+p)
		mu.Unlock()
		switch {
		case r.Method == "GET" && (p == "/ns/z" || p == "/ns/s"):
			w.Header().Set("ETag", `"`+ids.Revision(nil, []byte(p)).String()+`"`)
			w.WriteHeader(302)
		case r.Method == "GET" && strings.HasPrefix(p, "/ns/") && strings.Contains(p, "/rev/"):
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(docs[strings.Split(p, "/")[2]])
		case r.Method == "GET" && p == "/r/z/d/rev/"+id:
			w.Header().Set("Content-Type", seal.ContentType)
			io.WriteString(w, jwe)
		case r.Method == "GET" && p == "/r/z/d/rev/"+id+"/log":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode([]any{entry})
		case r.Method == "POST" && strings.HasSuffix(p, "/keys"):
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{"epoch": 1, "level": "sealed", "pad": false,
				"keys": []any{map[string]any{"kid": "s#1", "key": base64.RawURLEncoding.EncodeToString(ke)}}})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), reqs...)
	}
}

// v0.85 Addendum E Levels, §E.2.2 Protected header, §E.2.5 (ENC-14; E2E
// scenario 80): "accepting a base's ns only at E3", and "at E2 a branch
// seals all it serves under its own keys". A revision or log entry served
// under a branch's URL in the §E.2.2 form whose kid and pl.ns name the
// branch's base is rejected, whether the branch is sealed or end-to-end:
// an end-to-end branch's base is end-to-end too and serves no such form
// (what it reads through there is sealed patch sets and snapshots, which
// the E2E view opens up to the foreign parent). The reader asks nobody
// for the base's key or document to find that out. Until v0.85 the
// client accepted the base's ns there for an end-to-end branch, at any
// position of the chain (v0.82 Open 13).
func TestV085BaseNSNotAcceptedInE2Form(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ke := seal.NewKey()
	id := ids.Revision(nil, []byte("d")).String()
	at := ids.Revision(nil, []byte("at")).String()
	for _, level := range []string{"sealed", "e2e"} {
		zdoc := map[string]any{"encryption": map[string]any{"level": level, "epoch": 1.0}, "base": map[string]any{"ns": "s", "at": at}}
		srv, asked := v85BaseSealed(t, zdoc, ke, id)
		c, err := client.New(srv.URL, client.WithKeys(client.NewKeys(nil)))
		if err != nil {
			t.Fatal(err)
		}
		if d, err := c.Doc(ctx, "z", "d", id); !errors.Is(err, seal.ErrMismatch) {
			t.Errorf("%s branch: a document sealed under its base: %+v %v, want a mismatch", level, d, err)
		}
		if l, err := c.Log(ctx, "z", "d", id, ""); !errors.Is(err, seal.ErrMismatch) {
			t.Errorf("%s branch: a log entry sealed under its base: %+v %v, want a mismatch", level, l, err)
		}
		for _, a := range asked() {
			if strings.HasSuffix(a, "/keys") || strings.HasPrefix(a, "GET /ns/") {
				t.Errorf("%s branch: the reader asked %s before refusing", level, a)
			}
		}
		// The same bytes under the base's own URL are the base's.
		if base, err := seal.OpenExpect(mustJWE(t, srv.URL+"/r/z/d/rev/"+id), must(seal.ResourceKey(ke, "s", "d")), "s#1", seal.ResourcePL("s", "d", id, seal.KindDoc)); err != nil || string(base) != `{"n":1}` {
			t.Fatalf("the stub's document: %s %v", base, err)
		}
	}
}

func mustJWE(t *testing.T, url string) string {
	t.Helper()
	res, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return string(b)
}

// v85Branch is p29's e2e namespace e with d written twice and a branch eb
// forked there; it returns the fork and an entry forged on it: sealed
// under the base's key with the base's pl, as a server holding only
// ciphertext can replay or a base's writer can make.
func v85Branch(t *testing.T) (v *p29Env, fork, forgedID string, forged map[string]any) {
	t.Helper()
	ctx := context.Background()
	v = newP29Env(t, nil)
	w1 := must(v.x.CreateDocSealed(ctx, "e", "d", map[string]any{"n": 1.0}))
	fork = must(v.x.AppendSealed(ctx, "e", "d", w1.ID, ops(op("replace", "/n", 2)))).ID
	must(v.c.CreateBranch(ctx, "e", client.BranchRequest{Name: "eb"}))
	kr := p29Kr(t, must(v.x.Key(ctx, "e#1")), "e", "d")
	fv := jsonv.MustParse(must(seal.SealPatchSet(kr, "e#1", "e", "d", fork, ops(op("replace", "/n", 3)))))
	forgedID = must(client.ExpectedRevision(fork, fv))
	forged = map[string]any{"id": forgedID, "parent": fork, "kind": "rev", "patches": fv, "author": "user:a", "created": "2026-10-04T12:00:00Z"}
	return v, fork, forgedID, forged
}

// v85Splice is a transport that serves eb/d as if forged were its head
// after fork, and passes eb's current namespace document through doc.
func v85Splice(fork, forgedID string, forged map[string]any, nsDoc func(ns string, doc map[string]any)) http.RoundTripper {
	base := http.DefaultTransport.(*http.Transport).Clone()
	return roundTrip(func(req *http.Request) (*http.Response, error) {
		p := req.URL.Path
		switch {
		case p == "/r/eb/d/rev/"+forgedID:
			h := http.Header{}
			h.Set("Content-Type", "application/json")
			body := `{"error":"not offered","code":"not_offered"}`
			return &http.Response{StatusCode: 404, Header: h, Body: io.NopCloser(strings.NewReader(body)), ContentLength: int64(len(body)), Request: req}, nil
		case p == "/r/eb/d/rev/"+forgedID+"/log":
			r2 := req.Clone(req.Context())
			r2.URL.Path = "/r/eb/d/rev/" + fork + "/log"
			res, err := base.RoundTrip(r2)
			if err != nil {
				return nil, err
			}
			var arr []any
			json.NewDecoder(res.Body).Decode(&arr)
			res.Body.Close()
			b, _ := json.Marshal(append(arr, forged))
			res.Body = io.NopCloser(bytes.NewReader(b))
			res.ContentLength = int64(len(b))
			res.Header.Del("Content-Length")
			res.Header.Del("X-Log-Next")
			return res, nil
		case nsDoc != nil && req.Method == "GET" && strings.HasPrefix(p, "/ns/") && strings.Contains(p, "/rev/") && strings.Count(p, "/") == 4:
			res, err := base.RoundTrip(req)
			if err != nil || res.StatusCode != 200 {
				return res, err
			}
			var doc map[string]any
			json.NewDecoder(res.Body).Decode(&doc)
			res.Body.Close()
			nsDoc(strings.Split(p, "/")[2], doc)
			b, _ := json.Marshal(doc)
			res.Body = io.NopCloser(bytes.NewReader(b))
			res.ContentLength = int64(len(b))
			res.Header.Del("Content-Length")
			return res, nil
		}
		return base.RoundTrip(req)
	})
}

// v0.85 §G.3, §E.2.2, §E.3.1 (ENC-14, FED; E2E scenario 81, for a remote
// chain): "Clients reading an E3 remote branch accept read-through
// ciphertext whose pl.ns is in chain, up to the resource's foreign
// parent." The reader can't ask the remote base for its head at at, so it
// takes the fork from the branch itself: its head of the resource at its
// first namespace entry. Here eb's document is served as a remote
// branch's of e (base.origin and chain, played by the transport), and an
// entry sealed under e's key spliced after the fork is flagged and
// folded as []; the entries up to the fork still fold. Until v0.85 a
// remote base's fork wasn't checked.
func TestV085RemoteChainOnlyUpToFork(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	v, fork, forgedID, forged := v85Branch(t)
	rt := v85Splice(fork, forgedID, forged, func(ns string, doc map[string]any) {
		if b, ok := doc["base"].(map[string]any); ok && ns == "eb" {
			b["origin"], b["chain"] = "https://a.example", []any{"e"}
		}
	})
	x := v.s.Client(t, client.WithBearer(v.grant), client.WithHTTPClient(&http.Client{Transport: rt})).E2E(v.priv)
	// Read through: the base's entries fold in the branch.
	if d := must(x.DocE2E(ctx, "eb", "d", fork)); len(d.Flagged) != 0 || d.Value.(map[string]any)["n"] != 2.0 {
		t.Fatalf("read-through fold %+v", d)
	}
	d := must(x.DocE2E(ctx, "eb", "d", forgedID))
	if len(d.Flagged) != 1 || d.Flagged[0].ID != forgedID || d.Value.(map[string]any)["n"] != 2.0 {
		t.Fatalf("an entry sealed under the remote base past the fork: %+v", d)
	}
}

// v0.85 §7.1 End-to-end namespaces ("A client learns each namespace's
// level, a base's included, from … the current namespace document … It
// refuses a claim below the level it holds, or one it doesn't know while
// it holds any, and learns nothing from either"; E2E scenario 79, at E3):
// reading through an end-to-end branch walks its bases' current
// documents, and a base held as e2e whose document now names a lower
// level, or one that isn't a level, is refused; the level held stands.
func TestV085ReadThroughBaseLevelLowered(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	v, fork, _, _ := v85Branch(t)
	for what, enc := range map[string]any{"no encryption": nil, "at-rest": map[string]any{"level": "at-rest"}, "sealed": map[string]any{"level": "sealed", "epoch": 1.0}, "an unknown level": map[string]any{"level": "constructor"}} {
		rt := v85Splice(fork, "x", nil, func(ns string, doc map[string]any) {
			if ns != "e" {
				return
			}
			if enc == nil {
				delete(doc, "encryption")
			} else {
				doc["encryption"] = enc
			}
		})
		c := v.s.Client(t, client.WithBearer(v.grant), client.WithHTTPClient(&http.Client{Transport: rt}), client.WithExpectedLevel("e", "e2e"))
		if d, err := c.E2E(v.priv).DocE2E(ctx, "eb", "d", fork); !errors.Is(err, client.ErrLevelLowered) {
			t.Errorf("the base naming %s where e2e is held: %+v %v", what, d, err)
		}
		if c.HeldLevel("e") != "e2e" {
			t.Errorf("the base naming %s: held %q", what, c.HeldLevel("e"))
		}
	}
}

// Scenario 79 as the text has it, for a sealed (E2) base N: a client that
// holds sealed for N refuses N's current namespace document where it
// claims at-rest, or a level that isn't one of the four, and still holds
// sealed; N's document read by id teaches nothing and isn't refused. A
// reader of a sealed branch of N opens only what the branch seals under
// its own keys (TestV085BaseNSNotAcceptedInE2Form), so reading through
// the branch fetches no document of N: the refusal is where N's document
// is read.
func TestV085SealedBaseLevelHeld(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	for what, enc := range map[string]map[string]any{"at-rest": {"level": "at-rest"}, "a level that isn't one": {"level": "nope"}} {
		st := newE3Stub(t)
		v82NSDoc(st, enc, false)
		c, err := client.New(st.server().URL, client.WithExpectedLevel("e", "sealed"))
		if err != nil {
			t.Fatal(err)
		}
		if lv, err := c.EncryptionLevel(ctx, "e"); !errors.Is(err, client.ErrLevelLowered) {
			t.Errorf("%s where sealed is held: %q %v", what, lv, err)
		}
		if s, err := c.Sealed(ctx, "e"); !errors.Is(err, client.ErrLevelLowered) {
			t.Errorf("%s where sealed is held: Sealed %v %v", what, s, err)
		}
		old := ids.Revision(nil, []byte("old")).String()
		st.set("/ns/e/rev/"+old, st.json(200, map[string]any{"encryption": enc}))
		if _, err := c.NSDoc(ctx, "e", old); err != nil {
			t.Errorf("%s in a document read by id: %v", what, err)
		}
		if c.HeldLevel("e") != "sealed" {
			t.Errorf("%s: held %q", what, c.HeldLevel("e"))
		}
	}
}
