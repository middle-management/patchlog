package client_test

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/seal"
)

// v82NSDoc sets the stub's current namespace document of e to one with
// encryption enc (nil for none), served in the clear, or as a JWE where
// jose is set, as a sealed (E2) namespace serves it.
func v82NSDoc(st *e3Stub, enc map[string]any, jose bool) {
	nsID := ids.Revision(nil, []byte("ns")).String()
	st.mu.Lock()
	defer st.mu.Unlock()
	if jose {
		st.routes["/ns/e/rev/"+nsID] = st.jose("eyJhbGciOiJkaXIifQ..AAAA.AAAA.AAAA")
		return
	}
	doc := map[string]any{}
	if enc != nil {
		doc["encryption"] = enc
	}
	st.routes["/ns/e/rev/"+nsID] = st.json(200, doc)
}

func (st *e3Stub) set(path string, h func(http.ResponseWriter)) {
	st.mu.Lock()
	st.routes[path] = h
	st.mu.Unlock()
}

// v82Lowered reports a refusal a level held as e2e gives: the lowered
// claim itself, or the plaintext 200 it was to cover.
func v82Lowered(err error) bool {
	return errors.Is(err, client.ErrLevelLowered) || errors.Is(err, seal.ErrMismatch)
}

// E2E-7 (§7.1 End-to-end namespaces, Levels, HTTP-68; scenario 70): a
// client configured to expect e2e refuses a plaintext 200 of a resource
// other than the keyring, whatever level the server's namespace document
// or /keys now claims; the keyring is still read in the clear. Without
// the configuration, the same first contact is believed, which is why the
// setting exists.
func TestV082ExpectedLevelRefusesPlaintext(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	id := ids.Revision(nil, []byte("x")).String()
	for what, claim := range map[string]func(st *e3Stub){
		"the document names no encryption": func(st *e3Stub) { v82NSDoc(st, nil, false) },
		"the document says at-rest":        func(st *e3Stub) { v82NSDoc(st, map[string]any{"level": "at-rest"}, false) },
		"the document is served sealed":    func(st *e3Stub) { v82NSDoc(st, nil, true) },
		"the document says sealed":         func(st *e3Stub) { v82NSDoc(st, map[string]any{"level": "sealed", "epoch": 1}, false) },
		"an unknown level":                 func(st *e3Stub) { v82NSDoc(st, map[string]any{"level": "e2e-lite"}, false) },
		"/keys says sealed, the document is refused": func(st *e3Stub) {
			st.set("/ns/e", st.json(403, map[string]any{"code": "forbidden"}))
			st.set("/ns/e/keys", st.json(200, map[string]any{"keys": []any{}, "epoch": 1, "level": "sealed"}))
		},
		"/keys isn't offered, the document is refused": func(st *e3Stub) {
			st.set("/ns/e", st.json(403, map[string]any{"code": "forbidden"}))
			st.set("/ns/e/keys", st.json(404, map[string]any{"code": "not_offered"}))
		},
		"neither is found": func(st *e3Stub) {
			st.set("/ns/e", st.json(404, map[string]any{"code": "not_found"}))
		},
		"the document still says e2e": func(st *e3Stub) {},
	} {
		st := newE3Stub(t)
		claim(st)
		st.set("/r/e/d/rev/"+id, st.json(200, map[string]any{"title": "forged"}))
		st.set("/r/e/keyring/rev/"+id, st.json(200, map[string]any{"entries": []any{}}))
		url := st.server().URL
		c, err := client.New(url, client.WithExpectedLevel("e", "e2e"))
		if err != nil {
			t.Fatal(err)
		}
		x := c.E2EKeys(map[string][]byte{"e#1": st.ke})
		if d, err := x.DocE2E(ctx, "e", "d", id); !v82Lowered(err) {
			t.Fatalf("%s: DocE2E of a plaintext 200: %+v %v", what, d, err)
		}
		if d, err := c.Doc(ctx, "e", "d", id); !errors.Is(err, client.ErrLevelLowered) {
			t.Fatalf("%s: Doc of a plaintext 200: %+v %v", what, d, err)
		}
		if c.HeldLevel("e") != "e2e" {
			t.Fatalf("%s: the level held is %q", what, c.HeldLevel("e"))
		}
		// The keyring is the one resource read in the clear.
		if d, err := x.DocE2E(ctx, "e", client.KeyringName, id); err != nil || !d.Plain {
			t.Fatalf("%s: the keyring: %+v %v", what, d, err)
		}
		if _, err := c.Doc(ctx, "e", client.KeyringName, id); err != nil {
			t.Fatalf("%s: the keyring through Doc: %v", what, err)
		}
		// A namespace nothing was configured for is read as the server
		// says.
		st.set("/ns/p", st.json(404, map[string]any{"code": "not_found"}))
		st.set("/r/p/d/rev/"+id, st.json(200, map[string]any{"title": "plain"}))
		if _, err := c.Doc(ctx, "p", "d", id); err != nil {
			t.Fatalf("%s: another namespace: %v", what, err)
		}
	}
	// First contact without the setting: the lower claim is believed.
	st := newE3Stub(t)
	v82NSDoc(st, nil, false)
	st.set("/r/e/d/rev/"+id, st.json(200, map[string]any{"title": "forged"}))
	c, _ := client.New(st.server().URL)
	if d, err := c.E2E(nil).DocE2E(ctx, "e", "d", id); err != nil || !d.Plain {
		t.Fatalf("first contact without configuration: %+v %v", d, err)
	}
}

// E2E-7: a client that has learnt e2e, from the namespace document or
// from /keys, keeps it: a later document or /keys naming a lower level is
// ErrLevelLowered, a plaintext 200 is refused, and a transport failure, a
// 403 or a 404 teaches nothing. A With copy shares what was learnt.
func TestV082LearntLevelIsKept(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	id := ids.Revision(nil, []byte("x")).String()
	for what, learn := range map[string]func(st *e3Stub, c *client.Client){
		"learnt from the document": func(st *e3Stub, c *client.Client) {
			if lv, err := c.EncryptionLevel(ctx, "e"); err != nil || lv != "e2e" {
				t.Fatalf("level %q %v", lv, err)
			}
		},
		"learnt from /keys": func(st *e3Stub, c *client.Client) {
			st.set("/ns/e/keys", st.json(200, map[string]any{"keys": []any{}, "epoch": 1, "level": "e2e"}))
			if a, err := c.FetchKeysAnswer(ctx, "e", []int{}, nil); err != nil || a.Level != "e2e" {
				t.Fatalf("/keys %+v %v", a, err)
			}
		},
		"learnt by a read": func(st *e3Stub, c *client.Client) {
			st.set("/r/e/d/rev/"+id, st.jose(st.snapshot(id, map[string]any{"n": 1.0})))
			if _, err := c.E2EKeys(map[string][]byte{"e#1": st.ke}).DocE2E(ctx, "e", "d", id); err != nil {
				t.Fatal(err)
			}
		},
	} {
		st := newE3Stub(t)
		head := st.routes["/ns/e"]
		c, err := client.New(st.server().URL)
		if err != nil {
			t.Fatal(err)
		}
		learn(st, c)
		if c.HeldLevel("e") != "e2e" {
			t.Fatalf("%s: held %q", what, c.HeldLevel("e"))
		}
		// The copy, with another grant, holds the same table.
		cc := c.With(client.WithBearer("other"))
		x := cc.E2EKeys(map[string][]byte{"e#1": st.ke})
		st.set("/r/e/d/rev/"+id, st.json(200, map[string]any{"title": "forged"}))
		for claim, lower := range map[string]func(){
			"no encryption": func() { v82NSDoc(st, nil, false) },
			"sealed":        func() { v82NSDoc(st, nil, true) },
			"/keys sealed": func() {
				st.set("/ns/e", st.json(403, map[string]any{"code": "forbidden"}))
				st.set("/ns/e/keys", st.json(200, map[string]any{"keys": []any{}, "epoch": 1, "level": "sealed"}))
			},
		} {
			st.set("/ns/e", head)
			lower()
			if d, err := x.DocE2E(ctx, "e", "d", id); !errors.Is(err, client.ErrLevelLowered) {
				t.Fatalf("%s, then %s: DocE2E: %+v %v", what, claim, d, err)
			}
			if d, err := cc.Doc(ctx, "e", "d", id); !errors.Is(err, client.ErrLevelLowered) {
				t.Fatalf("%s, then %s: Doc: %+v %v", what, claim, d, err)
			}
			// A write under the lowered claim seals nothing and sends
			// nothing.
			if _, err := x.CreateDocSealed(ctx, "e", "new", map[string]any{"n": 1.0}); !errors.Is(err, client.ErrLevelLowered) {
				t.Fatalf("%s, then %s: a write: %v", what, claim, err)
			}
		}
		st.mu.Lock()
		for _, a := range st.asked {
			if strings.HasPrefix(a, "PATCH ") || strings.HasPrefix(a, "PUT ") {
				t.Fatalf("%s: a write was sent under a lowered level: %s", what, a)
			}
		}
		st.mu.Unlock()
		st.set("/ns/e", head)
		v82NSDoc(st, map[string]any{"level": "at-rest"}, false)
		if lv, err := cc.EncryptionLevel(ctx, "e"); !errors.Is(err, client.ErrLevelLowered) {
			t.Fatalf("%s: EncryptionLevel after the claim: %q %v", what, lv, err)
		}
		// Answers that name no level teach nothing: the plaintext stays
		// refused, and e2e stays held.
		for claim, f := range map[string]func(){
			"403 and /keys not offered": func() {
				st.set("/ns/e", st.json(403, map[string]any{"code": "forbidden"}))
				st.set("/ns/e/keys", st.json(404, map[string]any{"code": "not_offered"}))
			},
			"404 everywhere": func() {
				st.set("/ns/e", st.json(404, map[string]any{"code": "not_found"}))
				st.set("/ns/e/keys", st.json(404, map[string]any{"code": "not_found"}))
			},
			"/keys without a level": func() {
				st.set("/ns/e", st.json(403, map[string]any{"code": "forbidden"}))
				st.set("/ns/e/keys", st.json(200, map[string]any{"keys": []any{}}))
			},
			"a 500": func() {
				st.set("/ns/e", st.json(500, map[string]any{"code": "internal"}))
			},
		} {
			f()
			if d, err := x.DocE2E(ctx, "e", "d", id); err == nil {
				t.Fatalf("%s, then %s: DocE2E served a plaintext 200: %+v", what, claim, d)
			}
			if d, err := cc.Doc(ctx, "e", "d", id); !errors.Is(err, client.ErrLevelLowered) {
				t.Fatalf("%s, then %s: Doc: %+v %v", what, claim, d, err)
			}
			if c.HeldLevel("e") != "e2e" || cc.HeldLevel("e") != "e2e" {
				t.Fatalf("%s, then %s: held %q", what, claim, c.HeldLevel("e"))
			}
		}
	}
}

// E2E-7: the order none < at-rest < sealed < e2e. A level only rises; a
// historical namespace document, read by its id, names an earlier level
// without lowering or refusing anything.
func TestV082LevelOrder(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	st := newE3Stub(t)
	c, err := client.New(st.server().URL, client.WithExpectedLevel("e", "at-rest"), client.WithExpectedLevel("e", "sealed"), client.WithExpectedLevel("e", "at-rest"))
	if err != nil {
		t.Fatal(err)
	}
	if c.HeldLevel("e") != "sealed" || c.HeldLevel("other") != "" {
		t.Fatalf("configured: %q", c.HeldLevel("e"))
	}
	// e2e is higher: learnt.
	if lv, err := c.EncryptionLevel(ctx, "e"); err != nil || lv != "e2e" || c.HeldLevel("e") != "e2e" {
		t.Fatalf("raised to %q %v", lv, err)
	}
	for _, lower := range []map[string]any{nil, {"level": "at-rest"}, {"level": "sealed"}, {"level": "nope"}} {
		v82NSDoc(st, lower, false)
		if lv, err := c.EncryptionLevel(ctx, "e"); !errors.Is(err, client.ErrLevelLowered) {
			t.Fatalf("%v after e2e: %q %v", lower, lv, err)
		}
	}
	// An earlier document of the chain, read by id, isn't the level.
	old := ids.Revision(nil, []byte("old")).String()
	st.set("/ns/e/rev/"+old, st.json(200, map[string]any{}))
	if _, err := c.NSDoc(ctx, "e", old); err != nil || c.HeldLevel("e") != "e2e" {
		t.Fatalf("a historical document: %v, held %q", err, c.HeldLevel("e"))
	}
	if !client.ValidLevel("e2e") || !client.ValidLevel("sealed") || !client.ValidLevel("at-rest") || client.ValidLevel("") || client.ValidLevel("E2E") {
		t.Fatal("ValidLevel")
	}
	// A level the client doesn't know is held as e2e, never ignored.
	u, _ := client.New(st.server().URL, client.WithExpectedLevel("e", "e3"))
	if u.HeldLevel("e") != "e2e" {
		t.Fatalf("an unknown configured level is held as %q", u.HeldLevel("e"))
	}
	// Concurrent learners agree (run with -race).
	v82NSDoc(st, map[string]any{"level": "e2e", "epoch": 1}, false)
	n, _ := client.New(st.server().URL)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			n.With(client.WithExpectedLevel("e", "sealed")).EncryptionLevel(ctx, "e")
		}()
	}
	wg.Wait()
	if n.HeldLevel("e") != "e2e" {
		t.Fatalf("after concurrent reads: %q", n.HeldLevel("e"))
	}
}

// E2E-7 (§7.1, Levels): the level held stands on the paths that learn it
// beside a read: Sealed refuses a lowered document; a writer that can't
// read the document seals nothing where /keys isn't offered and e2e is
// held; and an undo there plans no plaintext inverse.
func TestV082LevelHeldOnWriteAndUndoPaths(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	// Sealed: a document in the clear, naming no encryption, where e2e is held.
	st := newE3Stub(t)
	v82NSDoc(st, nil, false)
	c, _ := client.New(st.server().URL, client.WithExpectedLevel("e", "e2e"))
	if s, err := c.Sealed(ctx, "e"); !errors.Is(err, client.ErrLevelLowered) {
		t.Errorf("Sealed under a lowered document: %v %v", s, err)
	}
	// A writer that can't read the document, /keys not offered: nothing
	// is sealed or planned as for a plain namespace.
	st = newE3Stub(t)
	st.set("/ns/e", st.json(403, map[string]any{"code": "forbidden"}))
	st.set("/ns/e/keys", st.json(404, map[string]any{"code": "not_offered"}))
	c, _ = client.New(st.server().URL, client.WithExpectedLevel("e", "e2e"))
	x := c.E2EKeys(map[string][]byte{"e#1": st.ke})
	if _, err := x.SealPatches(ctx, "e", "d", "", []any{map[string]any{"op": "add", "path": "", "value": map[string]any{}}}); !errors.Is(err, client.ErrLevelLowered) {
		t.Errorf("SealPatches where /keys isn't offered and e2e is held: %v", err)
	}
	g := client.NewGesture()
	if p, err := c.PlanUndo(ctx, "e", g); err == nil || !strings.Contains(err.Error(), "UndoE2E") {
		t.Errorf("PlanUndo where /keys isn't offered and e2e is held: %+v %v", p, err)
	}
}

// v82NS routes ns's namespace document, doc, in the clear.
func v82NS(st *e3Stub, ns string, doc map[string]any) {
	nsID := ids.Revision(nil, []byte("ns "+ns)).String()
	st.set("/ns/"+ns, func(w http.ResponseWriter) {
		w.Header().Set("ETag", `"`+nsID+`"`)
		w.Header().Set("X-Config-Revision", nsID)
		w.WriteHeader(302)
	})
	st.set("/ns/"+ns+"/rev/"+nsID, st.json(200, doc))
}

// v82Through is a stub of the chain e -> b -> bb, each namespace with
// the document docs gives it (absent: e2e at epoch 1, with its base),
// serving e/d at id as E2 delivers a document, sealed in namespace under
// its K_r, and a client holding only that namespace's epoch key.
func v82Through(t *testing.T, ke []byte, id, under string, docs map[string]map[string]any, opts ...client.Option) (*e3Stub, *client.Client) {
	st := newE3Stub(t)
	e2e := map[string]any{"level": "e2e", "epoch": 1}
	for ns, doc := range map[string]map[string]any{
		"e":  {"encryption": e2e, "base": map[string]any{"ns": "b", "at": id}},
		"b":  {"encryption": e2e, "base": map[string]any{"ns": "bb", "at": id}},
		"bb": {"encryption": e2e},
	} {
		if d, ok := docs[ns]; ok {
			doc = d
		}
		v82NS(st, ns, doc)
	}
	kr := must(seal.ResourceKey(ke, under, "d"))
	st.set("/r/e/d/rev/"+id, st.jose(must(seal.Seal(kr, under+"#1", seal.ResourcePL(under, "d", id, seal.KindDoc), []byte(`{"n":1}`)))))
	k := client.StaticKeys()
	k.Add(under+"#1", ke)
	c, err := client.New(st.server().URL, append(opts, client.WithKeys(k))...)
	if err != nil {
		t.Fatal(err)
	}
	return st, c
}

// E2E-7 (§7.1, Levels; Addendum E Levels, Branches of a raised base;
// §E.3.1): the walk of an e2e branch's bases reads each namespace's
// current document and learns its level from it. One held as e2e whose
// document now names a lower level is ErrLevelLowered, whether it is the
// branch itself, the base the content is sealed under, or a base further
// down the chain, and nothing is read through that chain.
func TestV082ReadThroughBaseLevelLowered(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	id := ids.Revision(nil, []byte("x")).String()
	ke := seal.NewKey()
	bases := map[string]map[string]any{"e": {"ns": "b", "at": id}, "b": {"ns": "bb", "at": id}}
	for what, lower := range map[string]map[string]any{
		"no encryption":       nil,
		"at-rest":             {"level": "at-rest"},
		"sealed in the clear": {"level": "sealed", "epoch": 1},
		"an unknown level":    {"level": "constructor"},
	} {
		for _, lowered := range []string{"e", "b", "bb"} {
			doc := map[string]any{}
			if lower != nil {
				doc["encryption"] = lower
			}
			if b := bases[lowered]; b != nil {
				doc["base"] = b
			}
			_, c := v82Through(t, ke, id, "b", map[string]map[string]any{lowered: doc}, client.WithExpectedLevel(lowered, "e2e"))
			if d, err := c.Doc(ctx, "e", "d", id); !errors.Is(err, client.ErrLevelLowered) {
				t.Errorf("%s naming %s where e2e is held: %+v %v", lowered, what, d, err)
			}
			if c.HeldLevel(lowered) != "e2e" {
				t.Errorf("%s naming %s: held %q", lowered, what, c.HeldLevel(lowered))
			}
		}
	}
}

// The walk reads the whole chain (Addendum E Levels; §E.3.1: readers
// accept a base's ns for content read through; a branch of a branch reads
// through both): content sealed in the base, or in the base's base, is
// read; a chain that comes back to a namespace ends; a base whose
// document can't be read ends it there, with what was learnt before it;
// and a namespace that is no base of the chain is refused.
func TestV082ReadThroughWalksTheChain(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	id := ids.Revision(nil, []byte("x")).String()
	ke := seal.NewKey()
	e2e := map[string]any{"level": "e2e", "epoch": 1}
	for _, under := range []string{"b", "bb"} {
		st, c := v82Through(t, ke, id, under, nil)
		d, err := c.Doc(ctx, "e", "d", id)
		if err != nil || d.Kid != under+"#1" {
			t.Fatalf("content sealed in %s: %+v %v", under, d, err)
		}
		sameJSON(t, d.Value, map[string]any{"n": 1.0})
		if !st.wasAsked("/ns/b") {
			t.Fatalf("content sealed in %s: the base's document wasn't read", under)
		}
	}
	// e -> b -> e: each document is read once.
	st, c := v82Through(t, ke, id, "b", map[string]map[string]any{"b": {"encryption": e2e, "base": map[string]any{"ns": "e", "at": id}}})
	if _, err := c.Doc(ctx, "e", "d", id); err != nil {
		t.Fatalf("a chain that comes back: %v", err)
	}
	n := 0
	st.mu.Lock()
	for _, a := range st.asked {
		if a == "GET /ns/e" || a == "GET /ns/b" {
			n++
		}
	}
	st.mu.Unlock()
	if n != 2 {
		t.Fatalf("a chain that comes back: %d namespace heads read", n)
	}
	// b's document refused: b is still the base, bb unknown.
	st, c = v82Through(t, ke, id, "b", nil)
	st.set("/ns/b", st.json(403, map[string]any{"code": "forbidden"}))
	if _, err := c.Doc(ctx, "e", "d", id); err != nil {
		t.Fatalf("the base's document refused, content sealed in the base: %v", err)
	}
	st, c = v82Through(t, ke, id, "bb", nil)
	st.set("/ns/b", st.json(403, map[string]any{"code": "forbidden"}))
	if d, err := c.Doc(ctx, "e", "d", id); !errors.Is(err, seal.ErrMismatch) {
		t.Fatalf("the base's document refused, content sealed below it: %+v %v", d, err)
	}
	// A base's document answering 503: the chain is unknown, not empty.
	st, c = v82Through(t, ke, id, "bb", nil)
	st.set("/ns/b", st.json(503, map[string]any{"code": "unavailable"}))
	if d, err := c.Doc(ctx, "e", "d", id); err == nil || errors.Is(err, seal.ErrMismatch) {
		t.Fatalf("the base's document 503: %+v %v", d, err)
	}
	// bb is no base of b where b names none.
	_, c = v82Through(t, ke, id, "bb", map[string]map[string]any{"b": {"encryption": e2e}})
	if d, err := c.Doc(ctx, "e", "d", id); !errors.Is(err, seal.ErrMismatch) {
		t.Fatalf("content sealed in a namespace outside the chain: %+v %v", d, err)
	}
}

// E2E-7 (§7.1, Levels; §11.2 Finding a gesture): a grant that can't read
// the namespace document, where /keys refuses, learns the level from the
// logs it reads, and a log delivered in the clear can't lower e2e where
// it is held: the undo is ErrUndoE2ELimited, never a plaintext plan. With
// nothing held, the same log is believed and planned.
func TestV082UndoLogInTheClearWhereE2EHeld(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	g := client.NewGesture()
	stub := func() *e3Stub {
		st := newE3Stub(t)
		st.set("/ns/e", st.json(403, map[string]any{"code": "forbidden"}))
		st.set("/ns/e/keys", st.json(403, map[string]any{"code": "forbidden"}))
		g0 := must(client.ExpectedRevision("", jsonv.FromGo([]any{map[string]any{"op": "add", "path": "", "value": map[string]any{"n": 1.0}}})))
		ps := []any{map[string]any{"op": "replace", "path": "/n", "value": 2.0}}
		h := must(client.ExpectedRevision(g0, jsonv.FromGo(ps)))
		st.set("/r/e/d", func(w http.ResponseWriter) { w.Header().Set("ETag", `"`+h+`"`); w.WriteHeader(302) })
		st.set("/r/e/d/rev/"+h+"/log", st.json(200, []any{
			map[string]any{"id": g0, "parent": "", "kind": "rev", "patches": []any{map[string]any{"op": "add", "path": "", "value": map[string]any{"n": 1.0}}}, "author": "user:w", "created": "2026-10-04T12:00:00.000Z"},
			map[string]any{"id": h, "parent": g0, "kind": "rev", "patches": ps, "author": "user:w", "gesture": g, "created": "2026-10-04T12:00:01.000Z"},
		}))
		st.set("/r/e/d/rev/"+h, st.json(200, map[string]any{"n": 2.0}))
		return st
	}
	st := stub()
	c, _ := client.New(st.server().URL, client.WithExpectedLevel("e", "e2e"))
	x := c.E2EKeys(map[string][]byte{"e#1": st.ke})
	if p, err := c.PlanUndo(ctx, "e", g, client.UndoResources("d"), client.UndoE2E(x)); !errors.Is(err, client.ErrUndoE2ELimited) {
		t.Errorf("PlanUndo over a log in the clear where e2e is held: %+v %v", p, err)
	}
	if p, err := c.PlanUndo(ctx, "e", g, client.UndoResources("d")); err == nil {
		t.Errorf("PlanUndo without UndoE2E: a plaintext plan %+v", p)
	}
	// Nothing held: the log's delivery is what there is to go by.
	st = stub()
	c, _ = client.New(st.server().URL)
	p, err := c.PlanUndo(ctx, "e", g, client.UndoResources("d"))
	if err != nil || len(p.Resources) != 1 {
		t.Fatalf("PlanUndo with nothing held: %+v %v", p, err)
	}
}
