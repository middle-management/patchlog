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
