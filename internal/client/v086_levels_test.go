package client_test

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/ids"
)

// v86NS serves ns's current namespace document from st: doc in the clear,
// or, with doc nil, a JWE, which is how a sealed namespace serves it.
func v86NS(st *e3Stub, ns string, doc map[string]any) {
	nsID := ids.Revision(nil, []byte("ns "+ns)).String()
	st.set("/ns/"+ns, func(w http.ResponseWriter) {
		w.Header().Set("ETag", `"`+nsID+`"`)
		w.Header().Set("X-Config-Revision", nsID)
		w.WriteHeader(302)
	})
	if doc == nil {
		st.set("/ns/"+ns+"/rev/"+nsID, st.jose("eyJhbGciOiJkaXIifQ..AAAA.AAAA.AAAA"))
		return
	}
	st.set("/ns/"+ns+"/rev/"+nsID, st.json(200, doc))
}

func v86Base(ns string) map[string]any {
	return map[string]any{"ns": ns, "at": ids.Revision(nil, []byte("at "+ns)).String()}
}

// v0.86 §7.1 End-to-end namespaces ("It holds for a branch at least the
// level it holds for any base in the branch's base chain (Levels)";
// HTTP-68; Encryption levels scenario 94): a client that holds sealed for
// n from its configuration and has learnt no level for z, a branch of n,
// refuses a z document claiming at-rest, or none, and then a plaintext 200
// of /r/z/derby. The chain is what z's own document names as its base.
// Until v0.86 a level was held per namespace only, and z was believed at
// whatever its document said.
func TestV086BranchHeldAtBasesLevel(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	id := ids.Revision(nil, []byte("x")).String()
	for what, enc := range map[string]map[string]any{"at-rest": {"level": "at-rest"}, "no encryption": nil, "a level that isn't one": {"level": "nope"}} {
		st := newE3Stub(t)
		doc := map[string]any{"base": v86Base("n")}
		if enc != nil {
			doc["encryption"] = enc
		}
		v86NS(st, "z", doc)
		st.set("/r/z/derby/rev/"+id, st.json(200, map[string]any{"title": "in the clear"}))
		c, err := client.New(st.server().URL, client.WithExpectedLevel("n", "sealed"))
		if err != nil {
			t.Fatal(err)
		}
		if c.HeldLevel("z") != "" {
			t.Fatalf("%s: before z's document is read, held %q", what, c.HeldLevel("z"))
		}
		if lv, err := c.EncryptionLevel(ctx, "z"); !errors.Is(err, client.ErrLevelLowered) {
			t.Fatalf("%s: a z document claiming it where sealed is held for its base: %q %v", what, lv, err)
		}
		if s, err := c.Sealed(ctx, "z"); !errors.Is(err, client.ErrLevelLowered) {
			t.Fatalf("%s: Sealed: %v %v", what, s, err)
		}
		if c.HeldLevel("z") != "sealed" || c.HeldLevel("n") != "sealed" {
			t.Fatalf("%s: held %q for z, %q for n", what, c.HeldLevel("z"), c.HeldLevel("n"))
		}
		// Read through or z's own: a plaintext 200 is refused.
		if d, err := c.Doc(ctx, "z", "derby", id); !errors.Is(err, client.ErrLevelLowered) {
			t.Fatalf("%s: a plaintext 200 of /r/z/derby: %+v %v", what, d, err)
		}
		// A With copy shares the chain.
		if d, err := c.With(client.WithAuthor("a")).Doc(ctx, "z", "derby", id); !errors.Is(err, client.ErrLevelLowered) {
			t.Fatalf("%s: a With copy: %+v %v", what, d, err)
		}
	}

	// A z document served sealed is the level held for n: accepted.
	st := newE3Stub(t)
	v86NS(st, "z", nil)
	c, _ := client.New(st.server().URL, client.WithExpectedLevel("n", "sealed"))
	if lv, err := c.EncryptionLevel(ctx, "z"); err != nil || lv != "sealed" {
		t.Fatalf("a sealed z: %q %v", lv, err)
	}

	// A namespace that names no base, or another, is its own.
	st = newE3Stub(t)
	v86NS(st, "p", map[string]any{})
	v86NS(st, "q", map[string]any{"base": v86Base("p")})
	st.set("/r/q/derby/rev/"+id, st.json(200, map[string]any{"title": "plain"}))
	c, _ = client.New(st.server().URL, client.WithExpectedLevel("n", "sealed"))
	for _, ns := range []string{"p", "q"} {
		if lv, err := c.EncryptionLevel(ctx, ns); err != nil || lv != "" {
			t.Fatalf("%s, no branch of n: %q %v", ns, lv, err)
		}
	}
	if _, err := c.Doc(ctx, "q", "derby", id); err != nil {
		t.Fatalf("a plaintext 200 in a namespace with no sealed base: %v", err)
	}
}

// v0.86 §7.1 (scenario 94, "any base in Z's base chain"): the chain is
// followed through every base whose document the client has read. z is a
// branch of n, a branch of m, for which the client holds e2e: once it has
// read both documents, a z document claiming sealed is refused. The
// document that names the base is the branch's own, so n's link to m is
// unknown until n's document is read.
func TestV086LevelHeldThroughChainOfBases(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	st := newE3Stub(t)
	e2e := map[string]any{"level": "e2e", "epoch": 1}
	v86NS(st, "n", map[string]any{"base": v86Base("m"), "encryption": e2e})
	v86NS(st, "z", map[string]any{"base": v86Base("n"), "encryption": map[string]any{"level": "sealed", "epoch": 1}})
	c, err := client.New(st.server().URL, client.WithExpectedLevel("m", "e2e"))
	if err != nil {
		t.Fatal(err)
	}
	// Only z's document read: it names n, of which nothing is held yet.
	if lv, err := c.EncryptionLevel(ctx, "z"); err != nil || lv != "sealed" {
		t.Fatalf("z before n's document is read: %q %v", lv, err)
	}
	if lv, err := c.EncryptionLevel(ctx, "n"); err != nil || lv != "e2e" {
		t.Fatalf("n: %q %v", lv, err)
	}
	if c.HeldLevel("z") != "e2e" {
		t.Fatalf("z is held at %q, its base n being e2e", c.HeldLevel("z"))
	}
	if lv, err := c.EncryptionLevel(ctx, "z"); !errors.Is(err, client.ErrLevelLowered) {
		t.Fatalf("a z document claiming sealed under an e2e chain: %q %v", lv, err)
	}
	// Through m alone as well: n's own level unlearnt, its link known.
	c2, _ := client.New(st.server().URL, client.WithExpectedLevel("m", "e2e"))
	v86NS(st, "n", map[string]any{"base": v86Base("m")})
	if _, err := c2.EncryptionLevel(ctx, "n"); !errors.Is(err, client.ErrLevelLowered) {
		t.Fatalf("an n document naming no level under e2e m: %v", err)
	}
	if lv, err := c2.EncryptionLevel(ctx, "z"); !errors.Is(err, client.ErrLevelLowered) || c2.HeldLevel("z") != "e2e" {
		t.Fatalf("z through n's link to m: %q %v, held %q", lv, err, c2.HeldLevel("z"))
	}
	// A chain that loops, as only a lying server serves, ends.
	st2 := newE3Stub(t)
	v86NS(st2, "a", map[string]any{"base": v86Base("b")})
	v86NS(st2, "b", map[string]any{"base": v86Base("a")})
	c3, _ := client.New(st2.server().URL, client.WithExpectedLevel("b", "sealed"))
	c3.EncryptionLevel(ctx, "b")
	if _, err := c3.EncryptionLevel(ctx, "a"); !errors.Is(err, client.ErrLevelLowered) || c3.HeldLevel("a") != "sealed" {
		t.Fatalf("a loop of bases: %v, held %q", err, c3.HeldLevel("a"))
	}
}

// v0.86 §7.1: the chain is the local one. A remote base (base.origin) is a
// namespace of another deployment, and the level this client holds for a
// namespace of that name here says nothing of it: a remote z isn't held
// to it. (Scenario 94's last sentence, "a remote Z that lags behind N's
// raise fails closed meanwhile", is left to an answer on how a level held
// in one deployment is keyed for another: docs/SPEC-FEEDBACK.md.)
func TestV086RemoteBaseIsNotInTheLocalChain(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	st := newE3Stub(t)
	b := v86Base("n")
	b["origin"] = "https://a.example"
	v86NS(st, "z", map[string]any{"base": b, "encryption": map[string]any{"level": "at-rest"}})
	c, _ := client.New(st.server().URL, client.WithExpectedLevel("n", "sealed"))
	if lv, err := c.EncryptionLevel(ctx, "z"); err != nil || lv != "at-rest" || c.HeldLevel("z") != "at-rest" {
		t.Fatalf("a remote branch of another deployment's n: %q %v, held %q", lv, err, c.HeldLevel("z"))
	}
}

// v0.86 scenario 94 ("A client that holds sealed for N … answered with a
// plaintext 200 … → refused"): a holder of sealed refuses a document's
// 200 that isn't application/jose, in the namespace itself as in its
// branches, the resource named keyring included, since only an end-to-end
// namespace keeps a keyring in the clear. Until v0.86 only a holder of
// e2e refused one. At-rest and plain read alike, as before.
func TestV086SealedHolderRefusesPlaintext(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	id := ids.Revision(nil, []byte("x")).String()
	st := newE3Stub(t)
	for _, ns := range []string{"n", "r"} {
		st.set("/r/"+ns+"/d/rev/"+id, st.json(200, map[string]any{"title": "in the clear"}))
		st.set("/r/"+ns+"/keyring/rev/"+id, st.json(200, map[string]any{"entries": []any{}}))
	}
	st.set("/r/n/j/rev/"+id, st.jose("eyJhbGciOiJkaXIifQ..AAAA.AAAA.AAAA"))
	c, err := client.New(st.server().URL, client.WithExpectedLevel("n", "sealed"), client.WithExpectedLevel("r", "at-rest"))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"d", client.KeyringName} {
		if d, err := c.Doc(ctx, "n", name, id); !errors.Is(err, client.ErrLevelLowered) {
			t.Fatalf("a plaintext 200 of n/%s where sealed is held: %+v %v", name, d, err)
		}
		if _, err := c.Doc(ctx, "r", name, id); err != nil {
			t.Fatalf("a plaintext 200 of r/%s where at-rest is held: %v", name, err)
		}
	}
	// A JWE isn't refused for its form (this one opens under no key).
	if _, err := c.Doc(ctx, "n", "j", id); err == nil || errors.Is(err, client.ErrLevelLowered) {
		t.Fatalf("a JWE where sealed is held: %v", err)
	}
}

// v0.86 §7.1 ("a configured level it doesn't know counting as e2e";
// HTTP-68; Encryption levels scenario 86): a client configured with a
// level for n that isn't one of the four refuses a plaintext 200 of
// /r/n/derby/rev/{id}, and then a document claiming sealed, in the clear
// or served as a JWE.
func TestV086UnknownConfiguredLevelCountsAsE2E(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	id := ids.Revision(nil, []byte("x")).String()
	st := newE3Stub(t)
	st.set("/r/n/derby/rev/"+id, st.json(200, map[string]any{"title": "in the clear"}))
	c, err := client.New(st.server().URL, client.WithExpectedLevel("n", "e3"))
	if err != nil {
		t.Fatal(err)
	}
	if d, err := c.Doc(ctx, "n", "derby", id); !errors.Is(err, client.ErrLevelLowered) {
		t.Fatalf("a plaintext 200 under a configured level the client doesn't know: %+v %v", d, err)
	}
	if d, err := c.E2E(nil).DocE2E(ctx, "n", "derby", id); !v82Lowered(err) {
		t.Fatalf("DocE2E of the same: %+v %v", d, err)
	}
	for what, doc := range map[string]map[string]any{"in the clear": {"encryption": map[string]any{"level": "sealed", "epoch": 1}}, "as a JWE": nil} {
		v86NS(st, "n", doc)
		if lv, err := c.EncryptionLevel(ctx, "n"); !errors.Is(err, client.ErrLevelLowered) {
			t.Fatalf("a later document claiming sealed, %s: %q %v", what, lv, err)
		}
		if c.HeldLevel("n") != "e2e" {
			t.Fatalf("held %q", c.HeldLevel("n"))
		}
	}
}

// v0.86 §7.1 ("A reader of a sealed branch needn't read its bases'
// namespace documents"; scenario 94), against a deployment: z is a sealed
// branch of sealed s. A client that holds sealed for s learns z's base
// where it opens z's document, which is served as a JWE and so names
// nothing until opened, and from then on holds z at s's level; it reads
// z without asking for s's document.
func TestV086SealedBranchDocumentTeachesItsBase(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{KeyStore: keyStore(t)})
	w := s.Client(t, client.WithAuthor("alice"), client.WithKeys(client.NewKeys(nil)))
	must(w.CreateNamespace(ctx, "s", map[string]any{"read": "public", "encryption": map[string]any{"level": "sealed"}}))
	r1 := must(w.Create(ctx, "s", "derby", nonced(client.GenesisPatches(map[string]any{"n": 1.0}))))
	must(w.CreateBranch(ctx, "s", client.BranchRequest{Name: "z"}))
	c := s.Client(t, client.WithKeys(client.NewKeys(nil)), client.WithExpectedLevel("s", "sealed"))
	if c.HeldLevel("z") != "" {
		t.Fatalf("before any document of z: held %q", c.HeldLevel("z"))
	}
	doc := must(c.NSDoc(ctx, "z", must(c.NSHead(ctx, "z")).ID))
	if b, _ := doc.Value["base"].(map[string]any); b["ns"] != "s" {
		t.Fatalf("z's document names base %v", doc.Value["base"])
	}
	if c.HeldLevel("z") != "sealed" {
		t.Fatalf("after z's document is opened: held %q", c.HeldLevel("z"))
	}
	if d := must(c.Doc(ctx, "z", "derby", r1.ID)); d.Value.(map[string]any)["n"] != 1.0 {
		t.Fatalf("read through the sealed branch: %+v", d)
	}
}
