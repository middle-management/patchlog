package bundle_test

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/bundle"
	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/core"
	"github.com/middle-management/patchlog/internal/grant"
	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/keystore"
	"github.com/middle-management/patchlog/internal/pgtest"
	"github.com/middle-management/patchlog/internal/seal"
	"github.com/middle-management/patchlog/internal/server"
	"github.com/middle-management/patchlog/internal/sig"
	"github.com/middle-management/patchlog/internal/testenv"
)

// §G.4.1 v0.42: the grant line's ns, `key` left out when not findable,
// `written` on lines written elsewhere, and grants of sealed and
// end-to-end namespaces.

func lineMaps(t *testing.T, b []byte) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, l := range lines(b) {
		var m map[string]any
		if err := json.Unmarshal(l, &m); err != nil {
			t.Fatal(err)
		}
		out = append(out, m)
	}
	return out
}

func sigStatuses(t *testing.T, b []byte, opt bundle.VerifyOptions) (map[string]bundle.SigStatus, *bundle.SigReport) {
	t.Helper()
	out := map[string]bundle.SigStatus{}
	opt.OnSignature = func(r bundle.SigResult) { out[r.ID] = r.Status }
	s, err := bundle.VerifyWith(context.Background(), bytes.NewReader(b), opt)
	if err != nil {
		t.Fatal(err)
	}
	return out, s.Signatures
}

// A branch export: a grant first recorded by a base's entry names the base
// in its grant line, a revision the branch reads through carries
// `written`, and a signature made over the base's name verifies in the
// branch's bundle.
func TestBranchExportGrantNSAndWritten(t *testing.T) {
	t.Parallel()
	nsKey := clienttest.NewKey("ns-key")
	opKey := clienttest.NewKey("operator-2026")
	botA := signerKey(t, "bot-a", 1)
	botB := signerKey(t, "bot-b", 2)
	ga := mint(t, nsKey.Priv, nsKey.Kid, "alice", botA)
	gb := mintFor(t, opKey.Priv, opKey.Kid, "bob", "r7", botB)
	byAuthor := map[string]*grant.Grant{"alice": ga, "bob": gb}
	served := map[string]*grant.Grant{ga.ID().String(): ga, gb.ID().String(): gb}
	jwks := []map[string]any{jwk(opKey, "2020-01-01T00:00:00Z", "")}
	srv := clienttest.New(t, clienttest.Options{Wrap: grantsHandler(served, func(a string) *grant.Grant { return byAuthor[a] }, jwks)})
	as := func(author string) *client.Client { return srv.Client(t, client.WithAuthor(author)) }
	must(as("alice").CreateNamespace(ctx, "matches", map[string]any{"read": "public",
		"keys": []any{nsKey.Entry("create", "append", "delete", "read", "branch")}}))

	origin := clienttest.Origin
	canon := func(p any) []byte { return jsonv.Canonical(must(client.ToValue(p))) }
	signed := func(k sig.Key, ns, name, parent string, patches any) client.WriteOption {
		var par *ids.ID
		if parent != "" {
			id := must(ids.Parse(parent))
			par = &id
		}
		return client.WithSignature(k.SignPatches(origin, ns, name, par, canon(patches)))
	}
	genesis := client.GenesisPatches(map[string]any{"n": 1})
	r1 := must(as("alice").Create(ctx, "matches", "derby", genesis, signed(botA, "matches", "derby", "", genesis))).ID
	must(as("alice").CreateBranch(ctx, "matches", client.BranchRequest{Name: "r7"}))
	p2 := ops(op("replace", "/n", 2))
	r2 := must(as("bob").Append(ctx, "r7", "derby", r1, p2, signed(botB, "r7", "derby", r1, p2))).ID

	var buf bytes.Buffer
	plan, _, err := bundle.Export(ctx, as("alice"), &buf, bundle.ExportOptions{Select: []string{"r7/derby"}, Authors: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Notes) != 0 {
		t.Fatalf("notes %v", plan.Notes)
	}
	var grantNS = map[string]any{}
	var written = map[string]any{}
	for _, m := range lineMaps(t, buf.Bytes())[1:] {
		if m["stored"] != nil {
			grantNS[m["grant"].(string)] = m["ns"]
			continue
		}
		written[m["id"].(string)] = m["written"]
		if m["ns"] != "r7" {
			t.Fatalf("a line names %v, not the exporting namespace", m["ns"])
		}
	}
	// Alice's grant was first recorded by an entry of the base; bob's by one of the branch.
	if grantNS[ga.ID().String()] != "matches" || grantNS[gb.ID().String()] != "r7" {
		t.Fatalf("grant line ns: %v", grantNS)
	}
	if written[r1] != "matches" || written[r2] != nil {
		t.Fatalf("written: %v", written)
	}

	// Offline the chains are attested, against the source verified: the
	// base's signature over "matches" holds in the branch's bundle.
	off, _ := sigStatuses(t, buf.Bytes(), bundle.VerifyOptions{})
	if off[r1] != bundle.SigAttested || off[r2] != bundle.SigAttested {
		t.Fatalf("offline: %v", off)
	}
	on, _ := sigStatuses(t, buf.Bytes(), bundle.VerifyOptions{Keys: bundle.SourceKeyChecker(as("alice"))})
	if on[r1] != bundle.SigVerified || on[r2] != bundle.SigVerified {
		t.Fatalf("against the source: %v", on)
	}
	// Without `written` the first line's signature binds the wrong namespace.
	stripped := bytes.Replace(buf.Bytes(), []byte(`,"written":"matches"`), nil, 1)
	if bytes.Equal(stripped, buf.Bytes()) {
		t.Fatalf("no written member in\n%s", buf.Bytes())
	}
	bad, _ := sigStatuses(t, stripped, bundle.VerifyOptions{})
	if bad[r1] != bundle.SigFailed || bad[r2] != bundle.SigAttested {
		t.Fatalf("without written: %v", bad)
	}
}

// `written` as { origin, ns }, and grant lines in the form of `written`
// that leave `key` out: the chain can't be completed from the bundle, and
// completes only through a finder that supplies a key that verifies.
func TestWrittenOriginAndKeylessGrantLine(t *testing.T) {
	t.Parallel()
	const baseOrigin = "https://base.example"
	nsKey := clienttest.NewKey("ns-key")
	other := clienttest.NewKey("other")
	bot := signerKey(t, "bot-1", 1)
	g := mint(t, nsKey.Priv, nsKey.Kid, "alice", bot)
	gid := g.ID().String()
	gl := grantLine(t, "matches", g, bundle.KeyEntry{})
	gl.GrantLine.Origin = baseOrigin

	build := func(origin string) []byte {
		return writeHistory(t, "r7", "derby", func(w *bundle.Writer) ids.ID {
			noErr(t, w.Line(gl))
			l, id := history(t, "r7", "derby", nil, client.GenesisPatches(map[string]any{"n": 1}), func(p *ids.ID, body []byte) string {
				return bot.Sign(sig.Digest(origin, "matches", "derby", p, body))
			}, gid)
			l.Written = bundle.NSRef{Origin: baseOrigin, NS: "matches"}
			noErr(t, w.Line(l))
			return id
		})
	}
	b := build(baseOrigin)
	ms := lineMaps(t, b)
	ns, _ := ms[1]["ns"].(map[string]any)
	wr, _ := ms[2]["written"].(map[string]any)
	if ns["origin"] != baseOrigin || ns["ns"] != "matches" || wr["origin"] != baseOrigin || wr["ns"] != "matches" {
		t.Fatalf("lines %v %v", ms[1], ms[2])
	}
	if _, has := ms[1]["key"]; has {
		t.Fatalf("a keyless grant line has a key: %v", ms[1])
	}
	id := ms[2]["id"].(string)

	st, rep := sigStatuses(t, b, bundle.VerifyOptions{})
	if st[id] != bundle.SigUnverifiable || len(rep.BadGrants) != 0 || rep.Grants != 1 {
		t.Fatalf("no key: %v %+v", st, rep)
	}
	finder := func(k clienttest.Key) bundle.KeyFinder {
		return func(_ context.Context, ns, kid string, rev *bundle.Line) []bundle.KeyEntry {
			if ns != "matches" || kid != nsKey.Kid || rev.ID != id {
				t.Errorf("finder asked %s %s %s", ns, kid, rev.ID)
			}
			return []bundle.KeyEntry{{Kid: k.Kid, Alg: sig.Alg, Pub: k.Pub}}
		}
	}
	if st, _ := sigStatuses(t, b, bundle.VerifyOptions{Finder: finder(nsKey)}); st[id] != bundle.SigVerified {
		t.Fatalf("finder with the right key: %v", st)
	}
	wrong := other
	wrong.Kid = nsKey.Kid
	if st, _ := sigStatuses(t, b, bundle.VerifyOptions{Finder: finder(wrong)}); st[id] != bundle.SigUnverifiable {
		t.Fatalf("finder with a wrong key: %v", st)
	}
	// A signature over another origin than written's fails.
	if st, _ := sigStatuses(t, build(srcOrigin), bundle.VerifyOptions{}); st[id] != bundle.SigFailed {
		t.Fatalf("signature over the header's origin: %v", st)
	}

	// Shape: written is a name or { origin, ns }, nothing else, and only
	// in a bundle with authors.
	hist := ms[2]
	for name, v := range map[string]any{
		"number":        1,
		"empty":         "",
		"member":        map[string]any{"origin": baseOrigin, "ns": "matches", "x": 1},
		"origin only":   map[string]any{"origin": baseOrigin},
		"origin syntax": map[string]any{"origin": "base.example", "ns": "matches"},
	} {
		h := map[string]any{}
		for k, x := range hist {
			h[k] = x
		}
		h["written"] = v
		verifyErr(t, join([][]byte{lines(b)[0], lines(b)[1], jsonv.Canonical(jsonv.FromGo(h))}), "written")
		_ = name
	}
	verifyErr(t, editHeader(t, b, func(h map[string]any) { h["authors"] = false }), "authors")
}

// --- sealed and end-to-end namespaces --------------------------------------------

// newWrappedEncDeployment is newEncDeployment behind a handler that is
// built once the deployment's client exists.
func newWrappedEncDeployment(t *testing.T, origin string, wrap func(next http.Handler, c *client.Client) http.Handler) *deployment {
	t.Helper()
	ks, err := keystore.New(keystore.Generate())
	if err != nil {
		t.Fatal(err)
	}
	o := core.Options{Path: pgtest.DB(t), BlobDir: t.TempDir(), Origin: origin, AuthDisabled: true, Purger: nopPurger{}, KeyStore: ks}
	testenv.Apply(&o)
	e, err := core.Open(o)
	if err != nil {
		t.Fatal(err)
	}
	var h http.Handler
	hs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { h.ServeHTTP(w, r) }))
	t.Cleanup(func() {
		hs.CloseClientConnections()
		hs.Close()
		e.Close()
	})
	c, err := client.New(hs.URL, client.WithAuthor("alice"), client.WithKeys(client.NewKeys(nil)))
	if err != nil {
		t.Fatal(err)
	}
	h = wrap(clienttest.CountPages(server.New(e)), c)
	return &deployment{t: t, origin: origin, url: hs.URL, c: c}
}

// sealedGrantsHandler makes a sealed namespace answer as an authenticated
// one would with the grants of v0.42: every resource log entry names the
// grant of its author (inside the entry's JWE), and GET
// /ns/{ns}/grants/{gid} answers a JWE with pl { ns, grant } under the
// namespace's epoch key.
func sealedGrantsHandler(t *testing.T, grants map[string]*grant.Grant, grantFor func(author string) *grant.Grant, jwks []map[string]any) func(http.Handler, *client.Client) http.Handler {
	grantsRE := regexp.MustCompile(`^/ns/([a-z0-9_-]+)/grants/(1[a-z2-7]+)$`)
	logRE := regexp.MustCompile(`^/r/[^/]+/[^/]+/rev/[^/]+/log$`)
	return func(next http.Handler, c *client.Client) http.Handler {
		epochKey := func(ns string) []byte {
			es, err := c.FetchKeys(ctx, ns, []int{1}, nil)
			if err != nil {
				t.Fatal(err)
			}
			for _, e := range es {
				if e.Resource == "" && e.Key != nil {
					return e.Key
				}
			}
			t.Fatal("no epoch key")
			return nil
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if m := grantsRE.FindStringSubmatch(r.URL.Path); m != nil {
				g := grants[m[2]]
				if g == nil {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(404)
					io.WriteString(w, `{"code":"not_found"}`)
					return
				}
				doc := map[string]any{"id": g.ID().String(), "root": g.Blocks[0].Raw, "stored": splitStored(g.Stored())}
				body, _ := json.Marshal(doc)
				jwe, err := seal.Seal(epochKey(m[1]), m[1]+"#1", seal.PL{"ns": m[1], "grant": g.ID().String()}, body)
				if err != nil {
					t.Fatal(err)
				}
				w.Header().Set("Content-Type", seal.ContentType)
				io.WriteString(w, jwe)
				return
			}
			if r.URL.Path == "/.well-known/patchlog-keys" {
				body, _ := json.Marshal(map[string]any{"keys": jwks})
				w.Header().Set("Content-Type", "application/json")
				w.Write(body)
				return
			}
			if logRE.MatchString(r.URL.Path) {
				rec := httptest.NewRecorder()
				next.ServeHTTP(rec, r)
				body := rec.Body.Bytes()
				var arr []string
				if rec.Code == 200 && json.Unmarshal(body, &arr) == nil {
					for i, jwe := range arr {
						h, err := seal.ParseHeader(jwe)
						if err != nil {
							t.Fatal(err)
						}
						ns, _ := h.PL["ns"].(string)
						name, _ := h.PL["name"].(string)
						kr, _ := seal.ResourceKey(epochKey(ns), ns, name)
						_, pt, err := seal.Open(jwe, kr)
						if err != nil {
							t.Fatal(err)
						}
						e := jsonv.MustParse(pt).(map[string]any)
						if g := grantFor(e["author"].(string)); g != nil {
							e["grant"] = map[string]any{"id": g.ID().String(), "sub": g.Blocks[0].Sub, "kid": g.Blocks[0].Kid}
						}
						if arr[i], err = seal.Seal(kr, h.Kid, h.PL, jsonv.Canonical(e)); err != nil {
							t.Fatal(err)
						}
					}
					body, _ = json.Marshal(arr)
				}
				for k, v := range rec.Header() {
					if k != "Content-Length" {
						w.Header()[k] = v
					}
				}
				w.WriteHeader(rec.Code)
				w.Write(body)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// A sealed namespace's grants are fetched sealed and opened with the
// namespace's key; the bundle carries them, so the signatures verify.
func TestSealedNamespaceGrantsExport(t *testing.T) {
	t.Parallel()
	nsKey := clienttest.NewKey("ns-key")
	bot := signerKey(t, "bot-1", 1)
	g := mintFor(t, nsKey.Priv, nsKey.Kid, "alice", "s", bot)
	served := map[string]*grant.Grant{g.ID().String(): g}
	jwks := []map[string]any{}
	src := newWrappedEncDeployment(t, stagingOrigin, sealedGrantsHandler(t, served, func(a string) *grant.Grant {
		if a == "alice" {
			return g
		}
		return nil
	}, jwks))
	src.ns("s", map[string]any{"read": "grant", "encryption": map[string]any{"level": "sealed"},
		"keys": []any{nsKey.Entry("create", "append", "delete", "read")}})
	canon := func(p any) []byte { return jsonv.Canonical(must(client.ToValue(p))) }
	p1 := append(client.GenesisPatches(map[string]any{"v": marker}), op("add", "/$nonce", seal.NewNonce()))
	r1 := must(src.c.Create(ctx, "s", "a", p1, client.WithSignature(bot.SignPatches(stagingOrigin, "s", "a", nil, canon(p1))))).ID
	par := must(ids.Parse(r1))
	p2 := nonce(op("add", "/w", 2.0))
	r2 := must(src.c.Append(ctx, "s", "a", r1, p2, client.WithSignature(bot.SignPatches(stagingOrigin, "s", "a", &par, canon(p2))))).ID

	var buf bytes.Buffer
	plan, _, err := bundle.Export(ctx, src.c, &buf, bundle.ExportOptions{Select: []string{"s"}, Authors: true, Plaintext: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Notes) != 0 {
		t.Fatalf("notes %v", plan.Notes)
	}
	ms := lineMaps(t, buf.Bytes())
	var nGrant int
	for _, m := range ms[1:] {
		if m["stored"] != nil {
			nGrant++
			if m["ns"] != "s" || m["key"] == nil {
				t.Fatalf("grant line %v", m)
			}
		} else if m["grant"] != g.ID().String() {
			t.Fatalf("line %v doesn't name the grant", m)
		}
	}
	if nGrant != 1 {
		t.Fatalf("%d grant lines", nGrant)
	}
	st, _ := sigStatuses(t, buf.Bytes(), bundle.VerifyOptions{})
	if st[r1] != bundle.SigAttested || st[r2] != bundle.SigAttested {
		t.Fatalf("statuses %v", st)
	}
	st, _ = sigStatuses(t, buf.Bytes(), bundle.VerifyOptions{Keys: bundle.SourceKeyChecker(src.c)})
	if st[r1] != bundle.SigVerified || st[r2] != bundle.SigVerified {
		t.Fatalf("against the source %v", st)
	}
}

// An end-to-end namespace serves its grants in the clear: the bundle
// carries them.
func TestE2ENamespaceGrantsExport(t *testing.T) {
	t.Parallel()
	nsKey := clienttest.NewKey("ns-key")
	bot := signerKey(t, "bot-1", 1)
	g := mintFor(t, nsKey.Priv, nsKey.Kid, "alice", "e", bot)
	served := map[string]*grant.Grant{g.ID().String(): g}
	hits := 0
	src := newWrappedEncDeployment(t, stagingOrigin, func(next http.Handler, _ *client.Client) http.Handler {
		inner := grantsHandler(served, func(a string) *grant.Grant {
			if a == "alice" {
				return g
			}
			return nil
		}, []map[string]any{})(next)
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.URL.Path, "/grants/") {
				hits++
				w.Header().Set("Cache-Control", "private")
			}
			inner.ServeHTTP(w, r)
		})
	})
	src.ns("e", map[string]any{"read": "grant", "encryption": map[string]any{"level": "e2e"},
		"keys": []any{nsKey.Entry("create", "append", "delete", "read")}})
	reader := identity(t)
	k1 := seal.NewKey()
	kr := must(seal.BuildKeyring("e", 1, k1, []*ecdh.PublicKey{reader.PublicKey()}))
	src.create("e", "keyring", kr.Value())
	d0 := e2eWrite(t, src, k1, "e#1", "e", "d", "", client.GenesisPatches(map[string]any{"v": marker}))

	var buf bytes.Buffer
	plan, _, err := bundle.Export(ctx, src.c, &buf, bundle.ExportOptions{Select: []string{"e/d"}, Authors: true})
	if err != nil {
		t.Fatal(err)
	}
	if hits == 0 {
		t.Fatal("no grant was fetched")
	}
	if len(plan.Notes) != 0 {
		t.Fatalf("notes %v", plan.Notes)
	}
	var grantLines, named int
	for _, m := range lineMaps(t, buf.Bytes())[1:] {
		if m["stored"] != nil {
			grantLines++
			continue
		}
		if m["id"] == d0 && m["grant"] == g.ID().String() {
			named++
		}
	}
	if grantLines == 0 || named != 1 {
		t.Fatalf("%d grant lines, %d lines naming it:\n%s", grantLines, named, buf.Bytes())
	}
}
