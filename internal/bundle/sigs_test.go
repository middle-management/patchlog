package bundle_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/bundle"
	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/grant"
	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/sig"
)

var b64u = base64.RawURLEncoding

// signerKey is a deterministic signer key; other seeds give other keys.
func signerKey(t *testing.T, kid string, seed byte) sig.Key {
	t.Helper()
	raw := bytes.Repeat([]byte{seed}, 32)
	k, err := sig.ParseKey(kid + ":" + b64u.EncodeToString(raw))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// storedBlocks splits the stored container of a grant (§C.3.1) into its
// SignedBlocks in base64url, authority first: field 2 is the authority
// block, field 3 the others.
func storedBlocks(t *testing.T, g *grant.Grant) []string {
	t.Helper()
	data := g.Stored()
	var out []string
	for len(data) > 0 {
		tag, n := binary.Uvarint(data)
		data = data[n:]
		l, n := binary.Uvarint(data)
		data = data[n:]
		if tag&7 != 2 {
			t.Fatalf("unexpected wire type in the stored grant")
		}
		out = append(out, b64u.EncodeToString(data[:l]))
		data = data[l:]
	}
	return out
}

// mint mints a root grant signed by issuer, listing signers.
func mint(t *testing.T, issuer ed25519.PrivateKey, kid, sub string, signers ...sig.Key) *grant.Grant {
	t.Helper()
	return mintFor(t, issuer, kid, sub, "matches", signers...)
}

// mintFor is mint for a grant naming namespace ns.
func mintFor(t *testing.T, issuer ed25519.PrivateKey, kid, sub, ns string, signers ...sig.Key) *grant.Grant {
	t.Helper()
	root := map[string]any{"kid": kid, "sub": sub, "ns": []any{ns}, "can": []any{"create", "append", "delete", "read"},
		"exp": time.Now().Add(time.Hour).UTC().Format(time.RFC3339)}
	if len(signers) > 0 {
		var es []any
		for _, k := range signers {
			es = append(es, k.Entry())
		}
		root["signers"] = es
	}
	g, err := grant.Mint(root, issuer)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func keyEntryOf(k clienttest.Key) bundle.KeyEntry {
	return bundle.KeyEntry{Kid: k.Kid, Alg: sig.Alg, Pub: k.Pub}
}

func grantLine(t *testing.T, ns string, g *grant.Grant, key bundle.KeyEntry) bundle.Line {
	t.Helper()
	root := jsonv.MustParse(jsonv.Canonical(g.Blocks[0].Raw)).(map[string]any)
	return bundle.Line{NS: ns, GrantLine: &bundle.GrantLine{ID: g.ID().String(), Root: root, Stored: storedBlocks(t, g), Key: key}}
}

const srcOrigin = "https://src.example"

func history(t *testing.T, ns, name string, parent *ids.ID, patches any, signer func(parent *ids.ID, body []byte) string, gid string) (bundle.Line, ids.ID) {
	t.Helper()
	v := must(client.ToValue(patches))
	body := jsonv.Canonical(v)
	id := ids.Revision(parent, body)
	l := bundle.Line{NS: ns, Resource: name, ID: id.String(), Kind: "rev", Patches: v, Author: "alice", Created: "2026-10-04T12:00:00Z", Grant: gid}
	if parent != nil {
		l.Parent = parent.String()
	}
	if signer != nil {
		l.Signature = signer(parent, body)
	}
	return l, id
}

// writeHistory writes a bundle with authors of ns/name: build writes the
// lines and returns the head. The writer needs the head up front, so it is
// built twice.
func writeHistory(t *testing.T, ns, name string, build func(w *bundle.Writer) ids.ID) []byte {
	t.Helper()
	mk := func(out *bytes.Buffer, head string) *bundle.Writer {
		return must(bundle.NewWriter(out, bundle.Header{Origin: srcOrigin, Created: "2026-10-04T12:00:00Z", Authors: true,
			At:   map[string]string{ns: ids.Hash(nil, []byte("at")).String()},
			Docs: map[string]bundle.DocInfo{ns + "/" + name: {History: bundle.Full, Head: head}}, Access: map[string]string{ns: bundle.AccessPublic}}))
	}
	var scratch bytes.Buffer
	head := build(mk(&scratch, ids.Hash(nil, []byte("x")).String()))
	var out bytes.Buffer
	w := mk(&out, head.String())
	build(w)
	if _, err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func TestVerifySignatureStatuses(t *testing.T) {
	t.Parallel()
	nsKey := clienttest.NewKey("ns-key")
	bot := signerKey(t, "bot-1", 1)
	other := signerKey(t, "bot-2", 2) // never listed
	good := mint(t, nsKey.Priv, nsKey.Kid, "alice", bot)
	// A grant whose line names a key that didn't sign its root block.
	forgedKey := clienttest.NewKey("ns-key")
	forged := mint(t, nsKey.Priv, nsKey.Kid, "mallory", bot)
	gid, fid := good.ID().String(), forged.ID().String()
	signAs := func(k sig.Key, ns string) func(parent *ids.ID, body []byte) string {
		return func(parent *ids.ID, body []byte) string {
			return k.Sign(sig.Digest(srcOrigin, ns, "derby", parent, body))
		}
	}

	bundleBytes := writeHistory(t, "matches", "derby", func(w *bundle.Writer) ids.ID {
		const ns = "matches"
		noErr(t, w.Line(grantLine(t, ns, good, keyEntryOf(nsKey))))
		noErr(t, w.Line(grantLine(t, ns, forged, keyEntryOf(forgedKey))))
		// 1 valid; 2 valid on the forged grant (its line's key is wrong);
		// 3 signed by a kid the grant doesn't list; 4 signature over
		// another namespace; 5 no grant named; 6 unsigned; 7 a signed
		// tombstone.
		var parent *ids.ID
		add := func(patches any, sign func(*ids.ID, []byte) string, g string) {
			l, id := history(t, ns, "derby", parent, patches, sign, g)
			noErr(t, w.Line(l))
			parent = &id
		}
		add(client.GenesisPatches(map[string]any{"n": 1}), signAs(bot, ns), gid)
		add(ops(op("replace", "/n", 2)), signAs(bot, ns), fid)
		add(ops(op("replace", "/n", 3)), signAs(other, ns), gid)
		add(ops(op("replace", "/n", 4)), signAs(bot, "elsewhere"), gid)
		add(ops(op("replace", "/n", 5)), signAs(bot, ns), "")
		add(ops(op("replace", "/n", 6)), nil, "")
		// 7: the tombstone, signed over "tombstone" on the previous head.
		tomb := ids.Tombstone(*parent)
		noErr(t, w.Line(bundle.Line{NS: ns, Resource: "derby", ID: tomb.String(), Parent: parent.String(), Kind: "tombstone", Author: "alice",
			Created: "2026-10-04T12:00:00Z", Grant: gid, Signature: bot.SignTombstone(srcOrigin, ns, "derby", *parent)}))
		return tomb
	})
	buf := bytes.NewBuffer(bundleBytes)

	var results []bundle.SigResult
	sum, err := bundle.VerifyWith(ctx, bytes.NewReader(buf.Bytes()), bundle.VerifyOptions{OnSignature: func(r bundle.SigResult) { results = append(results, r) }})
	if err != nil {
		t.Fatal(err)
	}
	want := []bundle.SigStatus{
		bundle.SigAttested,     // 1 valid
		bundle.SigFailed,       // 2 the forged grant line
		bundle.SigUnverifiable, // 3 kid not listed
		bundle.SigFailed,       // 4 bound to another namespace
		bundle.SigUnverifiable, // 5 no grant named
		bundle.SigUnsigned,     // 6
		bundle.SigAttested,     // 7 tombstone
	}
	if len(results) != len(want) {
		t.Fatalf("%d results, want %d: %+v", len(results), len(want), results)
	}
	for i, w := range want {
		if results[i].Status != w {
			t.Errorf("revision %d: %s (%s), want %s", i+1, results[i].Status, results[i].Reason, w)
		}
	}
	if results[0].Sub != "alice" || results[0].Kid != "bot-1" || results[0].Grant != gid {
		t.Errorf("result 1: %+v", results[0])
	}
	r := sum.Signatures
	if r == nil || r.Grants != 2 || len(r.BadGrants) != 1 || !strings.Contains(r.BadGrants[0], fid) {
		t.Fatalf("report: %+v", r)
	}
	if r.Counts[bundle.SigAttested] != 2 || r.Counts[bundle.SigFailed] != 2 || len(r.Problems) != 4 {
		t.Fatalf("counts: %+v", r)
	}
	// Plain Verify reads the same bundle and reports the same.
	s2, err := bundle.Verify(bytes.NewReader(buf.Bytes()))
	if err != nil || s2.Signatures.Counts[bundle.SigAttested] != 2 {
		t.Fatalf("Verify: %v %+v", err, s2)
	}

	// A KeyChecker that completes the chain turns attested into verified,
	// and one that refuses turns it into failed.
	check := func(v bundle.KeyVerdict) *bundle.SigReport {
		s, err := bundle.VerifyWith(ctx, bytes.NewReader(buf.Bytes()), bundle.VerifyOptions{
			Keys: func(_ context.Context, ns string, key bundle.KeyEntry, rev *bundle.Line) (bundle.KeyVerdict, string) {
				if key.Kid != nsKey.Kid || ns != "matches" || rev.ID == "" {
					t.Errorf("key checker called with %s %+v %s", ns, key, rev.ID)
				}
				return v, "test"
			}})
		if err != nil {
			t.Fatal(err)
		}
		return s.Signatures
	}
	if c := check(bundle.KeyInForce).Counts; c[bundle.SigVerified] != 2 || c[bundle.SigAttested] != 0 {
		t.Errorf("in force: %+v", c)
	}
	if c := check(bundle.KeyNotInForce).Counts; c[bundle.SigFailed] != 4 || c[bundle.SigVerified] != 0 {
		t.Errorf("not in force: %+v", c)
	}
	if c := check(bundle.KeyUnchecked).Counts; c[bundle.SigAttested] != 2 {
		t.Errorf("unchecked: %+v", c)
	}
}

func TestGrantLineOrderingAndShape(t *testing.T) {
	t.Parallel()
	nsKey := clienttest.NewKey("ns-key")
	bot := signerKey(t, "bot-1", 1)
	g := mint(t, nsKey.Priv, nsKey.Kid, "alice", bot)
	gid := g.ID().String()
	gl := grantLine(t, "matches", g, keyEntryOf(nsKey))
	sign := func(parent *ids.ID, body []byte) string {
		return bot.Sign(sig.Digest(srcOrigin, "matches", "derby", parent, body))
	}
	l, id := history(t, "matches", "derby", nil, client.GenesisPatches(map[string]any{"n": 1}), sign, gid)
	hdr := bundle.Header{Origin: srcOrigin, Created: "2026-10-04T12:00:00Z", Authors: true,
		At:   map[string]string{"matches": ids.Hash(nil, []byte("at")).String()},
		Docs: map[string]bundle.DocInfo{"matches/derby": {History: bundle.Full, Head: id.String()}}}

	// Grant line first: fine, and the digest covers it like any line.
	var ok bytes.Buffer
	w := must(bundle.NewWriter(&ok, hdr))
	noErr(t, w.Line(gl))
	noErr(t, w.Line(l))
	digest := must(w.Close())
	sum, err := bundle.Verify(bytes.NewReader(ok.Bytes()))
	if err != nil || sum.Digest != digest || sum.Lines != 2 {
		t.Fatalf("verify: %v %+v", err, sum)
	}
	h := sha256.Sum256(ok.Bytes())
	var want ids.ID
	copy(want[:], h[:])
	if digest != want.String() {
		t.Fatalf("digest %s is not trunc160(sha256) of the bytes, %s", digest, want)
	}
	// The grant line is the second line and has the spec's members.
	ls := lines(ok.Bytes())
	var m map[string]any
	if err := json.Unmarshal(ls[1], &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"ns", "grant", "root", "stored", "key"} {
		if _, has := m[k]; !has || len(m) != 5 {
			t.Fatalf("grant line %v", m)
		}
	}
	// Changing a byte of the stored grant changes the digest.
	tampered := bytes.Replace(ok.Bytes(), []byte(gl.GrantLine.Key.Pub), []byte(keyEntryOf(clienttest.NewKey("x")).Pub), 1)
	s2, err := bundle.Verify(bytes.NewReader(tampered))
	if err != nil || s2.Digest == digest {
		t.Fatalf("digest of a changed grant line: %v %+v", err, s2)
	}
	if s2.Signatures.Counts[bundle.SigFailed] != 1 {
		t.Fatalf("a wrong key on the grant line must fail its signatures: %+v", s2.Signatures)
	}

	// A line that names a grant before its grant line: rejected by the
	// writer and the reader.
	var bad bytes.Buffer
	w = must(bundle.NewWriter(&bad, hdr))
	if err := w.Line(l); err == nil || !strings.Contains(err.Error(), "no grant line before it") {
		t.Fatalf("writer accepted a grant reference without its grant line: %v", err)
	}
	reordered := join([][]byte{ls[0], ls[2], ls[1]})
	verifyErr(t, reordered, "no grant line before it")
	// The grant line twice.
	verifyErr(t, join([][]byte{ls[0], ls[1], ls[1], ls[2]}), "more than once")
	// A grant line in a bundle without authors.
	noAuthors := editHeader(t, ok.Bytes(), func(h map[string]any) { h["authors"] = false })
	verifyErr(t, noAuthors, "without authors")
	// Unknown members and a malformed key.
	for name, edit := range map[string]func(m map[string]any){
		"unknown member": func(m map[string]any) { m["extra"] = 1 },
		"stored":         func(m map[string]any) { m["stored"] = []any{} },
		"key":            func(m map[string]any) { m["key"] = map[string]any{"kid": "k", "alg": "RS256", "pub": "x"} },
		"root":           func(m map[string]any) { m["root"] = "x" },
	} {
		g := jsonv.MustParse(ls[1]).(map[string]any)
		edit(g)
		verifyErr(t, join([][]byte{ls[0], jsonv.Canonical(g), ls[2]}), "grant line")
		_ = name
	}

	// Older bundles, with authors but no grant lines or grant members,
	// still parse; their signatures are unverifiable.
	l2, id2 := history(t, "matches", "derby", nil, client.GenesisPatches(map[string]any{"n": 1}), sign, "")
	var old bytes.Buffer
	hdr2 := hdr
	hdr2.Docs = map[string]bundle.DocInfo{"matches/derby": {History: bundle.Full, Head: id2.String()}}
	w = must(bundle.NewWriter(&old, hdr2))
	noErr(t, w.Line(l2))
	must(w.Close())
	s3, err := bundle.Verify(bytes.NewReader(old.Bytes()))
	if err != nil || s3.Signatures.Counts[bundle.SigUnverifiable] != 1 {
		t.Fatalf("old bundle: %v %+v", err, s3)
	}
	// And one without authors reports nothing.
	hdr3 := hdr2
	hdr3.Authors = false
	var plain bytes.Buffer
	w = must(bundle.NewWriter(&plain, hdr3))
	noErr(t, w.Line(l2))
	must(w.Close())
	s4, err := bundle.Verify(bytes.NewReader(plain.Bytes()))
	if err != nil || s4.Signatures != nil {
		t.Fatalf("no authors: %v %+v", err, s4)
	}
}

// --- export and verification against a source -------------------------------------

// grantsHandler wraps a development-mode test server (which records no
// grants) so it behaves as an authenticated one would: it serves GET /ns/{ns}/grants/{gid} from the given grants,
// names the grant of every resource log entry (grantOf by the entry's
// author), and publishes an operator JWK Set at the default well-known path.
func grantsHandler(grants map[string]*grant.Grant, grantFor func(author string) *grant.Grant, jwks []map[string]any) func(http.Handler) http.Handler {
	grantsRE := regexp.MustCompile(`^/ns/([a-z0-9_-]+)/grants/(1[a-z2-7]+)$`)
	logRE := regexp.MustCompile(`^/r/[^/]+/[^/]+/rev/[^/]+/log$`)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if m := grantsRE.FindStringSubmatch(r.URL.Path); m != nil {
				g := grants[m[2]]
				if g == nil {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(404)
					io.WriteString(w, `{"code":"not_found"}`)
					return
				}
				blocks := splitStored(g.Stored())
				body, _ := json.Marshal(map[string]any{"id": g.ID().String(), "root": g.Blocks[0].Raw, "stored": blocks})
				w.Header().Set("Content-Type", "application/json")
				w.Write(body)
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
				var arr []map[string]any
				if rec.Code == 200 && json.Unmarshal(body, &arr) == nil {
					for _, e := range arr {
						if g := grantFor(e["author"].(string)); g != nil {
							e["grant"] = map[string]any{"id": g.ID().String(), "sub": g.Blocks[0].Sub, "kid": g.Blocks[0].Kid}
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

func splitStored(data []byte) []string {
	var out []string
	for len(data) > 0 {
		_, n := binary.Uvarint(data)
		data = data[n:]
		l, n := binary.Uvarint(data)
		data = data[n:]
		out = append(out, b64u.EncodeToString(data[:l]))
		data = data[l:]
	}
	return out
}

func jwk(k clienttest.Key, from, until string) map[string]any {
	pl := map[string]any{"from": from}
	if until != "" {
		pl["until"] = until
	}
	pub, _ := b64u.DecodeString(k.Pub)
	return map[string]any{"kty": "OKP", "crv": "Ed25519", "x": b64u.EncodeToString(pub), "kid": k.Kid, "use": "sig", "patchlog": pl}
}

func TestExportGrantLinesAndSourceVerification(t *testing.T) {
	t.Parallel()
	nsKey := clienttest.NewKey("ns-key")
	opKey := clienttest.NewKey("operator-2026")
	botA := signerKey(t, "bot-a", 1)
	botB := signerKey(t, "bot-b", 2)
	// alice writes under a grant signed by the namespace key, bob under one
	// signed by an operator key, carol under one that signed by neither
	// key the source knows (a grant the exporter can't place), dave's
	// isn't served at all.
	ga := mint(t, nsKey.Priv, nsKey.Kid, "alice", botA)
	gb := mint(t, opKey.Priv, opKey.Kid, "bob", botB)
	lost := clienttest.NewKey("lost-key")
	gc := mint(t, lost.Priv, nsKey.Kid, "carol", botA) // names ns-key, signed by another
	gd := mint(t, nsKey.Priv, nsKey.Kid, "dave", botA)
	byAuthor := map[string]*grant.Grant{"alice": ga, "bob": gb, "carol": gc, "dave": gd}
	served := map[string]*grant.Grant{ga.ID().String(): ga, gb.ID().String(): gb, gc.ID().String(): gc}

	jwks := []map[string]any{jwk(opKey, "2020-01-01T00:00:00Z", "")}
	srv := clienttest.New(t, clienttest.Options{Wrap: grantsHandler(served, func(a string) *grant.Grant { return byAuthor[a] }, jwks)})
	as := func(author string) *client.Client { return srv.Client(t, client.WithAuthor(author)) }
	noErr(t, func() error {
		_, err := as("alice").CreateNamespace(ctx, "matches", map[string]any{"read": "public",
			"keys": []any{nsKey.Entry("create", "append", "delete", "read")}})
		return err
	}())

	// Each writes one revision with a signature of its own (the server
	// stores it).
	origin := clienttest.Origin
	canon := func(p any) []byte { return jsonv.Canonical(must(client.ToValue(p))) }
	signed := func(k sig.Key, name string, parent string, patches any) client.WriteOption {
		var par *ids.ID
		if parent != "" {
			id := must(ids.Parse(parent))
			par = &id
		}
		return client.WithSignature(k.SignPatches(origin, "matches", name, par, canon(patches)))
	}
	genesis := client.GenesisPatches(map[string]any{"n": 1})
	r1 := must(as("alice").Create(ctx, "matches", "derby", genesis, signed(botA, "derby", "", genesis))).ID
	p2 := ops(op("replace", "/n", 2))
	r2 := must(as("bob").Append(ctx, "matches", "derby", r1, p2, signed(botB, "derby", r1, p2))).ID
	p3 := ops(op("replace", "/n", 3))
	r3 := must(as("carol").Append(ctx, "matches", "derby", r2, p3, signed(botA, "derby", r2, p3))).ID
	p4 := ops(op("replace", "/n", 4))
	r4 := must(as("dave").Append(ctx, "matches", "derby", r3, p4, signed(botA, "derby", r3, p4))).ID
	p5 := ops(op("replace", "/n", 5))
	r5 := must(as("alice").Append(ctx, "matches", "derby", r4, p5, signed(botA, "derby", r4, p5))).ID
	// A tombstone, signed over "tombstone".
	par5 := must(ids.Parse(r5))
	must(as("alice").Delete(ctx, "matches", "derby", r5, client.WithSignature(botA.SignTombstone(origin, "matches", "derby", par5))))

	var buf bytes.Buffer
	plan, sum, err := bundle.Export(ctx, as("alice"), &buf, bundle.ExportOptions{Select: []string{"matches/derby"}, Authors: true})
	if err != nil {
		t.Fatal(err)
	}
	// Grant lines: alice's and bob's, each before the first line naming it.
	ls := lines(buf.Bytes())
	var order []string
	first := map[string]int{}
	for i, l := range ls[1:] {
		var m map[string]any
		if err := json.Unmarshal(l, &m); err != nil {
			t.Fatal(err)
		}
		if g, ok := m["grant"].(string); ok {
			if _, isLine := m["stored"]; isLine {
				order = append(order, g)
				first[g] = i
				continue
			}
			if _, seen := first[g]; !seen {
				t.Errorf("line %d names grant %s before its grant line", i+2, g)
			}
		}
	}
	// Carol's grant is carried without a key: nobody can find the key that
	// signed it.
	if len(order) != 3 || order[0] != ga.ID().String() || order[1] != gb.ID().String() || order[2] != gc.ID().String() {
		t.Fatalf("grant lines %v, want alice's, bob's then carol's", order)
	}
	for _, l := range ls[1:] {
		var m map[string]any
		json.Unmarshal(l, &m)
		_, hasKey := m["key"]
		if m["stored"] != nil && (m["grant"] == gc.ID().String()) == hasKey {
			t.Errorf("grant line %s: key present is %v", m["grant"], hasKey)
		}
	}
	if sum.Lines != 6+3 { // 5 revisions and a tombstone, and 3 grant lines
		t.Fatalf("lines %d", sum.Lines)
	}
	if len(plan.Notes) != 2 {
		t.Fatalf("notes: %v", plan.Notes)
	}
	joined := strings.Join(plan.Notes, "\n")
	if !strings.Contains(joined, gc.ID().String()) || !strings.Contains(joined, "without a key") || !strings.Contains(joined, gd.ID().String()) || !strings.Contains(joined, "404") {
		t.Fatalf("notes %v", plan.Notes)
	}

	// Offline: every chain that completes is attested.
	status := func(opt bundle.VerifyOptions) map[string]bundle.SigStatus {
		out := map[string]bundle.SigStatus{}
		opt.OnSignature = func(r bundle.SigResult) { out[r.ID] = r.Status }
		if _, err := bundle.VerifyWith(ctx, bytes.NewReader(buf.Bytes()), opt); err != nil {
			t.Fatal(err)
		}
		return out
	}
	tomb := ids.Tombstone(par5).String()
	off := status(bundle.VerifyOptions{})
	wantOff := map[string]bundle.SigStatus{r1: bundle.SigAttested, r2: bundle.SigAttested, r3: bundle.SigUnverifiable,
		r4: bundle.SigUnverifiable, r5: bundle.SigAttested, tomb: bundle.SigAttested}
	for id, w := range wantOff {
		if off[id] != w {
			t.Errorf("offline %s: %s, want %s", id, off[id], w)
		}
	}
	// Against the source: the namespace key at the revision's position, and
	// the operator key at its created time, complete the chain.
	on := status(bundle.VerifyOptions{Keys: bundle.SourceKeyChecker(as("alice"))})
	wantOn := map[string]bundle.SigStatus{r1: bundle.SigVerified, r2: bundle.SigVerified, r3: bundle.SigUnverifiable,
		r4: bundle.SigUnverifiable, r5: bundle.SigVerified, tomb: bundle.SigVerified}
	for id, w := range wantOn {
		if on[id] != w {
			t.Errorf("online %s: %s, want %s", id, on[id], w)
		}
	}
}

// TestSourceKeyCheckerRejectsKeyNotInForce: a grant line naming a key that
// was never in the namespace document or the operator history is failed
// against the source, though its chain is complete offline.
func TestSourceKeyCheckerRejectsKeyNotInForce(t *testing.T) {
	t.Parallel()
	nsKey := clienttest.NewKey("ns-key")
	rogue := clienttest.NewKey("rogue")
	bot := signerKey(t, "bot-1", 1)
	g := mint(t, rogue.Priv, rogue.Kid, "mallory", bot)
	srv := clienttest.New(t, clienttest.Options{Wrap: grantsHandler(map[string]*grant.Grant{}, func(string) *grant.Grant { return nil }, nil)})
	c := srv.Client(t, client.WithAuthor("mallory"))
	must(c.CreateNamespace(ctx, "matches", map[string]any{"read": "public", "keys": []any{nsKey.Entry("create", "append", "read")}}))
	genesis := client.GenesisPatches(map[string]any{"n": 1})
	rev := must(c.Create(ctx, "matches", "derby", genesis,
		client.WithSignature(bot.SignPatches(clienttest.Origin, "matches", "derby", nil, jsonv.Canonical(must(client.ToValue(genesis))))))).ID

	// The bundle is made by hand, as a malicious or mistaken exporter would.
	line, _ := history(t, "matches", "derby", nil, genesis, func(p *ids.ID, body []byte) string {
		return bot.Sign(sig.Digest(clienttest.Origin, "matches", "derby", p, body))
	}, g.ID().String())
	if line.ID != rev {
		t.Fatalf("ids differ: %s %s", line.ID, rev)
	}
	var buf bytes.Buffer
	w := must(bundle.NewWriter(&buf, bundle.Header{Origin: clienttest.Origin, Created: "2026-10-04T12:00:00Z", Authors: true,
		At:   map[string]string{"matches": must(c.NSHead(ctx, "matches")).ID},
		Docs: map[string]bundle.DocInfo{"matches/derby": {History: bundle.Full, Head: rev}}}))
	noErr(t, w.Line(grantLine(t, "matches", g, keyEntryOf(rogue))))
	line.Created = must(c.Log(ctx, "matches", "derby", rev, ""))[0].Created
	noErr(t, w.Line(line))
	must(w.Close())

	off := must(bundle.Verify(bytes.NewReader(buf.Bytes())))
	if off.Signatures.Counts[bundle.SigAttested] != 1 {
		t.Fatalf("offline: %+v", off.Signatures)
	}
	on, err := bundle.VerifyWith(ctx, bytes.NewReader(buf.Bytes()), bundle.VerifyOptions{Keys: bundle.SourceKeyChecker(c)})
	if err != nil {
		t.Fatal(err)
	}
	if on.Signatures.Counts[bundle.SigFailed] != 1 || !strings.Contains(on.Signatures.Problems[0].Reason, "rogue") {
		t.Fatalf("online: %+v", on.Signatures)
	}
}

// --- import ------------------------------------------------------------------

// captureBatches records the step objects of every batch request a target
// receives, then strips their signatures before the server sees them.
type captured struct {
	reqs []map[string]any
}

func (c *captured) wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/batch") {
			b, _ := io.ReadAll(r.Body)
			v := jsonv.MustParse(b).(map[string]any)
			ns := strings.Split(r.URL.Path, "/")[2]
			rec := jsonv.Clone(v).(map[string]any)
			rec["_ns"] = ns
			c.reqs = append(c.reqs, rec)
			for _, it := range v["items"].([]any) {
				steps := it.(map[string]any)["steps"].([]any)
				for _, s := range steps {
					if m, ok := s.(map[string]any); ok {
						delete(m, "signature")
					}
				}
			}
			nb := jsonv.Canonical(v)
			r.Body = io.NopCloser(bytes.NewReader(nb))
			r.ContentLength = int64(len(nb))
		}
		next.ServeHTTP(w, r)
	})
}

// checkBatch verifies every step signature of a captured batch with signer
// against the digest §C.3 gives, and returns how many steps it saw.
func checkBatch(t *testing.T, req map[string]any, origin string, signer sig.Signer, forbidden map[string]bool) int {
	t.Helper()
	ns := req["_ns"].(string)
	n := 0
	for _, it := range req["items"].([]any) {
		m := it.(map[string]any)
		name := m["resource"].(string)
		var par *ids.ID
		if im, ok := m["ifMatch"].(string); ok && im != "" {
			id := must(ids.Parse(im))
			par = &id
		}
		for i, s := range m["steps"].([]any) {
			sm, ok := s.(map[string]any)
			if !ok || sm["signature"] == nil {
				t.Fatalf("%s/%s step %d is unsigned: %v", ns, name, i, s)
			}
			raw := sm["signature"].(string)
			if forbidden[raw] {
				t.Fatalf("%s/%s step %d re-sends an original signature", ns, name, i)
			}
			parsed := must(sig.Parse(raw))
			var body []byte
			if sm["delete"] == true {
				if par == nil {
					t.Fatalf("delete without a parent")
				}
				id := ids.Tombstone(*par)
				if !sig.Verify(signer, parsed, sig.Digest(origin, ns, name, par, nil)) {
					t.Fatalf("%s/%s step %d: tombstone signature does not verify", ns, name, i)
				}
				par = &id
			} else {
				body = jsonv.Canonical(sm["patches"])
				if !sig.Verify(signer, parsed, sig.Digest(origin, ns, name, par, body)) {
					t.Fatalf("%s/%s step %d: signature does not verify", ns, name, i)
				}
				id := ids.Revision(par, body)
				par = &id
			}
			n++
		}
	}
	return n
}

func TestImportSignsItsOwnStepsNotTheOriginals(t *testing.T) {
	t.Parallel()
	// A source whose revisions carry signatures, exported with authors.
	src := newDeployment(t, stagingOrigin)
	src.ns("matches", nil)
	orig := signerKey(t, "author-key", 7)
	genesis := client.GenesisPatches(map[string]any{"n": 1})
	canon := func(p any) []byte { return jsonv.Canonical(must(client.ToValue(p))) }
	forbidden := map[string]bool{}
	s1 := orig.SignPatches(stagingOrigin, "matches", "derby", nil, canon(genesis))
	r1 := must(src.c.Create(ctx, "matches", "derby", genesis, client.WithSignature(s1))).ID
	p2 := ops(op("replace", "/n", 2))
	id1 := must(ids.Parse(r1))
	s2 := orig.SignPatches(stagingOrigin, "matches", "derby", &id1, canon(p2))
	must(src.c.Append(ctx, "matches", "derby", r1, p2, client.WithSignature(s2)))
	forbidden[s1], forbidden[s2] = true, true
	var buf bytes.Buffer
	_, _, err := bundle.Export(ctx, src.c, &buf, bundle.ExportOptions{Select: []string{"matches/derby"}, Authors: true})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), s1) {
		t.Fatal("the bundle should carry the original signatures")
	}

	importer := signerKey(t, "importer-key", 9)
	var cap captured
	tgt := clienttest.New(t, clienttest.Options{Wrap: cap.wrap})
	c := tgt.Client(t, client.WithAuthor("alice"))
	rep, err := bundle.Import(ctx, c, bundle.BytesOpener(buf.Bytes()), bundle.ImportOptions{Mode: bundle.Atomic, CreateNamespaces: true, Signer: &importer})
	if err != nil {
		t.Fatalf("import: %v %+v", err, rep)
	}
	signers := must(sig.ParseSigners([]any{importer.Entry()}))
	steps := 0
	for _, req := range cap.reqs {
		steps += checkBatch(t, req, clienttest.Origin, signers[0], forbidden)
	}
	if steps < 2 { // the submit carries both steps (a namespace the import creates has no dry run)
		t.Fatalf("saw %d signed steps in %d batches", steps, len(cap.reqs))
	}

	// Without a signer the steps carry no signature at all, whatever the
	// bundle carries.
	var cap2 captured
	tgt2 := clienttest.New(t, clienttest.Options{Wrap: cap2.wrap})
	if _, err := bundle.Import(ctx, tgt2.Client(t, client.WithAuthor("alice")), bundle.BytesOpener(buf.Bytes()), bundle.ImportOptions{Mode: bundle.Atomic, CreateNamespaces: true}); err != nil {
		t.Fatal(err)
	}
	for _, req := range cap2.reqs {
		for _, it := range req["items"].([]any) {
			for _, s := range it.(map[string]any)["steps"].([]any) {
				if m, ok := s.(map[string]any); ok && m["signature"] != nil {
					t.Fatalf("unsigned import sent %v", m["signature"])
				}
			}
		}
	}
}
