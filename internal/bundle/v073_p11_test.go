package bundle_test

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/bundle"
	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/grant"
	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/seal"
	"github.com/middle-management/patchlog/internal/sig"
)

// v0.73 bundle format (P11): canonical lines and the digest over the
// bytes as written (§G.4.1, §I.9), sealed bundles' pl.last and padding
// (§G.5.1.1), grant lines' stored authority block (§G.4.1, §C.3.1), and
// limit refusals of either status (§6.6).

// writtenBundle is a small bundle the Writer wrote: a header and two
// snapshot lines.
func writtenBundle(t *testing.T) []byte {
	t.Helper()
	h := bundle.Header{Origin: stagingOrigin, Created: "2026-10-01T00:00:00Z", At: map[string]string{"n": ids.Hash(nil, []byte("at")).String()}, Docs: map[string]bundle.DocInfo{}}
	docs := map[string]any{"a": map[string]any{"title": "A", "n": 1.5}, "b": map[string]any{"title": "B"}}
	idOf := map[string]string{}
	for name, doc := range docs {
		idOf[name] = must(client.ExpectedRevision("", client.GenesisPatches(doc)))
		h.Docs[bundle.Key("n", name)] = bundle.DocInfo{History: bundle.Snapshot, Head: idOf[name]}
	}
	var buf bytes.Buffer
	w := must(bundle.NewWriter(&buf, h))
	for _, name := range []string{"a", "b"} {
		noErr(t, w.SnapshotDoc("n", name, idOf[name], docs[name], false))
	}
	must(w.Close())
	return buf.Bytes()
}

// The digest is over the bytes as written (§I.9), and every line is
// canonical JSON followed by one 0x0A: a blank line, a line that isn't
// byte for byte its canonical form, or a last line without its 0x0A
// rejects the bundle (§G.4.1, CIS-37).
func TestV073BundleLinesCanonical(t *testing.T) {
	t.Parallel()
	b := writtenBundle(t)
	sum := must(bundle.Verify(bytes.NewReader(b)))
	h := sha256.Sum256(b)
	var id ids.ID
	copy(id[:], h[:])
	if sum.Digest != id.String() {
		t.Fatalf("digest %s, want trunc160(sha256(bytes)) %s", sum.Digest, id)
	}
	ls := lines(b)
	reorder := func(l []byte) []byte { // the same members, not in canonical order
		m := jsonv.MustParse(l).(map[string]any)
		var sb strings.Builder
		sb.WriteString(`{"snapshot":` + string(jsonv.Canonical(m["snapshot"])))
		for _, k := range []string{"doc", "ns", "resource"} {
			sb.WriteString(`,"` + k + `":` + string(jsonv.Canonical(m[k])))
		}
		sb.WriteString("}")
		return []byte(sb.String())
	}
	for name, c := range map[string]struct {
		b    []byte
		want string
	}{
		"blank line between":     {join([][]byte{ls[0], {}, ls[1], ls[2]}), "line 2: a blank line"},
		"blank line at the end":  {append(append([]byte{}, b...), '\n'), "line 4: a blank line"},
		"blank line first":       {append([]byte("\n"), b...), "line 1: a blank line"},
		"no final 0x0A":          {b[:len(b)-1], "line 3: the last line doesn't end in 0x0A"},
		"pretty header":          {join([][]byte{bytes.ReplaceAll(ls[0], []byte(`":`), []byte(`": `)), ls[1], ls[2]}), "line 1: not canonical"},
		"member order":           {join([][]byte{ls[0], reorder(ls[1]), ls[2]}), "line 2: not canonical"},
		"number spelling":        {bytes.Replace(b, []byte(`"n":1.5`), []byte(`"n":1.50`), 1), "line 2: not canonical"},
		"escaped character":      {bytes.Replace(b, []byte(`"title":"A"`), []byte(`"title":"\`+`u0041"`), 1), "line 2: not canonical"},
		"CRLF":                   {bytes.ReplaceAll(b, []byte("\n"), []byte("\r\n")), "line 1: not canonical"},
		"trailing space":         {join([][]byte{ls[0], append(append([]byte{}, ls[1]...), ' '), ls[2]}), "line 2: not canonical"},
		"byte order mark":        {append([]byte("\xef\xbb\xbf"), b...), "line 1: not"},
		"leading space on entry": {join([][]byte{ls[0], append([]byte(" "), ls[1]...), ls[2]}), "line 2: not canonical"},
	} {
		_, err := bundle.Verify(bytes.NewReader(c.b))
		if err == nil || !errors.Is(err, bundle.ErrInvalid) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want an invalid-bundle error containing %q", name, err, c.want)
		}
	}
	// The importer reads through the same Reader: nothing is written.
	dst := newDeployment(t, cmsOrigin)
	_, err := bundle.Import(ctx, dst.c, bundle.BytesOpener(b[:len(b)-1]), bundle.ImportOptions{Mode: bundle.Atomic, CreateNamespaces: true})
	if err == nil || !errors.Is(err, bundle.ErrInvalid) {
		t.Fatalf("import of an unterminated bundle: %v", err)
	}
	if _, err := dst.c.NSHead(ctx, "n"); !client.IsNotFound(err) {
		t.Fatalf("the refused import created n: %v", err)
	}
}

func aesGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// sealedProtected is the protected header of a sealed bundle's JWE line.
func sealedProtected(t *testing.T, line []byte) map[string]any {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(strings.SplitN(string(line), ".", 2)[0])
	noErr(t, err)
	return jsonv.MustParse(raw).(map[string]any)
}

// A sealed bundle's last line says so in pl, { bundle, line, last: true }
// (§G.5.1.1, MF-60); one with last beside pl, as written before v0.73,
// still reads.
func TestV073SealedBundleLastInPL(t *testing.T) {
	t.Parallel()
	plain := writtenBundle(t)
	id := identity(t)
	var buf bytes.Buffer
	sw := must(bundle.NewSealedWriter(&buf, []*ecdh.PublicKey{id.PublicKey()}))
	must(sw.Write(plain))
	noErr(t, sw.Close())
	b := buf.Bytes()
	ls := lines(b)
	for i, l := range ls[1:] {
		h := sealedProtected(t, l)
		pl := h["pl"].(map[string]any)
		if _, top := h["last"]; top {
			t.Fatalf("line %d: last beside pl: %v", i, h)
		}
		if last := i == len(ls)-2; (pl["last"] == true) != last || (!last && len(pl) != 2) {
			t.Fatalf("line %d: pl %v", i, pl)
		}
	}
	r, sealed, err := bundle.Unseal(bytes.NewReader(b), id)
	noErr(t, err)
	got := must(io.ReadAll(r))
	if !sealed || !bytes.Equal(got, plain) {
		t.Fatal("the unsealed bundle differs from the plain one")
	}

	env, key := sealedParts(t, b, id)
	bid := env["id"].(string)
	last := len(ls) - 1
	pt := lines(plain)[last-1]
	with := func(line []byte) []byte {
		out := append([][]byte{}, ls...)
		out[last] = line
		return join(out)
	}
	hdr := func(pl map[string]any, top map[string]any) map[string]any {
		h := map[string]any{"alg": "dir", "enc": "A256GCM", "pl": pl}
		for k, v := range top {
			h[k] = v
		}
		return h
	}
	// The form written before v0.73.
	legacy := with(sealLine(t, key, hdr(map[string]any{"bundle": bid, "line": last - 1}, map[string]any{"last": true}), pt))
	r, _, err = bundle.Unseal(bytes.NewReader(legacy), id)
	noErr(t, err)
	if s, err := bundle.Verify(r); err != nil || s.Digest != must(bundle.Verify(bytes.NewReader(plain))).Digest {
		t.Fatalf("legacy last: %v", err)
	}
	for name, c := range map[string]struct {
		b    []byte
		want string
	}{
		"pl.last false":   {with(sealLine(t, key, hdr(map[string]any{"bundle": bid, "line": last - 1, "last": false}, nil), pt)), "pl.last must be true"},
		"pl other member": {with(sealLine(t, key, hdr(map[string]any{"bundle": bid, "line": last - 1, "first": true}, nil), pt)), "pl must be {bundle, line, last?}"},
		"no last":         {with(sealLine(t, key, hdr(map[string]any{"bundle": bid, "line": last - 1}, nil), pt)), "no line says last"},
		"pl.last early":   {join(append(append([][]byte{}, ls[:last]...), sealLine(t, key, hdr(map[string]any{"bundle": bid, "line": last - 1, "last": true}, nil), pt), ls[last])), "follows the last"},
	} {
		r, _, err := bundle.Unseal(bytes.NewReader(c.b), id)
		if err == nil {
			_, err = bundle.Verify(r)
		}
		if err == nil || !errors.Is(err, bundle.ErrInvalid) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want an invalid-bundle error containing %q", name, err, c.want)
		}
	}
}

// Padding (§E.2.2) may be applied to each sealed line's plaintext: the
// writer pads to the bucket on request, and readers remove the trailing
// spaces before the checks and the digest (§G.5.1.1, MF-61). What is left
// is checked as strictly as a plain line (CIS-37).
func TestV073SealedBundlePadding(t *testing.T) {
	t.Parallel()
	plain := writtenBundle(t)
	digest := must(bundle.Verify(bytes.NewReader(plain))).Digest
	id := identity(t)
	var buf bytes.Buffer
	sw := must(bundle.NewSealedWriter(&buf, []*ecdh.PublicKey{id.PublicKey()}))
	sw.Pad = true
	must(sw.Write(plain))
	noErr(t, sw.Close())
	b := buf.Bytes()
	env, key := sealedParts(t, b, id)
	block := must(aesGCM(key))
	for i, l := range lines(b)[1:] {
		parts := strings.Split(string(l), ".")
		iv, _ := base64.RawURLEncoding.DecodeString(parts[2])
		ct, _ := base64.RawURLEncoding.DecodeString(parts[3])
		tag, _ := base64.RawURLEncoding.DecodeString(parts[4])
		pt := must(block.Open(nil, iv, append(ct, tag...), []byte(parts[0])))
		if want := lines(plain)[i]; len(pt) != seal.PadLen(len(want)) || !bytes.Equal(bytes.TrimRight(pt, " "), want) {
			t.Fatalf("line %d: %d bytes, want %q padded to %d", i, len(pt), want, seal.PadLen(len(want)))
		}
	}
	r, _, err := bundle.Unseal(bytes.NewReader(b), id)
	noErr(t, err)
	if s, err := bundle.Verify(r); err != nil || s.Digest != digest {
		t.Fatalf("padded: %v, digest %v, want %s", err, s, digest)
	}
	// Padded or not, the import's source.bundle is the plain digest.
	dst := newDeployment(t, cmsOrigin)
	rep, err := bundle.Import(ctx, dst.c, bundle.UnsealOpener(bundle.BytesOpener(b), id), bundle.ImportOptions{Mode: bundle.Atomic, CreateNamespaces: true})
	noErr(t, err)
	if rep.Digest != digest {
		t.Fatalf("import digest %s, want %s", rep.Digest, digest)
	}

	// Plaintexts that aren't one canonical line, padded or not.
	ls := lines(b)
	bid := env["id"].(string)
	hdr := map[string]any{"alg": "dir", "enc": "A256GCM", "pl": map[string]any{"bundle": bid, "line": 1}}
	with := func(pt []byte) []byte {
		out := append([][]byte{}, ls...)
		out[2] = sealLine(t, key, hdr, pt)
		return join(out)
	}
	line1 := lines(plain)[1]
	for name, c := range map[string]struct {
		b    []byte
		want string
	}{
		"padded with a tab":  {with(append(append([]byte{}, line1...), '\t')), "not canonical"},
		"leading space":      {with(append([]byte(" "), line1...)), "not canonical"},
		"not canonical":      {with(bytes.Replace(line1, []byte(`":`), []byte(`": `), 1)), "not canonical"},
		"empty":              {with([]byte("   ")), "a blank line"},
		"two lines":          {with(append(append(append([]byte{}, line1...), '\n'), line1...)), "holds a 0x0A"},
		"newline at the end": {with(append(append([]byte{}, line1...), '\n')), "holds a 0x0A"},
	} {
		r, _, err := bundle.Unseal(bytes.NewReader(c.b), id)
		if err == nil {
			_, err = bundle.Verify(r)
		}
		if err == nil || !errors.Is(err, bundle.ErrInvalid) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want an invalid-bundle error containing %q", name, err, c.want)
		}
	}

	// The writer seals only what a Reader would read.
	for name, in := range map[string][]byte{
		"blank line":    append([]byte("\n"), plain...),
		"not canonical": bytes.Replace(plain, []byte(`":`), []byte(`": `), 1),
		"no final 0x0A": plain[:len(plain)-1],
	} {
		sw := must(bundle.NewSealedWriter(io.Discard, []*ecdh.PublicKey{id.PublicKey()}))
		_, err := sw.Write(in)
		if err == nil {
			err = sw.Close()
		}
		if err == nil || !errors.Is(err, bundle.ErrInvalid) {
			t.Errorf("sealed writer, %s: %v", name, err)
		}
	}
}

// storedString wraps a grants handler so that GET /ns/{ns}/grants/{gid}
// serves stored as the authority block alone, one string (§C.3.1), as a
// v0.73 server does.
func storedString(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/grants/") {
			next.ServeHTTP(w, r)
			return
		}
		rec := httptest.NewRecorder()
		next.ServeHTTP(rec, r)
		body := rec.Body.Bytes()
		var m map[string]any
		if rec.Code == 200 && json.Unmarshal(body, &m) == nil {
			if arr, ok := m["stored"].([]any); ok && len(arr) > 0 {
				m["stored"] = arr[0]
			}
			body, _ = json.Marshal(m)
		}
		for k, v := range rec.Header() {
			if k != "Content-Length" {
				w.Header()[k] = v
			}
		}
		w.WriteHeader(rec.Code)
		w.Write(body)
	})
}

// Grant lines carry stored as one string, the authority SignedBlock
// (§G.4.1, §C.3.1): the exporter writes it whether the source serves the
// string or, as before v0.73, every block; a bundle whose grant line
// carries the old array still reads, as its first element (GR-31).
func TestV073GrantLineStoredString(t *testing.T) {
	t.Parallel()
	for _, served := range []string{"string", "array"} {
		t.Run(served, func(t *testing.T) {
			t.Parallel()
			nsKey := clienttest.NewKey("ns-key")
			bot := signerKey(t, "bot-a", 1)
			g := mint(t, nsKey.Priv, nsKey.Kid, "alice", bot)
			grants := map[string]*grant.Grant{g.ID().String(): g}
			wrap := grantsHandler(grants, func(string) *grant.Grant { return g }, nil)
			if served == "string" {
				inner := wrap
				wrap = func(h http.Handler) http.Handler { return storedString(inner(h)) }
			}
			srv := clienttest.New(t, clienttest.Options{Wrap: wrap})
			c := srv.Client(t, client.WithAuthor("alice"))
			_, err := c.CreateNamespace(ctx, "matches", map[string]any{"read": "public", "keys": []any{nsKey.Entry("create", "append", "delete", "read")}})
			noErr(t, err)
			genesis := client.GenesisPatches(map[string]any{"n": 1})
			canon := jsonv.Canonical(must(client.ToValue(genesis)))
			r1 := must(c.Create(ctx, "matches", "derby", genesis, client.WithSignature(bot.SignPatches(clienttest.Origin, "matches", "derby", nil, canon)))).ID

			var buf bytes.Buffer
			_, _, err = bundle.Export(ctx, c, &buf, bundle.ExportOptions{Select: []string{"matches/derby"}, Authors: true})
			noErr(t, err)
			sum := must(bundle.Verify(bytes.NewReader(buf.Bytes())))
			var gl map[string]any
			for _, l := range lines(buf.Bytes())[1:] {
				m := jsonv.MustParse(l).(map[string]any)
				if _, ok := m["stored"]; ok {
					gl = m
				}
			}
			want := storedBlocks(t, g)[0]
			if gl == nil || gl["stored"] != want {
				t.Fatalf("grant line %v, want stored %q", gl, want)
			}
			if sum.Signatures == nil || sum.Signatures.Counts[bundle.SigAttested] != 1 {
				t.Fatalf("signatures %+v", sum.Signatures)
			}
			// The old form: every block, authority first, read as its
			// first; the rest isn't used.
			ls := lines(buf.Bytes())
			for i, l := range ls {
				m := jsonv.MustParse(l).(map[string]any)
				if _, ok := m["stored"]; ok {
					m["stored"] = []any{want, base64.RawURLEncoding.EncodeToString([]byte("a narrowing block"))}
					ls[i] = jsonv.Canonical(m)
				}
			}
			var results []bundle.SigResult
			_, err = bundle.VerifyWith(ctx, bytes.NewReader(join(ls)), bundle.VerifyOptions{OnSignature: func(r bundle.SigResult) { results = append(results, r) }})
			noErr(t, err)
			if len(results) != 1 || results[0].ID != r1 || results[0].Status != bundle.SigAttested {
				t.Fatalf("legacy stored array: %+v", results)
			}
			// Neither form may be empty or other than base64url.
			for name, v := range map[string]any{"empty string": "", "empty array": []any{}, "padded": want + "=", "number": 1.0, "array of numbers": []any{1.0}} {
				for i, l := range ls {
					m := jsonv.MustParse(l).(map[string]any)
					if _, ok := m["stored"]; ok {
						m["stored"] = v
						bad := append([][]byte{}, ls...)
						bad[i] = jsonv.Canonical(m)
						if _, err := bundle.Verify(bytes.NewReader(join(bad))); err == nil || !strings.Contains(err.Error(), "stored") {
							t.Errorf("stored %s: %v", name, err)
						}
					}
				}
			}
		})
	}
}

// The writer takes a grant line's stored as one string and writes it so.
func TestV073GrantLineWriterString(t *testing.T) {
	t.Parallel()
	nsKey := clienttest.NewKey("ns-key")
	bot := signerKey(t, "bot-1", 1)
	g := mint(t, nsKey.Priv, nsKey.Kid, "alice", bot)
	gid := g.ID().String()
	sign := func(parent *ids.ID, body []byte) string {
		return bot.Sign(sig.Digest(srcOrigin, "matches", "derby", parent, body))
	}
	b := writeHistory(t, "matches", "derby", func(w *bundle.Writer) ids.ID {
		noErr(t, w.Line(grantLine(t, "matches", g, keyEntryOf(nsKey))))
		l, id := history(t, "matches", "derby", nil, client.GenesisPatches(map[string]any{"n": 1}), sign, gid)
		noErr(t, w.Line(l))
		return id
	})
	m := jsonv.MustParse(lines(b)[1]).(map[string]any)
	if s, ok := m["stored"].(string); !ok || s != storedBlocks(t, g)[0] {
		t.Fatalf("stored %v", m["stored"])
	}
	if s := must(bundle.Verify(bytes.NewReader(b))); s.Signatures.Counts[bundle.SigAttested] != 1 {
		t.Fatalf("signatures %+v", s.Signatures)
	}
}

// limitProxy fronts a deployment as a v0.73 core answers limits: a batch
// over itemsPerBatch or batchSize is 422 limit at step 4, where this core
// answers 413 (§6.6, §7.5); and with blobPending, every blob upload is 422
// limit blobPending.
func limitProxy(t *testing.T, target string, blobPending bool) string {
	t.Helper()
	u := must(url.Parse(target))
	rp := httputil.NewSingleHostReverseProxy(u)
	rp.ModifyResponse = func(res *http.Response) error {
		if res.StatusCode == 413 && res.Request.Method == "POST" && strings.HasSuffix(res.Request.URL.Path, "/batch") {
			res.StatusCode, res.Status = 422, "422 Unprocessable Entity"
		}
		return nil
	}
	hs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if blobPending && r.Method == "PUT" && strings.Contains(r.URL.Path, "/blob/") {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(422)
			io.WriteString(w, `{"code":"limit","limit":"blobPending","measured":4096,"max":1024,"message":"the uploader's pending blobs would exceed blobPending"}`)
			return
		}
		rp.ServeHTTP(w, r)
	}))
	t.Cleanup(hs.Close)
	return hs.URL
}

// A limit refusal is 413 for a body cut off and 422 limit at step 4
// (§6.6): the importer recognises both with client.IsLimit, for an atomic
// batch over the namespace's batch limits and for a blob upload over
// blobPending (GB-16).
func TestV073ImportLimitEitherStatus(t *testing.T) {
	t.Parallel()
	b := bulkSource(t)
	dst := bulkTarget(t)
	bob := must(client.New(limitProxy(t, dst.url, false), client.WithAuthor("bob")))
	rep, err := bundle.Import(ctx, bob, bundle.BytesOpener(b), bundle.ImportOptions{Mode: bundle.Atomic})
	var tl *bundle.TooLargeError
	if !errors.As(err, &tl) || !strings.Contains(err.Error(), "allowance") || !strings.Contains(err.Error(), "422 limit") {
		t.Fatalf("atomic import refused with 422 limit: %v", err)
	}
	if len(rep.Batches) != 1 || rep.Batches[0].DryRun != "failed" {
		t.Fatalf("report %+v", rep.Batches)
	}
	if h := dst.head("bulk", "doc-0"); h.State != client.NotFound {
		t.Fatal("a failed atomic import wrote")
	}

	src := newDeployment(t, stagingOrigin)
	src.ns("m", nil)
	src.create("m", "a", map[string]any{"img": src.upload("m", "a", "image/png", "", []byte("blob x"))})
	var buf bytes.Buffer
	_, _, err = bundle.Export(ctx, src.c, &buf, bundle.ExportOptions{Select: []string{"m/a"}})
	noErr(t, err)
	dst2 := newDeployment(t, cmsOrigin)
	dst2.ns("m", nil)
	c := must(client.New(limitProxy(t, dst2.url, true), client.WithAuthor("alice")))
	_, err = bundle.Import(ctx, c, bundle.BytesOpener(buf.Bytes()), bundle.ImportOptions{Mode: bundle.Atomic})
	if err == nil || !strings.Contains(err.Error(), "allowance that raises the importer's blobPending") {
		t.Fatalf("blob upload refused with 422 limit: %v", err)
	}
}

// snapshotOf exports the snapshot documents of namespaces nss of d.
func snapshotOf(t *testing.T, d *deployment, nss ...string) []byte {
	t.Helper()
	var buf bytes.Buffer
	_, _, err := bundle.Export(ctx, d.c, &buf, bundle.ExportOptions{Select: nss, Mode: bundle.Snapshot, Plaintext: true})
	noErr(t, err)
	return buf.Bytes()
}

// An upstream namespace is written only by imports from one origin: a
// bundle from another origin than the imports that wrote an existing
// {ns}-upstream is refused at step 1, before anything is written, and
// imports renamed (§G.4.4, MF-45). An import batch's source without
// origin is the target's own (§7.5).
func TestV073UpstreamOneOrigin(t *testing.T) {
	t.Parallel()
	const otherOrigin = "https://other.example"
	x := newDeployment(t, stagingOrigin)
	x.ns("m", nil)
	x.create("m", "a", map[string]any{"v": 1.0})
	y := newDeployment(t, otherOrigin)
	y.ns("m", nil)
	y.ns("copy", nil)
	y.create("m", "a", map[string]any{"v": 2.0})
	y.create("copy", "a", map[string]any{"v": 3.0})

	dst := newDeployment(t, cmsOrigin)
	importB(t, dst, snapshotOf(t, x, "m"), bundle.ImportOptions{})
	before := must(dst.c.NSHead(ctx, "m-upstream")).ID
	_, err := bundle.Import(ctx, dst.c, bundle.BytesOpener(snapshotOf(t, y, "m")), bundle.ImportOptions{Mode: bundle.Atomic, CreateNamespaces: true})
	var ce *bundle.CheckError
	if !errors.As(err, &ce) || !strings.Contains(err.Error(), "m-upstream") || !strings.Contains(err.Error(), "written by imports from "+stagingOrigin) ||
		!strings.Contains(err.Error(), "comes from "+otherOrigin) {
		t.Fatalf("a second origin's import into m-upstream: %v", err)
	}
	if after := must(dst.c.NSHead(ctx, "m-upstream")).ID; after != before || dst.doc("m", "a")["v"] != 1.0 {
		t.Fatal("the refused import wrote")
	}
	// Renamed, it goes through m2-upstream.
	importB(t, dst, snapshotOf(t, y, "m"), bundle.ImportOptions{NSMap: map[string]string{"m": "m2"}})
	if dst.doc("m2", "a")["v"] != 2.0 || dst.doc("m2-upstream", "a")["v"] != 2.0 {
		t.Fatal("the renamed import")
	}
	// The first origin goes on importing into m-upstream.
	x.append("m", "a", op("replace", "/v", 4.0))
	importB(t, dst, snapshotOf(t, x, "m"), bundle.ImportOptions{})
	if dst.doc("m", "a")["v"] != 4.0 {
		t.Fatal("a later import from the first origin")
	}

	// The target's own bundle, imported renamed, writes sources without
	// origin: they count as its own origin.
	dst.ns("loc", nil)
	dst.create("loc", "a", map[string]any{"v": 5.0})
	importB(t, dst, snapshotOf(t, dst, "loc"), bundle.ImportOptions{NSMap: map[string]string{"loc": "copy"}})
	if dst.doc("copy-upstream", "a")["v"] != 5.0 {
		t.Fatal("the local import")
	}
	_, err = bundle.Import(ctx, dst.c, bundle.BytesOpener(snapshotOf(t, y, "copy")), bundle.ImportOptions{Mode: bundle.Atomic, CreateNamespaces: true})
	if !errors.As(err, &ce) || !strings.Contains(err.Error(), "copy-upstream") || !strings.Contains(err.Error(), "written by imports from "+cmsOrigin) {
		t.Fatalf("an import into an upstream the target's own imports wrote: %v", err)
	}
}

// Where the target is sealed, the patch sets generated in its upstream
// namespace carry a fresh $nonce, even where the upstream isn't sealed
// (§G.4.4, MF-46): the target fast-forwards from them.
func TestV073UpstreamNonceForSealedTarget(t *testing.T) {
	t.Parallel()
	src := newDeployment(t, stagingOrigin)
	src.ns("p", map[string]any{"read": "grant"})
	src.create("p", "a", map[string]any{"v": marker})
	snap := snapshotOf(t, src, "p")
	dst := newEncDeployment(t, cmsOrigin)
	dst.ns("p", map[string]any{"read": "grant", "encryption": map[string]any{"level": "sealed"}})
	importB(t, dst, snap, bundle.ImportOptions{})
	if lv := must(dst.c.EncryptionLevel(ctx, "p-upstream")); lv != "" {
		t.Fatalf("the upstream was created %q, as protected as its private source", lv)
	}
	up, tg := dst.head("p-upstream", "a"), dst.head("p", "a")
	if up.ID != tg.ID {
		t.Fatalf("upstream head %s, target head %s: the target didn't fast-forward", up.ID, tg.ID)
	}
	if d := dst.doc("p-upstream", "a"); d["v"] != marker || !seal.ValidNonce(fmt.Sprint(d["$nonce"])) {
		t.Fatalf("upstream doc %v", d)
	}
	// Again: unchanged, nothing written.
	rep := importB(t, dst, snap, bundle.ImportOptions{})
	if u := rep.Doc("p/a").Upstream; u.Class != "unchanged" || len(rep.Batches) != 0 {
		t.Fatalf("second import: upstream %s, %d batches", u.Class, len(rep.Batches))
	}
}

// Upstream diffs ignore $nonce whatever the namespaces' levels (§G.4.4,
// MF-47): a snapshot whose only change is its $nonce writes nothing.
func TestV073UpstreamDiffIgnoresNonce(t *testing.T) {
	t.Parallel()
	src := newDeployment(t, stagingOrigin)
	src.ns("n", nil)
	src.create("n", "a", map[string]any{"v": 1.0, "$nonce": seal.NewNonce()})
	dst := newDeployment(t, cmsOrigin)
	importB(t, dst, snapshotOf(t, src, "n"), bundle.ImportOptions{})
	up := dst.head("n-upstream", "a").ID
	src.append("n", "a", op("replace", "/$nonce", seal.NewNonce()))
	rep := importB(t, dst, snapshotOf(t, src, "n"), bundle.ImportOptions{})
	if u := rep.Doc("n/a").Upstream; u.Class != "unchanged" || u.Head != up || len(rep.Batches) != 0 {
		t.Fatalf("a snapshot changed only in its $nonce: upstream %+v, %d batches", u, len(rep.Batches))
	}
	// A real change still diffs, without touching the $nonce.
	src.append("n", "a", op("replace", "/v", 2.0), op("replace", "/$nonce", seal.NewNonce()))
	rep = importB(t, dst, snapshotOf(t, src, "n"), bundle.ImportOptions{})
	if u := rep.Doc("n/a").Upstream; u.Class != "append" || dst.doc("n", "a")["v"] != 2.0 {
		t.Fatalf("a changed snapshot: upstream %+v", u)
	}
}

// A renamed import rewrites a $successor naming a mapped namespace,
// /r/{src}/…, as any reference: in history lines, the value of an add or
// replace at /$successor, and in snapshot documents. A bare one needs
// nothing (§8.1, §G.4.4, MF-48).
func TestV073RenameSuccessor(t *testing.T) {
	t.Parallel()
	src := newDeployment(t, stagingOrigin)
	src.ns("a", nil)
	src.ns("b", nil)
	src.create("b", "new", map[string]any{"t": 1.0})
	src.create("a", "old", map[string]any{"t": 0.0})
	src.append("a", "old", op("add", "/$successor", "/r/b/new"))
	src.append("a", "old", op("replace", "/t", 9.0), op("replace", "/$successor", "/r/b/new"))
	must(src.c.Delete(ctx, "a", "old", src.head("a", "old").ID))
	src.create("a", "local", map[string]any{"t": 2.0})
	localLast := src.append("a", "local", op("add", "/$successor", "sibling"))
	must(src.c.Delete(ctx, "a", "local", localLast))
	src.create("a", "live", map[string]any{"t": 3.0, "$successor": "/r/b/new"})

	var full bytes.Buffer
	_, _, err := bundle.Export(ctx, src.c, &full, bundle.ExportOptions{Select: []string{"a/old", "a/local", "b/new"}})
	noErr(t, err)
	dst := newDeployment(t, cmsOrigin)
	rep := importB(t, dst, full.Bytes(), bundle.ImportOptions{NSMap: map[string]string{"b": "b2"}})
	h := dst.head("a", "old")
	if h.State != client.Tombstoned || h.Successor != "/r/b2/new" {
		t.Fatalf("a/old: %+v, want a tombstone whose successor is /r/b2/new", h)
	}
	if d := rep.Doc("a/old"); !d.Renamed {
		t.Fatalf("a/old not rewritten: %+v", d)
	}
	for _, u := range rep.Undeclared {
		if u.Pointer == "/$successor" {
			t.Errorf("a $successor listed as undeclared: %+v", u)
		}
	}
	// Its first $successor revision names the new path too.
	es := must(dst.c.Log(ctx, "a", "old", h.Last, ""))
	for _, e := range es {
		if bytes.Contains(jsonv.Canonical(must(client.ToValue(e.Patches))), []byte("/r/b/new")) {
			t.Errorf("revision %s still names /r/b/new", e.ID)
		}
	}
	// A bare successor isn't a reference: ids kept.
	if hl := dst.head("a", "local"); hl.Last != localLast || hl.Successor != "sibling" {
		t.Fatalf("a/local: %+v", hl)
	}

	// A snapshot document's $successor.
	var snap bytes.Buffer
	_, _, err = bundle.Export(ctx, src.c, &snap, bundle.ExportOptions{Select: []string{"a/live", "b/new"}, Mode: bundle.Snapshot})
	noErr(t, err)
	dst2 := newDeployment(t, cmsOrigin)
	importB(t, dst2, snap.Bytes(), bundle.ImportOptions{NSMap: map[string]string{"b": "b2"}})
	for _, ns := range []string{"a", "a-upstream"} {
		if d := dst2.doc(ns, "live"); d["$successor"] != "/r/b2/new" {
			t.Fatalf("%s/live: %v", ns, d)
		}
	}
}

// As a target, a sealed namespace whose read is public ranks public
// (§2.1): the importer reads its read with its keys, and refuses a private
// or sealed source into it at step 1 unless overridden. Ranks apply only
// between namespaces: a bundle of a namespace back into itself isn't
// ranked (§G.5.1, MF-52).
func TestV073SealedPublicTargetRanksPublic(t *testing.T) {
	t.Parallel()
	src := newEncDeployment(t, stagingOrigin)
	src.ns("s", map[string]any{"read": "grant", "encryption": map[string]any{"level": "sealed"}})
	must(src.c.Create(ctx, "s", "a", append(client.GenesisPatches(map[string]any{"v": marker}), op("add", "/$nonce", seal.NewNonce()))))
	var sb bytes.Buffer
	_, _, err := bundle.Export(ctx, src.c, &sb, bundle.ExportOptions{Select: []string{"s"}, Plaintext: true})
	noErr(t, err)
	priv := newDeployment(t, stagingOrigin)
	priv.ns("p", map[string]any{"read": "grant"})
	priv.create("p", "a", map[string]any{"v": marker})
	var pb bytes.Buffer
	_, _, err = bundle.Export(ctx, priv.c, &pb, bundle.ExportOptions{Select: []string{"p"}, Plaintext: true})
	noErr(t, err)

	sealedPublic := map[string]any{"read": "public", "encryption": map[string]any{"level": "sealed"}}
	dst := newEncDeployment(t, cmsOrigin)
	dst.ns("s", sealedPublic)
	dst.ns("p", sealedPublic)
	importErr(t, dst, sb.Bytes(), bundle.ImportOptions{}, "s is sealed with read public, which ranks public as a target")
	importErr(t, dst, pb.Bytes(), bundle.ImportOptions{}, "p is sealed with read public, which ranks public as a target")
	if h := dst.head("s", "a"); h.State != client.NotFound {
		t.Fatal("a refused import wrote")
	}
	rep := importB(t, dst, sb.Bytes(), bundle.ImportOptions{AllowLessProtected: true})
	if !strings.Contains(strings.Join(rep.Notes, " "), "overrode") || dst.doc("s", "a")["v"] != marker {
		t.Fatalf("override: %v", rep.Notes)
	}
	// With read grant it ranks sealed, as its source.
	dst2 := newEncDeployment(t, cmsOrigin)
	dst2.ns("s", map[string]any{"read": "grant", "encryption": map[string]any{"level": "sealed"}})
	importB(t, dst2, sb.Bytes(), bundle.ImportOptions{})
	// A sealed public namespace's own bundle, back into it.
	dst.ns("own", sealedPublic)
	must(dst.c.Create(ctx, "own", "a", append(client.GenesisPatches(map[string]any{"v": 1.0}), op("add", "/$nonce", seal.NewNonce()))))
	var ob bytes.Buffer
	_, osum, err := bundle.Export(ctx, dst.c, &ob, bundle.ExportOptions{Select: []string{"own"}, Plaintext: true})
	noErr(t, err)
	if osum.Header.Access["own"] != bundle.AccessSealed {
		t.Fatalf("source access %v", osum.Header.Access)
	}
	if rep := importB(t, dst, ob.Bytes(), bundle.ImportOptions{}); rep.Doc("own/a").Class != "present" {
		t.Fatalf("own bundle: %+v", rep.Doc("own/a"))
	}
	// Into another namespace of the same deployment, it is ranked.
	importErr(t, dst, ob.Bytes(), bundle.ImportOptions{NSMap: map[string]string{"own": "p"}}, "less protected")
}
