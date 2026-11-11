package core_test

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/archive"
	"github.com/middle-management/patchlog/internal/bundle"
	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/keystore"
	"github.com/middle-management/patchlog/internal/seal"
)

// Spec v0.82, prune archives (§8.6, §G.5.1 access; FED-5, BT-4): the
// server writes access in an archive's header, the namespace's protection
// as a source (§2.1), so an importer goes by it as by an export's.

// v82toolsArchives is a deployment with encryption and a file archiver.
type v82toolsArchives struct {
	t   *testing.T
	ctx context.Context
	dir string
	srv *clienttest.Server
	c   *client.Client
	x   *client.E2E
}

func v82toolsNewArchives(t *testing.T) *v82toolsArchives {
	t.Helper()
	ks, err := keystore.New(keystore.Generate())
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	a, err := archive.NewDir(archive.URL(dir))
	if err != nil {
		t.Fatal(err)
	}
	srv := clienttest.New(t, clienttest.Options{KeyStore: ks, Archiver: a})
	c := srv.Client(t, client.WithAuthor("alice"), client.WithKeys(client.NewKeys(nil)))
	_, priv, err := seal.GenerateRecipient()
	if err != nil {
		t.Fatal(err)
	}
	return &v82toolsArchives{t: t, ctx: context.Background(), dir: dir, srv: srv, c: c, x: c.E2E(priv)}
}

func v82toolsMust[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

// chain writes three revisions of ns/a, by the namespace's level, and
// returns their ids.
func (w *v82toolsArchives) chain(ns string, e2e, nonces bool) []string {
	w.t.Helper()
	ctx := w.ctx
	var revs []string
	if e2e {
		revs = append(revs, v82toolsMust(w.x.CreateDocSealed(ctx, ns, "a", map[string]any{"n": 0.0})).ID)
		for i := 1; i < 3; i++ {
			ps := []any{map[string]any{"op": "replace", "path": "/n", "value": float64(i)}}
			revs = append(revs, v82toolsMust(w.x.AppendSealed(ctx, ns, "a", revs[i-1], ps)).ID)
		}
		return revs
	}
	with := func(ps []any) []any {
		if nonces {
			ps = append(ps, map[string]any{"op": "add", "path": "/$nonce", "value": seal.NewNonce()})
		}
		return ps
	}
	revs = append(revs, v82toolsMust(w.c.Create(ctx, ns, "a", with(client.GenesisPatches(map[string]any{"n": 0.0})))).ID)
	for i := 1; i < 3; i++ {
		ps := with([]any{map[string]any{"op": "replace", "path": "/n", "value": float64(i)}})
		revs = append(revs, v82toolsMust(w.c.Append(ctx, ns, "a", revs[i-1], ps)).ID)
	}
	return revs
}

// pruned prunes ns/a below horizon and returns the archive's bundle,
// decrypted where the namespace is encrypted (Engine.ReadArchive).
func (w *v82toolsArchives) pruned(ns, horizon string, e2e bool) []byte {
	w.t.Helper()
	ctx := w.ctx
	// Past the time a prune leaves recent revisions alone (§8.6).
	w.srv.Clock.Advance(2 * time.Hour)
	var res *client.PruneResult
	if e2e {
		res = v82toolsMust(w.x.PruneE2E(ctx, ns, "a", horizon))
	} else {
		res = v82toolsMust(w.c.Prune(ctx, ns, "a", client.PruneRequest{Horizon: horizon}))
	}
	if res.Horizon != horizon {
		w.t.Fatalf("%s/a pruned to %s, want %s", ns, res.Horizon, horizon)
	}
	raw := v82toolsMust(os.ReadFile(filepath.Join(w.dir, ns, "a", horizon+".jsonl")))
	r := v82toolsMust(w.srv.Engine.ReadArchive(ctx, ns, "a", bytes.NewReader(raw)))
	return v82toolsMust(io.ReadAll(r))
}

// BT-4 (§G.5.1 access, §8.6, §2.1): a prune's archive names its
// namespace's protection as a source: public or private by its read
// without encryption or at rest, sealed at E2 whatever its read, e2e at
// E3. (A branch writes no archive, §8.6 "Branches don't prune";
// archiveAccess gives its own protection, v082_tools_access_test.go.)
func TestV082ToolsArchiveHeaderAccess(t *testing.T) {
	t.Parallel()
	w := v82toolsNewArchives(t)
	ctx := w.ctx
	enc := func(read, level string) map[string]any {
		doc := map[string]any{"read": read}
		if level != "" {
			doc["encryption"] = map[string]any{"level": level}
		}
		return doc
	}
	for _, c := range []struct {
		ns   string
		doc  map[string]any
		want string
	}{
		{"pub", enc("public", ""), bundle.AccessPublic},
		{"priv", enc("grant", ""), bundle.AccessPrivate},
		{"rest-pub", enc("public", "at-rest"), bundle.AccessPublic},
		{"rest-priv", enc("grant", "at-rest"), bundle.AccessPrivate},
		{"sealed-pub", enc("public", "sealed"), bundle.AccessSealed},
		{"sealed-priv", enc("grant", "sealed"), bundle.AccessSealed},
		{"e", enc("grant", "e2e"), bundle.AccessE2E},
	} {
		encDoc, _ := c.doc["encryption"].(map[string]any)
		lv, _ := encDoc["level"].(string)
		e2e, sealed := lv == "e2e", lv == "sealed"
		v82toolsMust(w.c.CreateNamespace(ctx, c.ns, c.doc))
		if e2e {
			v82toolsMust(w.x.InitKeyring(ctx, c.ns))
		}
		revs := w.chain(c.ns, e2e, sealed)
		b := w.pruned(c.ns, revs[len(revs)-1], e2e)
		sum, err := bundle.Verify(bytes.NewReader(b))
		if err != nil {
			t.Fatalf("%s: the archive: %v", c.ns, err)
		}
		if got := sum.Header.Access; len(got) != 1 || got[c.ns] != c.want {
			t.Fatalf("%s: header access %v, want %s", c.ns, got, c.want)
		}
		// As written, a member of the header line (§G.4.1).
		hdr := jsonv.MustParse(bytes.SplitN(b, []byte("\n"), 2)[0]).(map[string]any)
		if a, _ := hdr["access"].(map[string]any); a[c.ns] != c.want {
			t.Fatalf("%s: header line %v", c.ns, hdr)
		}
	}
}

// v82toolsTarget is another deployment, to import into.
func v82toolsTarget(t *testing.T) *client.Client {
	t.Helper()
	ks, err := keystore.New(keystore.Generate())
	if err != nil {
		t.Fatal(err)
	}
	srv := clienttest.New(t, clienttest.Options{KeyStore: ks})
	return srv.Client(t, client.WithAuthor("alice"), client.WithKeys(client.NewKeys(nil)))
}

// v82toolsRefused imports b into c with opt and wants an access refusal
// (step 1, §G.5.1) containing want.
func v82toolsRefused(t *testing.T, what string, c *client.Client, b []byte, opt bundle.ImportOptions, want string) {
	t.Helper()
	opt.Mode, opt.CreateNamespaces = bundle.Atomic, true
	_, err := bundle.Import(context.Background(), c, bundle.BytesOpener(b), opt)
	var ae *bundle.AccessError
	if err == nil || !errors.As(err, &ae) || !strings.Contains(err.Error(), want) {
		t.Fatalf("%s: %v, want an access refusal containing %q", what, err, want)
	}
}

// Scenario 49 (§G.5.1, §8.6, §2.1; BT-4): an e2e namespace's archive,
// decrypted, says "e2e", so its lines are refused at step 1 for any
// target but an e2e one of the same name, override or not; nothing is
// written.
func TestV082ToolsE2EArchiveRefusedElsewhere(t *testing.T) {
	t.Parallel()
	w := v82toolsNewArchives(t)
	ctx := w.ctx
	v82toolsMust(w.c.CreateNamespace(ctx, "e", map[string]any{"read": "grant", "encryption": map[string]any{"level": "e2e"}}))
	v82toolsMust(w.x.InitKeyring(ctx, "e"))
	revs := w.chain("e", true, false)
	b := w.pruned("e", revs[2], true)
	if sum := v82toolsMust(bundle.Verify(bytes.NewReader(b))); sum.Header.Access["e"] != bundle.AccessE2E || sum.Lines != 2 {
		t.Fatalf("the e2e archive: %d lines, access %v", sum.Lines, sum.Header.Access)
	}

	// Under another name.
	dst := v82toolsTarget(t)
	for _, allow := range []bool{false, true} {
		v82toolsRefused(t, "as other", dst, b, bundle.ImportOptions{NSMap: map[string]string{"e": "other"}, AllowLessProtected: allow}, "only be imported under its own name")
	}
	for _, ns := range []string{"e", "other"} {
		if _, err := dst.NSHead(ctx, ns); !client.IsNotFound(err) {
			t.Fatalf("the refused import created %s: %v", ns, err)
		}
	}
	// Into same-named targets that aren't e2e.
	for name, doc := range map[string]map[string]any{
		"private": {"read": "grant"},
		"public":  {"read": "public"},
		"sealed":  {"read": "grant", "encryption": map[string]any{"level": "sealed"}},
	} {
		dst := v82toolsTarget(t)
		v82toolsMust(dst.CreateNamespace(ctx, "e", doc))
		for _, allow := range []bool{false, true} {
			v82toolsRefused(t, "into a "+name+" e", dst, b, bundle.ImportOptions{AllowLessProtected: allow}, "can only go into an e2e target")
		}
		if h := v82toolsMust(dst.Head(ctx, "e", "a")); h.State != client.NotFound {
			t.Fatalf("the refused import into a %s e wrote a: %+v", name, h)
		}
	}
}

// BT-4, stored data (stored.md): an archive written before v0.82 has no
// access, which a header reads as private. One of an e2e namespace must
// not go in as private plaintext anywhere: its sealed ops refuse the
// import at step 1, whatever the target, override or not, and nothing is
// written. Restore, which goes by ids, ignores access and still takes it.
func TestV082ToolsOldE2EArchiveWithoutAccess(t *testing.T) {
	t.Parallel()
	w := v82toolsNewArchives(t)
	ctx := w.ctx
	v82toolsMust(w.c.CreateNamespace(ctx, "e", map[string]any{"read": "grant", "encryption": map[string]any{"level": "e2e"}}))
	v82toolsMust(w.x.InitKeyring(ctx, "e"))
	revs := w.chain("e", true, false)
	b := w.pruned("e", revs[2], true)
	// As v0.27.0 wrote it: the same bundle without the header's access.
	ls := bytes.Split(bytes.TrimSuffix(b, []byte("\n")), []byte("\n"))
	hdr := jsonv.MustParse(ls[0]).(map[string]any)
	delete(hdr, "access")
	ls[0] = jsonv.Canonical(hdr)
	old := append(bytes.Join(ls, []byte("\n")), '\n')
	sum := v82toolsMust(bundle.Verify(bytes.NewReader(old)))
	if len(sum.Header.Access) != 0 || sum.Header.AccessOf("e") != bundle.AccessPrivate {
		t.Fatalf("the old archive's access: %v", sum.Header.Access)
	}

	// A target created for the import, as private.
	dst := v82toolsTarget(t)
	for _, opt := range []bundle.ImportOptions{{}, {AllowLessProtected: true}, {NSMap: map[string]string{"e": "other"}}} {
		v82toolsRefused(t, "an old e2e archive", dst, old, opt, "is a sealed op")
	}
	for _, ns := range []string{"e", "other"} {
		if _, err := dst.NSHead(ctx, ns); !client.IsNotFound(err) {
			t.Fatalf("the refused import created %s: %v", ns, err)
		}
	}
	// Existing targets of every level, the same-named e2e one included:
	// the bundle doesn't say what it is.
	for name, doc := range map[string]map[string]any{
		"private": {"read": "grant"},
		"public":  {"read": "public"},
		"sealed":  {"read": "grant", "encryption": map[string]any{"level": "sealed"}},
		"e2e":     {"read": "grant", "encryption": map[string]any{"level": "e2e"}},
	} {
		dst := v82toolsTarget(t)
		v82toolsMust(dst.CreateNamespace(ctx, "e", doc))
		for _, allow := range []bool{false, true} {
			v82toolsRefused(t, "an old e2e archive into a "+name+" e", dst, old, bundle.ImportOptions{AllowLessProtected: allow}, "is a sealed op")
		}
		if h := v82toolsMust(dst.Head(ctx, "e", "a")); h.State != client.NotFound {
			t.Fatalf("the refused import into a %s e wrote a: %+v", name, h)
		}
	}

	// Restore (§D.4) reads the archive without its access: written back
	// in place of the new one, sealed again to the resource's archive key.
	id := v82toolsMust(w.srv.Engine.ArchiveIdentity(ctx, "e", "a"))
	p := filepath.Join(w.dir, "e", "a", revs[2]+".jsonl")
	f := v82toolsMust(os.Create(p))
	sw := v82toolsMust(bundle.NewSealedWriter(f, []*ecdh.PublicKey{id.PublicKey()}))
	v82toolsMust(sw.Write(old))
	if err := sw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	reps := v82toolsMust(archive.Restore(ctx, w.srv.Engine, archive.RestoreOptions{NS: "e", Name: "a"}))
	if len(reps) != 1 || len(reps[0].Failed) != 0 || reps[0].Archives != 1 {
		t.Fatalf("restore of the old archive: %+v", reps)
	}
	log := v82toolsMust(w.c.Log(ctx, "e", "a", revs[2], ""))
	if len(log) != 3 || log[0].ID != revs[0] || !log[0].HasPatches {
		t.Fatalf("the restored log: %+v", log)
	}
}
