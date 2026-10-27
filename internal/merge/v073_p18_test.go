package merge_test

import (
	"bytes"
	"crypto/ecdh"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/keystore"
	"github.com/middle-management/patchlog/internal/merge"
	"github.com/middle-management/patchlog/internal/seal"
)

// P18 review: a reader of the old e2e branch's newest epoch whose public
// key the rebasing view doesn't know isn't dropped silently (§F.8.1,
// §E.3.2). Rebase reports it in DroppedReaders; with Switch it stops
// before replaying (ErrReadersDropped), so the old branch stays in use.
// Run again with the reader as a SuccessorReader (not a sender), the
// rebase resumes, wraps the successor's key for it, and switches.
func TestV073RebaseKeepsOldBranchReaders(t *testing.T) {
	t.Parallel()
	e := newE3(t, map[string]any{"encryption": map[string]any{"level": "e2e"}})
	_, reader, err := seal.GenerateRecipient()
	noErr(t, err)
	tp := seal.Thumbprint(reader.PublicKey())
	must(e.c.CreateBranch(ctx, "m", client.BranchRequest{Name: "r7"}))
	must(e.x.InitKeyring(ctx, "r7", reader.PublicKey()))
	e.append("r7", "derby", op("replace", "/score", "1-0"))

	// Without Switch: reported, nothing refused.
	res, err := merge.Rebase(ctx, e.c, merge.RebaseOptions{Branch: "r7", New: "r7a", Plan: merge.Options{E2E: e.x}})
	noErr(t, err)
	if len(res.DroppedReaders) != 1 || res.DroppedReaders[0] != tp || res.FirstResult == nil {
		t.Fatalf("rebase without switch: %+v", res)
	}

	// With Switch: refused before the replay, the old branch not frozen.
	res, err = merge.Rebase(ctx, e.c, merge.RebaseOptions{Branch: "r7", New: "r7b", Switch: true, Plan: merge.Options{E2E: e.x}})
	if !errors.Is(err, merge.ErrReadersDropped) || res == nil || res.Switched || res.First != nil ||
		len(res.DroppedReaders) != 1 || res.DroppedReaders[0] != tp || !strings.Contains(err.Error(), tp) {
		t.Fatalf("switch dropping a reader: %+v, %v", res, err)
	}
	if p := must(e.c.NSDoc(ctx, "r7", must(e.c.NSHead(ctx, "r7")).ID)); p.Value["frozen"] != nil {
		t.Fatalf("the old branch was frozen: %v", p.Value)
	}

	// Resumed with the reader named: its key is added, and the switch goes on.
	res, err = merge.Rebase(ctx, e.c, merge.RebaseOptions{Branch: "r7", New: "r7b", Switch: true, Plan: merge.Options{E2E: e.x},
		SuccessorReaders: []*ecdh.PublicKey{reader.PublicKey()}})
	noErr(t, err)
	if !res.Switched || res.Created || len(res.DroppedReaders) != 0 {
		t.Fatalf("resumed rebase: %+v", res)
	}
	kr, _ := must2(e.x.Keyring(ctx, "r7b"))
	key := must(kr.EpochKey(reader, seal.Kid("r7b", kr.Current("r7b")), []*ecdh.PublicKey{e.priv.PublicKey()}))
	if !bytes.Equal(key, must(e.x.Key(ctx, seal.Kid("r7b", kr.Current("r7b"))))) {
		t.Fatal("the reader's entry holds another key")
	}
	sameDoc(t, e.doc("r7b", "derby"), map[string]any{"title": "Derby", "score": "1-0"})

	// Named from the start, a new successor gets the reader at once.
	res, err = merge.Rebase(ctx, e.c, merge.RebaseOptions{Branch: "r7b", New: "r7c", Switch: true, Plan: merge.Options{E2E: e.x},
		SuccessorReaders: []*ecdh.PublicKey{reader.PublicKey()}})
	noErr(t, err)
	if !res.Switched || len(res.DroppedReaders) != 0 {
		t.Fatalf("rebase naming the reader: %+v", res)
	}
}

// legacyKeyringTransport serves the keyring revisions of the namespaces in
// paths as body, a keyring document in the format before v0.63, playing a
// keyring stored before the upgrade.
func legacyKeyringTransport(body []byte, nss ...string) http.RoundTripper {
	base := http.DefaultTransport.(*http.Transport).Clone()
	return rtFunc(func(req *http.Request) (*http.Response, error) {
		res, err := base.RoundTrip(req)
		if err != nil || req.Method != "GET" || res.StatusCode != 200 {
			return res, err
		}
		hit := false
		for _, ns := range nss {
			hit = hit || strings.HasPrefix(req.URL.Path, "/r/"+ns+"/keyring/rev/")
		}
		if !hit {
			return res, nil
		}
		io.Copy(io.Discard, res.Body)
		res.Body.Close()
		res.Body = io.NopCloser(bytes.NewReader(body))
		res.ContentLength = int64(len(body))
		res.Header.Del("Content-Length")
		return res, nil
	})
}

// P18 review: a base whose keyring is still in the format before v0.63
// doesn't block rebasing an e2e branch with a keyring of its own: the
// keyring a namespace reads through from its base isn't its own, legacy
// or not. A branch whose own keyring is in that format is refused with
// the namespace to migrate named.
func TestV073RebaseUnderLegacyKeyrings(t *testing.T) {
	t.Parallel()
	ks, err := keystore.New(keystore.Generate())
	noErr(t, err)
	s := clienttest.New(t, clienttest.Options{KeyStore: ks})
	c := s.Client(t, client.WithAuthor("alice"))
	_, priv, err := seal.GenerateRecipient()
	noErr(t, err)
	x := c.E2E(priv)
	must(c.CreateNamespace(ctx, "m", map[string]any{"encryption": map[string]any{"level": "e2e"}}))
	must(x.InitKeyring(ctx, "m"))
	must(x.CreateDocSealed(ctx, "m", "derby", map[string]any{"title": "Derby", "score": "0-0"}))
	km := must(x.Key(ctx, "m#1"))
	for _, br := range []string{"r7", "r8"} {
		must(c.CreateBranch(ctx, "m", client.BranchRequest{Name: br}))
		must(x.InitKeyring(ctx, br))
		h := must(c.Head(ctx, br, "derby"))
		must(x.AppendSealed(ctx, br, "derby", h.ID, ops(op("replace", "/score", "1-0"))))
	}
	legacy, _ := json.Marshal(must(seal.BuildKeyring("m", 1, km, []*ecdh.PublicKey{priv.PublicKey()})).Value())

	// m's keyring, and so the one r7b reads through when created, legacy.
	c2 := s.Client(t, client.WithAuthor("alice"), client.WithHTTPClient(&http.Client{Transport: legacyKeyringTransport(legacy, "m", "r7b")}))
	x2 := c2.E2E(priv)
	res, err := merge.Rebase(ctx, c2, merge.RebaseOptions{Branch: "r7", New: "r7b", Switch: true, Plan: merge.Options{E2E: x2}})
	noErr(t, err)
	if !res.Switched {
		t.Fatalf("rebase under a legacy base keyring: %+v", res)
	}
	sameDoc(t, (&e3env{t: t, c: c, x: x, priv: priv}).doc("r7b", "derby"), map[string]any{"title": "Derby", "score": "1-0"})

	// r8's own keyring legacy: refused, naming r8.
	k8 := must(x.Key(ctx, "r8#1"))
	legacy8, _ := json.Marshal(must(seal.BuildKeyring("r8", 1, k8, []*ecdh.PublicKey{priv.PublicKey()})).Value())
	c3 := s.Client(t, client.WithAuthor("alice"), client.WithHTTPClient(&http.Client{Transport: legacyKeyringTransport(legacy8, "r8")}))
	_, err = merge.Rebase(ctx, c3, merge.RebaseOptions{Branch: "r8", New: "r8b", Plan: merge.Options{E2E: c3.E2E(priv)}})
	if err == nil || !strings.Contains(err.Error(), "migrate-keyring -ns r8") {
		t.Fatalf("rebase of a branch whose own keyring is legacy: %v", err)
	}
}
