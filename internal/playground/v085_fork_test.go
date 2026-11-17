package playground

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/seal"
)

// v0.85 §E.2.2 Protected header, §E.3.1 (ENC-14; E2E scenario 81): at E3 a
// reader accepts a base's ns in a sealed patch set's pl and kid only up
// to the resource's foreign parent. The playground's fold (foldLog,
// nsChainOK), run under node against a live deployment: in eb, an
// end-to-end branch of e, d's entries read through from e fold; an entry
// sealed under e's key with e's pl, spliced into eb's log after the fork
// (played by a proxy), is flagged and folded as [], so the document stays
// the fork's. Until v0.85 the playground accepted a base's key anywhere
// in the log.
func TestV085ForkBoundWithNode(t *testing.T) {
	t.Parallel()
	node := needNode(t)
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{Auth: true, KeyStore: newTestKeyStore(t)})
	k := clienttest.NewKey("k")
	if _, err := s.Client(t, client.WithBearer(s.OperatorGrant(t, "e"))).CreateNamespace(ctx, "e",
		map[string]any{"read": "grant", "keys": []any{k.Entry("*")}, "encryption": map[string]any{"level": "e2e"}}); err != nil {
		t.Fatal(err)
	}
	jwk, priv, _ := seal.GenerateRecipient()
	grant := k.Grant(t, s.Now(), "user:a", []string{"e", "eb"}, []string{"read", "create", "append", "config", "branch"}, map[string]any{"enc": jwk})
	c := s.Client(t, client.WithBearer(grant))
	x := c.E2E(priv)
	if _, err := x.InitKeyring(ctx, "e"); err != nil {
		t.Fatal(err)
	}
	w1, err := x.CreateDocSealed(ctx, "e", "d", map[string]any{"n": 1.0})
	if err != nil {
		t.Fatal(err)
	}
	fk, err := x.AppendSealed(ctx, "e", "d", w1.ID, []any{map[string]any{"op": "replace", "path": "/n", "value": 2.0}})
	if err != nil {
		t.Fatal(err)
	}
	fork := fk.ID
	if _, err := c.CreateBranch(ctx, "e", client.BranchRequest{Name: "eb"}); err != nil {
		t.Fatal(err)
	}
	ke, err := x.Key(ctx, "e#1")
	if err != nil {
		t.Fatal(err)
	}
	kr, _ := seal.ResourceKey(ke, "e", "d")
	sealedOp, err := seal.SealPatchSet(kr, "e#1", "e", "d", fork, jsonv.FromGo([]any{map[string]any{"op": "replace", "path": "/n", "value": 3.0}}))
	if err != nil {
		t.Fatal(err)
	}
	fv := jsonv.MustParse(sealedOp)
	forgedID, err := client.ExpectedRevision(fork, fv)
	if err != nil {
		t.Fatal(err)
	}
	forged := map[string]any{"id": forgedID, "parent": fork, "kind": "rev", "patches": fv, "author": "user:a", "created": "2026-10-04T12:00:00Z"}
	ebHead, err := c.NSHead(ctx, "eb")
	if err != nil {
		t.Fatal(err)
	}
	ebDoc, err := c.NSDoc(ctx, "eb", ebHead.ID)
	if err != nil {
		t.Fatal(err)
	}

	// The proxy: eb/d as if the forged entry were its head.
	origin, _ := url.Parse(s.URL)
	rp := httputil.NewSingleHostReverseProxy(origin)
	rp.ModifyResponse = func(res *http.Response) error {
		if res.Request.URL.Path != "/r/eb/d/rev/"+fork+"/log" || res.Request.Header.Get("X-Spliced") == "" {
			return nil
		}
		var arr []any
		json.NewDecoder(res.Body).Decode(&arr)
		res.Body.Close()
		b, _ := json.Marshal(append(arr, forged))
		res.Body = io.NopCloser(bytes.NewReader(b))
		res.ContentLength = int64(len(b))
		res.Header.Del("Content-Length")
		res.Header.Del("X-Log-Next")
		return nil
	}
	px := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/r/eb/d/rev/" + forgedID:
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(404)
			io.WriteString(w, `{"error":"not offered","code":"not_offered"}`)
			return
		case "/r/eb/d/rev/" + forgedID + "/log":
			r.URL.Path = "/r/eb/d/rev/" + fork + "/log"
			r.Header.Set("X-Spliced", "1")
		}
		rp.ServeHTTP(w, r)
	}))
	t.Cleanup(px.Close)

	js, err := assets.ReadFile("static/app.js")
	if err != nil {
		t.Fatal(err)
	}
	var fns []string
	for _, f := range []string{"logPages", "pageEndErr", "jweID", "readLogRange", "revTarget", "notOffered", "readDoc", "nsChainOK",
		"epochKey", "contentKey", "openSealed", "decrypted", "openSnapshot", "foldLog", "nsDocPL", "nsHeadDoc", "openSealedEntries", "loadHistory", "openEntries"} {
		fns = append(fns, jsFunction(t, js, f))
	}
	// The harness of v081_xrev_test.go, with the namespace documents given.
	const stub = `async function nsInfo(ns) { return { level: 'e2e', doc: { encryption: { level: 'e2e' } } }; }`
	if !strings.Contains(xrevHarness, stub) {
		t.Fatal("xrevHarness's nsInfo stub changed")
	}
	harness := strings.Replace(xrevHarness, stub, `async function nsInfo(ns) { return { level: 'e2e', doc: (input.nsDocs || {})[ns] || { encryption: { level: 'e2e' } } }; }`, 1)
	dir := t.TempDir()
	h := filepath.Join(dir, "harness.js")
	if err := os.WriteFile(h, []byte(strings.Replace(harness, "FUNCTIONS", strings.Join(fns, "\n"), 1)), 0o644); err != nil {
		t.Fatal(err)
	}
	in, _ := json.Marshal(map[string]any{"mode": "reads", "base": px.URL, "bearer": grant,
		"keys":   map[string]string{"e#1": b64u.EncodeToString(ke)},
		"nsDocs": map[string]any{"eb": ebDoc.Value},
		"reads": []any{
			map[string]any{"key": "through", "ns": "eb", "name": "d", "id": fork, "path": "/r/eb/d/rev/" + fork},
			map[string]any{"key": "spliced", "ns": "eb", "name": "d", "id": forgedID, "path": "/r/eb/d/rev/" + forgedID},
		}})
	inPath := filepath.Join(dir, "input.json")
	if err := os.WriteFile(inPath, in, 0o644); err != nil {
		t.Fatal(err)
	}
	sealJS, _ := filepath.Abs("static/seal.js")
	cmd := exec.Command(node, h, sealJS, inPath)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	b, err := cmd.Output()
	if err != nil {
		t.Fatalf("node: %v\n%s", err, stderr.String())
	}
	var out map[string]struct {
		Doc     map[string]any
		Err     string
		Flagged int
		Paths   []string
	}
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("node output %s: %v", b, err)
	}
	if r := out["through"]; r.Err != "" || r.Flagged != 0 || r.Doc["n"] != 2.0 {
		t.Errorf("the base's entries read through: %+v", r)
	}
	r := out["spliced"]
	if r.Err != "" || r.Flagged != 1 || r.Doc["n"] != 2.0 {
		t.Errorf("an entry sealed under the base past the fork: %+v, want it flagged and the fork's document", r)
	}
	// The fork is the base's head of d at the branch's at, read once.
	asked := 0
	for _, p := range append(out["through"].Paths, r.Paths...) {
		if strings.HasPrefix(p, "/ns/e/rev/") && strings.Contains(p, "/heads") {
			asked++
		}
	}
	if asked != 1 {
		t.Errorf("the folds read the base's /heads at the branch's at %d times, want once: %v %v", asked, out["through"].Paths, r.Paths)
	}
}
