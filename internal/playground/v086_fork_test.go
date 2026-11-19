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
	"regexp"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/seal"
)

// v0.86 §E.2.2 Protected header ("Where they can't place that parent, the
// op fails the check (§E.3.2)"; ENC-14; Encryption levels scenario 87),
// §G.4.1 (the foreign parent is the head the branch's /heads lists at its
// first ns_id), in the playground's fold (foldLog, nsChainOK) under node
// against a live deployment. eb is an end-to-end branch of e, forked at
// d's second revision, with one write of its own after it.
//
//   - A reader that may read neither e's /heads nor eb's: every op sealed
//     under e is flagged and folded as [], so a fold of them alone has no
//     valid revision, and eb's own write still folds.
//   - A reader that may not read e's /heads: the fork is placed from eb's
//     own /heads at its first namespace entry, what eb reads through
//     folds, and an entry sealed under e spliced after the fork is flagged.
//   - eb served as a remote branch of e (base.origin, base.chain): the
//     fork is placed from eb's own /heads alone, and where the reader may
//     not read it nothing sealed under e is accepted.
//
// Until v0.86 the playground checked no fork it couldn't place, and none
// at all for a remote base.
func TestV086ForkUnplacedWithNode(t *testing.T) {
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
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	_, err := x.InitKeyring(ctx, "e")
	must(err)
	w1, err := x.CreateDocSealed(ctx, "e", "d", map[string]any{"n": 1.0})
	must(err)
	fk, err := x.AppendSealed(ctx, "e", "d", w1.ID, []any{map[string]any{"op": "replace", "path": "/n", "value": 2.0}})
	must(err)
	fork := fk.ID
	_, err = c.CreateBranch(ctx, "e", client.BranchRequest{Name: "eb"})
	must(err)
	_, err = x.InitKeyring(ctx, "eb")
	must(err)
	// eb's own write, of the whole document: it applies whatever precedes it.
	ow, err := x.AppendSealed(ctx, "eb", "d", fork, []any{map[string]any{"op": "add", "path": "", "value": map[string]any{"n": 9.0}}})
	must(err)
	own := ow.ID
	ke, err := x.Key(ctx, "e#1")
	must(err)
	keb, err := x.Key(ctx, "eb#1")
	must(err)
	kr, _ := seal.ResourceKey(ke, "e", "d")
	sealedOp, err := seal.SealPatchSet(kr, "e#1", "e", "d", fork, jsonv.FromGo([]any{map[string]any{"op": "replace", "path": "/n", "value": 3.0}}))
	must(err)
	fv := jsonv.MustParse(sealedOp)
	forgedID, err := client.ExpectedRevision(fork, fv)
	must(err)
	forged := map[string]any{"id": forgedID, "parent": fork, "kind": "rev", "patches": fv, "author": "user:a", "created": "2026-10-04T12:00:00Z"}
	ebHead, err := c.NSHead(ctx, "eb")
	must(err)
	ebDoc, err := c.NSDoc(ctx, "eb", ebHead.ID)
	must(err)
	remoteDoc := map[string]any{}
	for k, v := range ebDoc.Value {
		remoteDoc[k] = v
	}
	rb := map[string]any{"origin": "https://a.example", "chain": []any{"e"}}
	for k, v := range ebDoc.Value["base"].(map[string]any) {
		rb[k] = v
	}
	remoteDoc["base"] = rb

	js, err := assets.ReadFile("static/app.js")
	must(err)
	var fns []string
	for _, f := range []string{"logPages", "pageEndErr", "jweID", "readLogRange", "revTarget", "notOffered", "readDoc", "nsFirstEntry", "revPrecedes", "nsChainOK",
		"epochKey", "contentKey", "openSealed", "decrypted", "openSnapshot", "foldLog", "nsDocPL", "nsHeadDoc", "openSealedEntries", "loadHistory", "openEntries"} {
		fns = append(fns, jsFunction(t, js, f))
	}
	const stub = `async function nsInfo(ns) { return { level: 'e2e', doc: { encryption: { level: 'e2e' } } }; }`
	if !strings.Contains(xrevHarness, stub) {
		t.Fatal("xrevHarness's nsInfo stub changed")
	}
	harness := strings.Replace(xrevHarness, stub, `async function nsInfo(ns) { return { level: 'e2e', doc: (input.nsDocs || {})[ns] || { encryption: { level: 'e2e' } } }; }`, 1)
	dir := t.TempDir()
	h := filepath.Join(dir, "harness.js")
	must(os.WriteFile(h, []byte(strings.Replace(harness, "FUNCTIONS", strings.Join(fns, "\n"), 1)), 0o644))
	sealJS, _ := filepath.Abs("static/seal.js")
	origin, _ := url.Parse(s.URL)

	type result struct {
		Doc     map[string]any
		Err     string
		Flagged int
		Paths   []string
	}
	// run folds eb/d at its fork, at eb's own write and at the spliced
	// entry, through a proxy that answers 403 to the /heads deny matches.
	run := func(name string, deny *regexp.Regexp, nsDoc map[string]any) map[string]result {
		rp := httputil.NewSingleHostReverseProxy(origin)
		rp.ModifyResponse = func(res *http.Response) error {
			if res.Request.Header.Get("X-Spliced") == "" {
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
			switch p := r.URL.Path; {
			case deny != nil && strings.HasSuffix(p, "/heads") && deny.MatchString(p):
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(403)
				io.WriteString(w, `{"error":"forbidden","code":"forbidden"}`)
				return
			case p == "/r/eb/d/rev/"+forgedID:
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(404)
				io.WriteString(w, `{"error":"not offered","code":"not_offered"}`)
				return
			case p == "/r/eb/d/rev/"+forgedID+"/log":
				r.URL.Path = "/r/eb/d/rev/" + fork + "/log"
				r.Header.Set("X-Spliced", "1")
			}
			rp.ServeHTTP(w, r)
		}))
		t.Cleanup(px.Close)
		in, _ := json.Marshal(map[string]any{"mode": "reads", "base": px.URL, "bearer": grant,
			"keys":   map[string]string{"e#1": b64u.EncodeToString(ke), "eb#1": b64u.EncodeToString(keb)},
			"nsDocs": map[string]any{"eb": nsDoc},
			"reads": []any{
				map[string]any{"key": "through", "ns": "eb", "name": "d", "id": fork, "path": "/r/eb/d/rev/" + fork},
				map[string]any{"key": "own", "ns": "eb", "name": "d", "id": own, "path": "/r/eb/d/rev/" + own},
				map[string]any{"key": "spliced", "ns": "eb", "name": "d", "id": forgedID, "path": "/r/eb/d/rev/" + forgedID},
			}})
		inPath := filepath.Join(dir, name+".json")
		must(os.WriteFile(inPath, in, 0o644))
		cmd := exec.Command(node, h, sealJS, inPath)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		b, err := cmd.Output()
		if err != nil {
			t.Fatalf("%s: node: %v\n%s", name, err, stderr.String())
		}
		var out map[string]result
		if err := json.Unmarshal(b, &out); err != nil {
			t.Fatalf("%s: node output %s: %v", name, b, err)
		}
		return out
	}
	asked := func(r result, prefix string) int {
		n := 0
		for _, p := range r.Paths {
			if strings.HasPrefix(p, prefix) && strings.Contains(p, "/heads") {
				n++
			}
		}
		return n
	}
	placed := func(name string, out map[string]result) {
		t.Helper()
		if r := out["through"]; r.Err != "" || r.Flagged != 0 || r.Doc["n"] != 2.0 {
			t.Errorf("%s: the base's entries read through: %+v", name, r)
		}
		if r := out["own"]; r.Err != "" || r.Flagged != 0 || r.Doc["n"] != 9.0 {
			t.Errorf("%s: the branch's own write: %+v", name, r)
		}
		if r := out["spliced"]; r.Err != "" || r.Flagged != 1 || r.Doc["n"] != 2.0 {
			t.Errorf("%s: an entry sealed under the base past the fork: %+v, want it flagged and the fork's document", name, r)
		}
	}
	unplaced := func(name string, out map[string]result) {
		t.Helper()
		// Nothing but e's entries, each folded as []: there is no document.
		if r := out["through"]; !strings.Contains(r.Err, "no valid revision") || r.Doc != nil {
			t.Errorf("%s: the base's entries, the fork unplaced: %+v, want no valid revision", name, r)
		}
		if r := out["own"]; r.Err != "" || r.Flagged != 2 || r.Doc["n"] != 9.0 {
			t.Errorf("%s: the branch's own write over entries folded as []: %+v", name, r)
		}
		if r := out["spliced"]; !strings.Contains(r.Err, "no valid revision") || r.Doc != nil {
			t.Errorf("%s: the spliced entry, the fork unplaced: %+v, want no valid revision", name, r)
		}
	}

	both := regexp.MustCompile(`^/ns/(e|eb)/`)
	out := run("neither", both, ebDoc.Value)
	unplaced("neither /heads readable", out)
	if asked(out["through"], "/ns/e/") == 0 || asked(out["through"], "/ns/eb/") == 0 {
		t.Errorf("the fold asked for the base's /heads and then the branch's own: %v", out["through"].Paths)
	}

	out = run("own", regexp.MustCompile(`^/ns/e/`), ebDoc.Value)
	placed("the fork placed from the branch's own /heads", out)
	if asked(out["through"], "/ns/eb/") != 1 {
		t.Errorf("the branch's own /heads at its first entry is read once: %v", out["through"].Paths)
	}

	out = run("remote", nil, remoteDoc)
	placed("a remote base", out)
	if asked(out["through"], "/ns/e/") != 0 {
		t.Errorf("a remote base's /heads was asked for here: %v", out["through"].Paths)
	}
	unplaced("a remote base, the branch's own /heads unreadable", run("remote-unplaced", regexp.MustCompile(`^/ns/eb/`), remoteDoc))
}
