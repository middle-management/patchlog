package playground

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/keystore"
	"github.com/middle-management/patchlog/internal/server"
)

func (e *siEnv) mergePlan(body any, hdr ...string) (int, map[string]any) {
	e.t.Helper()
	b, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", MergePrefix+"plan", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	rec := httptest.NewRecorder()
	e.pg.ServeHTTP(rec, req)
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		e.t.Fatalf("status %d, body %q", rec.Code, rec.Body)
	}
	return rec.Code, out
}

func set(path string, v any) []any {
	return []any{map[string]any{"op": "add", "path": path, "value": v}}
}

// mergeFixture: base "matches" with a and b; branch "rel" changes a
// (fast-forward), changes b where the base changes it too (conflict) and
// creates c.
func mergeFixture(t *testing.T, e *siEnv, nsdoc map[string]any) *client.Client {
	t.Helper()
	ctx := context.Background()
	c := e.s.Client(t, client.WithAuthor("ed"))
	must := func(_ any, err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(c.CreateNamespace(ctx, "matches", nsdoc))
	a, err := c.CreateDoc(ctx, "matches", "a", map[string]any{"score": 0})
	must(a, err)
	b, err := c.CreateDoc(ctx, "matches", "b", map[string]any{"score": 0})
	must(b, err)
	must(c.CreateBranch(ctx, "matches", client.BranchRequest{Name: "rel"}))
	must(c.Append(ctx, "rel", "a", a.ID, set("/score", 1)))
	must(c.Append(ctx, "rel", "b", b.ID, set("/score", 2)))
	must(c.CreateDoc(ctx, "rel", "c", map[string]any{"score": 9}))
	must(c.Append(ctx, "matches", "b", b.ID, set("/score", 3)))
	return c
}

func resourcesByName(out map[string]any) map[string]map[string]any {
	m := map[string]map[string]any{}
	for _, r := range out["resources"].([]any) {
		x := r.(map[string]any)
		m[x["resource"].(string)] = x
	}
	return m
}

func TestMergePlanResolveAndSubmit(t *testing.T) {
	t.Parallel()
	e := newSIEnv(t, false, Options{})
	c := mergeFixture(t, e, map[string]any{"read": "public"})
	ctx := context.Background()
	before, err := c.NSHead(ctx, "matches")
	if err != nil {
		t.Fatal(err)
	}

	code, out := e.mergePlan(map[string]any{"branch": "rel"}, "X-Author", "ed")
	if code != 200 {
		t.Fatalf("%d %v", code, out)
	}
	if out["target"] != "matches" || out["clean"] != false || out["dryRun"] != nil {
		t.Fatalf("plan %v", out)
	}
	rs := resourcesByName(out)
	if rs["a"]["status"] != "ahead" || rs["c"]["status"] != "ahead" || rs["b"]["status"] != "conflicting" {
		t.Fatalf("statuses a=%v b=%v c=%v", rs["a"]["status"], rs["b"]["status"], rs["c"]["status"])
	}
	if len(out["hints"].([]any)) == 0 {
		t.Error("no hint about merge.authors")
	}

	// Re-plan pinned, with a resolution.
	code, out = e.mergePlan(map[string]any{"branch": "rel", "branchAt": out["branchAt"],
		"resolve": map[string]any{"b": set("/score", 5)}}, "X-Author", "ed")
	if code != 200 || out["clean"] != true || out["dryRunError"] != nil {
		t.Fatalf("%d %v", code, out)
	}
	if n := len(out["dryRun"].([]any)); n != 3 {
		t.Fatalf("dry run items %d", n)
	}
	// The planner wrote nothing.
	after, _ := c.NSHead(ctx, "matches")
	if after.ID != before.ID {
		t.Fatalf("the planner moved the base: %s -> %s", before.ID, after.ID)
	}

	// The batch is the wire format: submit it as the page would.
	body, _ := json.Marshal(out["batch"])
	req := httptest.NewRequest("POST", "/ns/matches/batch", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Author", "ed")
	rec := httptest.NewRecorder()
	e.api.ServeHTTP(rec, req)
	if rec.Code != 201 {
		t.Fatalf("submit %d %s", rec.Code, rec.Body)
	}
	hd, err := c.Head(ctx, "matches", "b")
	if err != nil {
		t.Fatal(err)
	}
	d, err := c.Doc(ctx, "matches", "b", hd.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := json.Marshal(d.Value); !strings.Contains(string(got), `"score":5`) {
		t.Errorf("b = %s", got)
	}
	// Fast-forwards keep the branch's ids.
	ha, _ := c.Head(ctx, "matches", "a")
	hb, _ := c.Head(ctx, "rel", "a")
	if ha.ID != hb.ID {
		t.Errorf("a: %s in the base, %s in the branch", ha.ID, hb.ID)
	}
}

func TestMergePlanNothingToMerge(t *testing.T) {
	t.Parallel()
	e := newSIEnv(t, false, Options{})
	ctx := context.Background()
	c := e.s.Client(t, client.WithAuthor("ed"))
	if _, err := c.CreateNamespace(ctx, "matches", map[string]any{"read": "public"}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.CreateBranch(ctx, "matches", client.BranchRequest{Name: "rel"}); err != nil {
		t.Fatal(err)
	}
	code, out := e.mergePlan(map[string]any{"branch": "rel"}, "X-Author", "ed")
	if code != 200 || out["batch"] != nil || out["clean"] != true || len(out["resources"].([]any)) != 0 {
		t.Fatalf("%d %v", code, out)
	}
	// Not a branch, and no base named.
	code, out = e.mergePlan(map[string]any{"branch": "matches"}, "X-Author", "ed")
	if code != 422 || out["code"] != "merge_unsupported" {
		t.Fatalf("%d %v", code, out)
	}
	code, out = e.mergePlan(map[string]any{"branch": "no/such"})
	if code != 400 {
		t.Fatalf("%d %v", code, out)
	}
	code, out = e.mergePlan(map[string]any{"branch": "nosuch"}, "X-Author", "ed")
	if code != 404 {
		t.Fatalf("%d %v", code, out)
	}
}

func TestMergePlanRefusals(t *testing.T) {
	t.Parallel()
	e := newSIEnv(t, false, Options{})
	c := mergeFixture(t, e, map[string]any{"read": "public"})
	h, err := c.NSHead(context.Background(), "matches")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.PatchConfig(context.Background(), "matches", h.Config, set("/signatures", "required")); err != nil {
		t.Fatal(err)
	}
	code, out := e.mergePlan(map[string]any{"branch": "rel"}, "X-Author", "ed")
	if code != 422 || out["code"] != "merge_unsupported" || !strings.Contains(out["message"].(string), "signatures") {
		t.Fatalf("%d %v", code, out)
	}
	code, out = e.mergePlan(map[string]any{"branch": "rel", "resolve": map[string]any{"b": 7}}, "X-Author", "ed")
	if code != 400 {
		t.Fatalf("%d %v", code, out)
	}
}

// The planner's transport lets through reads and a batch dry run only.
func TestMergePlannerTransportIsReadOnly(t *testing.T) {
	t.Parallel()
	hit := 0
	api := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit++; w.WriteHeader(204) })
	rt := readOnly{forward{api, http.Header{}}}
	for _, tc := range []struct {
		method, url string
		pass        bool
	}{
		{"GET", "http://x/ns/a", true},
		{"HEAD", "http://x/ns/a/r/b", true},
		{"POST", "http://x/ns/a/batch?dry-run=1", true},
		{"POST", "http://x/ns/a/batch", false},
		{"POST", "http://x/ns/a/batch?dry-run=0", false},
		{"POST", "http://x/ns/a/r/b/blobs?dry-run=1", false},
		{"PATCH", "http://x/ns/a", false},
		{"PUT", "http://x/ns/a/r/b/blobs/x", false},
		{"DELETE", "http://x/ns/a/r/b", false},
		{"POST", "http://x/ns/a/purge", false},
	} {
		before := hit
		req, _ := http.NewRequest(tc.method, tc.url, strings.NewReader("{}"))
		res, err := rt.RoundTrip(req)
		if err != nil {
			t.Fatal(err)
		}
		if passed := hit > before; passed != tc.pass {
			t.Errorf("%s %s: passed %v, want %v (status %d)", tc.method, tc.url, passed, tc.pass, res.StatusCode)
		}
	}
}

// The planner reads with the caller's own headers: whoever may not read the
// branch or the base gets the API's refusal.
func TestMergePlanAuth(t *testing.T) {
	t.Parallel()
	e := newSIEnv(t, true, Options{})
	ctx := context.Background()
	admin := clienttest.NewKey("admin")
	op := e.s.Client(t, client.WithBearer(e.s.OperatorGrant(t, "priv")))
	if _, err := op.CreateNamespace(ctx, "priv", map[string]any{"read": "grant", "keys": []any{admin.Entry("*")}}); err != nil {
		t.Fatal(err)
	}
	all := admin.Grant(t, e.s.Now(), "user:root", []string{"priv", "draft"}, []string{"read", "create", "append", "branch"})
	c := e.s.Client(t, client.WithBearer(all))
	a, err := c.CreateDoc(ctx, "priv", "a", map[string]any{"n": 0})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.CreateBranch(ctx, "priv", client.BranchRequest{Name: "draft"}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Append(ctx, "draft", "a", a.ID, set("/n", 1)); err != nil {
		t.Fatal(err)
	}
	req := map[string]any{"branch": "draft"}
	if code, out := e.mergePlan(req); code != 401 && code != 403 && code != 404 {
		t.Errorf("anonymous: %d %v", code, out)
	}
	// reads the branch, not the base
	half := admin.Grant(t, e.s.Now(), "user:x", []string{"draft"}, []string{"read"})
	if code, out := e.mergePlan(req, "Authorization", "Bearer "+half); code != 401 && code != 403 && code != 404 {
		t.Errorf("branch only: %d %v", code, out)
	}
	code, out := e.mergePlan(req, "Authorization", "Bearer "+all)
	if code != 200 || out["clean"] != true || out["batch"] == nil || out["dryRunError"] != nil {
		t.Fatalf("with grant: %d %v", code, out)
	}
}

// A sealed namespace is refused before anything is planned: the page holds
// no keys the planner could use.
func TestMergePlanSealedRefused(t *testing.T) {
	t.Parallel()
	ks, err := keystore.New(keystore.Generate())
	if err != nil {
		t.Fatal(err)
	}
	s := clienttest.New(t, clienttest.Options{KeyStore: ks})
	api := server.New(s.Engine)
	e := &siEnv{t: t, s: s, api: api, pg: HandlerWith(api, Options{})}
	ctx := context.Background()
	c := s.Client(t, client.WithAuthor("ed"))
	if _, err := c.CreateNamespace(ctx, "matches", map[string]any{"read": "public", "encryption": map[string]any{"level": "sealed"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.CreateBranch(ctx, "matches", client.BranchRequest{Name: "rel"}); err != nil {
		t.Fatal(err)
	}
	code, out := e.mergePlan(map[string]any{"branch": "rel"}, "X-Author", "ed")
	if code != 422 || out["code"] != "merge_unsupported" || !strings.Contains(out["message"].(string), "sealed") {
		t.Fatalf("%d %v", code, out)
	}
}
