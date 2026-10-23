package dav_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/dav"
)

// preV056 is a transport that answers GET /ns/{ns}/principal as a core
// before v0.56 did (§7.4): without the members named (key, operator).
func preV056(members ...string) func(http.RoundTripper) http.RoundTripper {
	return func(next http.RoundTripper) http.RoundTripper {
		return rtFunc(func(r *http.Request) (*http.Response, error) {
			res, err := next.RoundTrip(r)
			if err != nil || res.StatusCode != http.StatusOK || !strings.HasSuffix(r.URL.Path, "/principal") {
				return res, err
			}
			b, err := io.ReadAll(res.Body)
			res.Body.Close()
			if err != nil {
				return nil, err
			}
			var m map[string]any
			if err := json.Unmarshal(b, &m); err != nil {
				return nil, err
			}
			for _, k := range members {
				delete(m, k)
			}
			b, _ = json.Marshal(m)
			res.Body = io.NopCloser(bytes.NewReader(b))
			res.ContentLength = int64(len(b))
			res.Header.Set("Content-Length", strconv.Itoa(len(b)))
			return res, nil
		})
	}
}

// preKey sets a gateway's core to answer /principal without key, as
// before v0.56: a user is then the verifying namespace, kid and sub.
func preKey(o *dav.Options) { o.Client = o.Client.With(client.WithTransport(preV056("key"))) }

// GW-26 (§H.7 "Users", §7.4 key): a user is the root sub with the key
// that verified the root block, by its thumbprint, the same in every
// namespace and under any kid: alice's two tokens of one key, listed
// in docs under two kids, are one user, whose save without If-Match is
// rebased on what the other token read; a token of another key under
// the same kid elsewhere is someone else, who doesn't read her swap
// file; and after docs rotates the key under the same kid, her token of
// the new key is a new user too.
func TestGatewayUserIsKeyV073(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{Auth: true, RealClock: true})
	k := clienttest.NewKey("k")
	kb := clienttest.Key{Kid: "kb", Pub: k.Pub, Priv: k.Priv} // k's key under another kid
	other := clienttest.NewKey("k")                           // another key under k's kid
	for ns, keys := range map[string][]any{"docs": {k.Entry("*"), kb.Entry("*")}, "notes": {other.Entry("*")}} {
		must(s.Client(t, client.WithBearer(s.OperatorGrant(t, ns))).CreateNamespace(ctx, ns, map[string]any{"read": "grant", "keys": keys}))
	}
	writer := []string{"read", "create", "append", "restore", "delete", "config"}
	e := &env{t: t, ctx: ctx, s: s, c: s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:admin", []string{"docs"}, writer)))}
	e.dav = newTestServer(t, must(dav.New(dav.Options{Client: s.Client(t), Namespaces: []string{"docs", "notes"}, Gateway: true, Logf: t.Logf})))

	viaK := k.Grant(t, s.Now(), "user:alice", []string{"docs"}, writer)
	viaKB := kb.Grant(t, s.Now(), "user:alice", []string{"docs"}, writer)
	e.create("docs", "x", map[string]any{"v": 1, "w": 1})
	buf := e.expect(e.doAs(viaK, "GET", "/docs/x.json", ""), 200, "alice's GET under kid k").body
	h, _ := e.load("docs", "x")
	must(e.c.Append(ctx, "docs", "x", h.ID, []any{replace("/w", 2)}))
	e.expect(e.doAs(viaKB, "PUT", "/docs/x.json", strings.Replace(buf, `"v": 1`, `"v": 2`, 1)), 201, "her save under kid kb, no If-Match")
	_, doc := e.load("docs", "x")
	sameJSON(t, doc, map[string]any{"v": 2, "w": 2})

	// Same kid, same sub, same rights, another key: another user.
	both := []string{"docs", "notes"}
	e.expect(e.doAs(k.Grant(t, s.Now(), "user:alice", both, writer), "PUT", "/docs/.x.json.swp", "alice's swap"), 201, "alice's swap file")
	e.expect(e.doAs(other.Grant(t, s.Now(), "user:alice", both, writer), "GET", "/docs/.x.json.swp", ""), 404, "the swap file to notes' key named k, for user:alice")

	// docs rotates alice's key, keeping the kid: her token of the new key
	// is a new user, with neither her swap file nor her records.
	rotated := clienttest.NewKey("k")
	nh := must(e.c.NSHead(ctx, "docs"))
	must(e.c.PatchConfig(ctx, "docs", nh.Config, []any{replace("/keys", []any{rotated.Entry("*"), kb.Entry("*")})}))
	e.expect(e.doAs(rotated.Grant(t, s.Now(), "user:alice", both, writer), "GET", "/docs/.x.json.swp", ""), 404, "the swap file to alice's token of the rotated key")
}

// GW-27 (§H.7 "Users", §7.4 operator): an operator grant is never a user
// of a gateway: 403, as /principal's operator says, and kept refused for
// a while without asking the core again.
func TestGatewayOperatorGrantRefusedV073(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	var principals atomic.Int64
	s := clienttest.New(t, clienttest.Options{Auth: true, RealClock: true, Wrap: func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(r.URL.Path, "/principal") {
				principals.Add(1)
			}
			next.ServeHTTP(w, r)
		})
	}})
	must(s.Client(t, client.WithBearer(s.OperatorGrant(t, "docs"))).CreateNamespace(ctx, "docs", map[string]any{"read": "grant", "keys": []any{clienttest.NewKey("k").Entry("*")}}))
	e := &env{t: t, ctx: ctx, s: s, dav: newTestServer(t, must(dav.New(dav.Options{Client: s.Client(t), Namespaces: []string{"docs"}, Gateway: true, Logf: t.Logf})))}
	op := clienttest.Mint(t, s.OperatorKey, map[string]any{"kid": "operator", "sub": "op:root", "ns": []any{"docs"},
		"can": []any{"read"}, "exp": s.Now().Add(time.Hour).Format(time.RFC3339)})
	r := e.expect(e.doAs(op, "PROPFIND", "/docs/", "", "Depth", "1"), 403, "an operator grant")
	if !strings.Contains(r.body, "operator") || r.header.Get("WWW-Authenticate") != "" {
		t.Fatalf("403 %v %q", r.header, r.body)
	}
	asked := principals.Load()
	e.expect(e.doAs(op, "GET", "/docs/x.json", ""), 403, "the operator grant again")
	if n := principals.Load() - asked; n != 0 {
		t.Fatalf("the core was asked /principal %d more times for the refused operator grant", n)
	}
}

// GW-28 (§H.7 "Users", §H.4 "Others' writes"): a user's own entries are
// also those the core recorded under the user's grant (its sub, and a
// kid that names its key) or, with authentication disabled, its
// X-Author, written through another program: a save from before such an
// edit, touching the same member, is no conflict with it.
func TestOwnEntriesByIdentityV073(t *testing.T) {
	t.Parallel()
	t.Run("grant", func(t *testing.T) {
		t.Parallel()
		e, k := authEnv(t, true)
		writer := []string{"read", "create", "append", "restore", "delete"}
		alice := k.Grant(t, e.s.Now(), "user:alice", []string{"docs"}, writer)
		e.create("docs", "x", map[string]any{"v": 1, "w": 1})
		buf := e.expect(e.doAs(alice, "GET", "/docs/x.json", ""), 200, "alice's GET").body
		// Alice's script, with another token of hers, straight to the core.
		script := e.s.Client(t, client.WithBearer(k.Grant(t, e.s.Now().Add(time.Second), "user:alice", []string{"docs"}, writer)))
		h, _ := e.load("docs", "x")
		must(script.Append(e.ctx, "docs", "x", h.ID, []any{replace("/v", 5)}))
		e.expect(e.doAs(alice, "PUT", "/docs/x.json", strings.Replace(buf, `"v": 1`, `"v": 2`, 1)), 201, "alice's save from before her script's edit of v")
		_, doc := e.load("docs", "x")
		sameJSON(t, doc, map[string]any{"v": 2, "w": 1})
		// Bob's edit of the same member is someone else's.
		bob := e.s.Client(t, client.WithBearer(k.Grant(t, e.s.Now(), "user:bob", []string{"docs"}, writer)))
		buf = e.expect(e.doAs(alice, "GET", "/docs/x.json", ""), 200, "alice reads again").body
		h, _ = e.load("docs", "x")
		must(bob.Append(e.ctx, "docs", "x", h.ID, []any{replace("/v", 7)}))
		e.expect(e.doAs(alice, "PUT", "/docs/x.json", strings.Replace(buf, `"v": 2`, `"v": 3`, 1)), 409, "alice's save over bob's edit of v")
		// A delete by alice's script is hers too: her save from before it
		// makes the file anew, where one over bob's delete is refused.
		e.create("docs", "y", map[string]any{"v": 1})
		e.create("docs", "z", map[string]any{"v": 1})
		e.expect(e.doAs(alice, "GET", "/docs/y.json", ""), 200, "alice's GET of y")
		e.expect(e.doAs(alice, "GET", "/docs/z.json", ""), 200, "alice's GET of z")
		h, _ = e.load("docs", "y")
		must(script.Delete(e.ctx, "docs", "y", h.ID))
		h, _ = e.load("docs", "z")
		must(bob.Delete(e.ctx, "docs", "z", h.ID))
		e.expect(e.doAs(alice, "PUT", "/docs/y.json", `{"v": 2}`), 201, "alice's save over her script's delete of y")
		e.expect(e.doAs(alice, "PUT", "/docs/z.json", `{"v": 2}`), 409, "alice's save over bob's delete of z")
	})
	t.Run("author", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t, []string{"docs"}, nil, nil)
		e.create("docs", "x", map[string]any{"v": 1, "w": 1})
		buf := e.expect(e.do("GET", "/docs/x.json", ""), 200, "GET").body
		// Another program writing as the server's X-Author, dav.
		mine := e.s.Client(t, client.WithAuthor("dav"))
		h, _ := e.load("docs", "x")
		must(mine.Append(e.ctx, "docs", "x", h.ID, []any{replace("/v", 5)}))
		e.expect(e.do("PUT", "/docs/x.json", strings.Replace(buf, `"v": 1`, `"v": 2`, 1)), 201, "the save from before the same author's edit of v")
		_, doc := e.load("docs", "x")
		sameJSON(t, doc, map[string]any{"v": 2, "w": 1})
		buf = e.expect(e.do("GET", "/docs/x.json", ""), 200, "GET again").body
		h, _ = e.load("docs", "x")
		must(e.c.Append(e.ctx, "docs", "x", h.ID, []any{replace("/v", 7)}))
		e.expect(e.do("PUT", "/docs/x.json", strings.Replace(buf, `"v": 2`, `"v": 3`, 1)), 409, "the save over another author's edit of v")
	})
}

// GW-29 (§H.7 "Users": with authentication disabled, a user is an
// X-Author): a gateway over a development core takes the Basic user
// name as the X-Author of each user's requests, which keys the user:
// two names are two users, with their own scratch files, and their
// writes are recorded under their names.
func TestGatewayAuthorUsersV073(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{})
	must(s.Client(t, client.WithAuthor("setup")).CreateNamespace(ctx, "docs", map[string]any{"read": "public"}))
	e := &env{t: t, ctx: ctx, s: s, c: s.Client(t, client.WithAuthor("other"))}
	e.dav = newTestServer(t, must(dav.New(dav.Options{Client: s.Client(t), Namespaces: []string{"docs"}, Gateway: true, Logf: t.Logf})))
	as := func(user, method, p, body string) resp {
		t.Helper()
		req := must(http.NewRequest(method, e.dav.URL+p, strings.NewReader(body)))
		req.SetBasicAuth(user, "anything")
		res := must(testHTTP.Do(req))
		defer res.Body.Close()
		b, _ := io.ReadAll(res.Body)
		return resp{status: res.StatusCode, header: res.Header, body: string(b)}
	}
	e.expect(as("ann", "PUT", "/docs/a.json", `{"by": "ann"}`), 201, "ann's PUT")
	if a := e.lastEntry("docs", "a").Author; a != "ann" {
		t.Fatalf("a's author %q", a)
	}
	e.expect(as("ann", "PUT", "/docs/.a.json.swp", "ann's swap"), 201, "ann's swap file")
	e.expect(as("bob", "GET", "/docs/.a.json.swp", ""), 404, "ann's swap file to bob")
	if r := e.expect(as("ann", "GET", "/docs/.a.json.swp", ""), 200, "ann's swap file to ann"); r.body != "ann's swap" {
		t.Fatalf("ann's swap file %q", r.body)
	}
	e.expect(as("bob", "PUT", "/docs/b.json", `{"by": "bob"}`), 201, "bob's PUT")
	if a := e.lastEntry("docs", "b").Author; a != "bob" {
		t.Fatalf("b's author %q", a)
	}
	e.expect(as("", "GET", "/docs/a.json", ""), 401, "no user name")
}
