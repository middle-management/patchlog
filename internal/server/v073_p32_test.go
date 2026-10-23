package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	plclient "github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/core"
)

// P32 REMOTE-LEVELS: a remote branch follows its base's level and read
// (§G.5.2), answers 502 upstream where its server lacks the level (§1),
// and judges its own config writes by the base's current document.

// sync follows B's remote bases once.
func syncRemotes(t *testing.T, b *tenv) error {
	t.Helper()
	return b.e.SyncRemotes(context.Background())
}

// keyed is a client of e that opens sealed answers (dev mode: raw keys).
func (e *tenv) keyed() *plclient.Client {
	e.t.Helper()
	c, err := plclient.New(e.srv.URL, plclient.WithKeys(plclient.NewKeys(nil)), plclient.WithAuthor("test"))
	if err != nil {
		e.t.Fatal(err)
	}
	return c
}

// configOf is a namespace's current document, opened if it is sealed.
func (e *tenv) configOf(ns string) map[string]any {
	e.t.Helper()
	d, err := e.keyed().NSDoc(context.Background(), ns, e.nsHead(ns))
	if err != nil {
		e.t.Fatalf("%s: %v", ns, err)
	}
	return d.Value
}

// lastEntry is a namespace's newest log entry, opened if it is sealed.
func (e *tenv) lastEntry(ns string) plclient.NSEntry {
	e.t.Helper()
	lg, err := e.keyed().NSLog(context.Background(), ns, e.nsHead(ns), "")
	if err != nil || len(lg) == 0 {
		e.t.Fatalf("%s: %v", ns, err)
	}
	return lg[len(lg)-1]
}

func levelOf(doc map[string]any) string {
	enc, _ := doc["encryption"].(map[string]any)
	l, _ := enc["level"].(string)
	return l
}

// ENC-45: a raise of the base's level seen in its log is followed, the
// branch's local dependents first, leaves first, by config writes of the
// deployment (RemoteAuthor), which seal what the branch reads through
// (§G.5.2, Addendum E Levels, CONFORMANCE Levels 31, 33).
func TestV073RemoteFollowsRaise(t *testing.T) {
	t.Parallel()
	a, b, _ := pair(t, []envOpt{withKeyStore(newKeyStore(t)), withEncTuning}, []envOpt{withKeyStore(newKeyStore(t)), withEncTuning})
	a.mkNS("m", map[string]any{"read": "grant"})
	x := a.create("m", "x", map[string]any{"v": 1.0})
	expect(t, b.mkRemote("r1", remoteGenesis("m", a.nsHead("m"), map[string]any{"read": "grant", "schemaReads": map[string]any{"for": []any{"*"}}})), 201)
	expect(t, b.branch("r1", map[string]any{"name": "r1-x"}, "alice"), 201)
	expect(t, b.branch("r1-x", map[string]any{"name": "r1-y"}, "alice"), 201)
	if g := b.get("/r/r1/x/rev/" + x); g.Code != 200 || isJOSE(g) {
		t.Fatalf("before the raise: %d %s", g.Code, g.Body)
	}
	// A rotation of nothing: a config change that raises nothing is no notice.
	expect(t, a.patchNS("m", ops(op("add", "/x-note", "n")), ""), 201)
	if err := syncRemotes(t, b); err != nil {
		t.Fatal(err)
	}
	if n, _ := b.e.RemoteNotices(context.Background(), "r1"); len(n) != 0 {
		t.Fatalf("notices for a change that raises nothing: %+v", n)
	}

	expect(t, a.patchNS("m", ops(op("add", "/encryption", map[string]any{"level": "sealed"})), ""), 201)
	if err := syncRemotes(t, b); err != nil {
		t.Fatal(err)
	}
	for _, ns := range []string{"r1-y", "r1-x", "r1"} {
		doc := b.configOf(ns)
		if levelOf(doc) != "sealed" {
			t.Fatalf("%s after its base's raise: %v", ns, doc)
		}
		if last := b.lastEntry(ns); last.Kind != "config" || last.Author != core.RemoteAuthor || last.Grant != nil || last.GrantNull {
			t.Fatalf("%s: raise entry %+v", ns, last)
		}
	}
	// schemaReads, which sealed refuses, went with the raise (Levels).
	if _, ok := b.configOf("r1")["schemaReads"]; ok {
		t.Fatal("schemaReads kept at sealed")
	}
	// Read-through content is sealed now, under the branch's own keys.
	for _, ns := range []string{"r1", "r1-x", "r1-y"} {
		if g := b.get("/r/" + ns + "/x/rev/" + x); g.Code != 200 || !isJOSE(g) {
			t.Fatalf("%s after the raise: %d %s", ns, g.Code, g.Body)
		}
	}
	notices, err := b.e.RemoteNotices(context.Background(), "r1")
	if err != nil || len(notices) != 1 || notices[0].Kind != "config" || !notices[0].Applied {
		t.Fatalf("notices %+v %v", notices, err)
	}
	if ls, _ := b.e.RemoteLevels(context.Background(), ""); len(ls) != 0 {
		t.Fatalf("levels %+v", ls)
	}
	// Following again changes nothing.
	head := b.nsHead("r1")
	if err := syncRemotes(t, b); err != nil || b.nsHead("r1") != head {
		t.Fatalf("second sync: %v", err)
	}
}

// proxyA serves A through a proxy: intercept answers a request itself when
// it returns true; rewrite, if set, rewrites the body of answers whose
// path is rewritePath.
func proxyA(t *testing.T, a *tenv, intercept func(w http.ResponseWriter, r *http.Request) bool, rewritePath string, rewrite func([]byte) []byte) string {
	t.Helper()
	p := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if intercept != nil && intercept(w, r) {
			return
		}
		hr, _ := http.NewRequest(r.Method, a.srv.URL+r.URL.RequestURI(), r.Body)
		hr.Header = r.Header.Clone()
		res, err := client.Do(hr)
		if err != nil {
			w.WriteHeader(502)
			return
		}
		defer res.Body.Close()
		body, _ := io.ReadAll(res.Body)
		if rewrite != nil && r.URL.Path == rewritePath {
			body = rewrite(body)
		}
		for k, v := range res.Header {
			if k != "Content-Length" {
				w.Header()[k] = v
			}
		}
		w.WriteHeader(res.StatusCode)
		w.Write(body)
	}))
	t.Cleanup(p.Close)
	return p.URL
}

// ENC-45: a read the base made non-public restricts a public remote
// branch's, its public dependents first, leaves first (§G.5.2 SHOULD).
func TestV073RemoteRestrictsRead(t *testing.T) {
	t.Parallel()
	a, b, _ := pair(t, nil, nil)
	a.mkNS("m", map[string]any{"read": "public"})
	a.create("m", "x", map[string]any{"v": 1.0})
	expect(t, b.mkRemote("r", remoteGenesis("m", a.nsHead("m"), nil)), 201)
	expect(t, b.branch("r", map[string]any{"name": "rx"}, "alice"), 201)
	expect(t, a.patchNS("m", ops(op("replace", "/read", "grant")), ""), 201)
	if err := syncRemotes(t, b); err != nil {
		t.Fatal(err)
	}
	for _, ns := range []string{"rx", "r"} {
		if doc := b.configOf(ns); doc["read"] != "grant" {
			t.Fatalf("%s after its base's read was restricted: %v", ns, doc)
		}
		if last := b.lastEntry(ns); last.Author != core.RemoteAuthor {
			t.Fatalf("%s: %+v", ns, last)
		}
	}
	ns, _ := b.e.RemoteNotices(context.Background(), "r")
	if len(ns) != 1 || ns[0].Kind != "config" || !ns[0].Applied {
		t.Fatalf("notices %+v", ns)
	}
}

// ENC-45: a raise to e2e seen after at is one Levels refuse the branch
// (Addendum E Levels, Branches of a raised base): it is recorded, and the
// branch marked for a rebase, while it keeps serving what it read
// through, which its base serves as at the level before the raise. A's
// document is rewritten in transit here, since this server raises no
// existing namespace to e2e yet; B reads it only from A (§G.5.2).
func TestV073RemoteE2ERaiseNeedsRebase(t *testing.T) {
	t.Parallel()
	a, b, rt := pair(t, nil, []envOpt{withKeyStore(newKeyStore(t)), withEncTuning})
	a.mkNS("m", map[string]any{"read": "grant"})
	x := a.create("m", "x", map[string]any{"v": 1.0})
	expect(t, b.mkRemote("r", remoteGenesis("m", a.nsHead("m"), map[string]any{"read": "grant"})), 201)
	expect(t, a.patchNS("m", ops(op("add", "/x-note", "raised")), ""), 201)
	raised := a.nsHead("m")
	rt.set(proxyA(t, a, nil, "/ns/m/rev/"+raised, func(body []byte) []byte {
		var doc map[string]any
		if err := json.Unmarshal(body, &doc); err != nil {
			t.Errorf("A's document: %v", err)
			return body
		}
		doc["encryption"] = map[string]any{"level": "e2e"}
		out, _ := json.Marshal(doc)
		return out
	}), "")
	if err := syncRemotes(t, b); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	ls, err := b.e.RemoteLevels(ctx, "r")
	if err != nil || len(ls) != 1 || ls[0].Level != "e2e" || !ls[0].Rebase || ls[0].Lacks || ls[0].ID != raised {
		t.Fatalf("levels %+v %v", ls, err)
	}
	ns, _ := b.e.RemoteNotices(ctx, "r")
	if len(ns) != 1 || ns[0].Kind != "config" || ns[0].Applied || ns[0].ID != raised {
		t.Fatalf("notices %+v", ns)
	}
	if levelOf(b.configOf("r")) != "" {
		t.Fatal("raised to e2e")
	}
	expect(t, b.get("/r/r/x/rev/"+x), 200)
}
