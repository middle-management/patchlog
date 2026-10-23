package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
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

// CIS-32 (ENC-46, GB-38): on a server without a key store, which lacks
// every level, a remote branch whose base is raised to sealed after at
// answers 502 upstream, naming the base's deployment, for every resource
// the base had at at, read through or written on since and not purged
// since; so does a local branch reading through it. Writes other than
// purges get the same 502 at step 2.1, before the retry lookup; a purge
// works, and a resource purged since is 410 (§1, §6.2, §12.1, CONFORMANCE
// CONF-2, Levels 36, 38, 40).
func TestV073RemoteUpstreamLevel(t *testing.T) {
	t.Parallel()
	a, b, _ := pair(t, []envOpt{withKeyStore(newKeyStore(t)), withEncTuning}, []envOpt{withEncTuning})
	a.mkNS("m", map[string]any{"read": "public"})
	x1 := a.create("m", "x", map[string]any{"v": 1.0})
	y1 := a.create("m", "y", map[string]any{"v": 2.0})
	z1 := a.create("m", "z", map[string]any{"v": 3.0})
	gone1 := a.create("m", "gone", map[string]any{"v": 4.0})
	expect(t, b.mkRemote("r", remoteGenesis("m", a.nsHead("m"), nil)), 201)
	// Written on since: x; B's own: mine; a local branch reading through.
	x2 := b.appendRev("r", "x", x1, ops(op("replace", "/v", 10.0)))
	mine := b.create("r", "mine", map[string]any{"own": true})
	expect(t, b.branch("r", map[string]any{"name": "rx"}, "alice"), 201)
	zx := b.appendRev("rx", "z", z1, ops(op("replace", "/v", 30.0)))
	expect(t, b.purge("r", "gone", gone1, "admin"), 204)
	expect(t, b.get("/r/r/y"), 302)

	expect(t, a.patchNS("m", ops(op("add", "/encryption", map[string]any{"level": "sealed"})), ""), 201)
	if err := syncRemotes(t, b); err != nil {
		t.Fatal(err)
	}
	upstream := func(r *resp, what string) {
		t.Helper()
		if r.Code != 502 || r.Str("code") != "upstream" || r.Str("origin") != originA {
			t.Errorf("%s: %d %s, want 502 upstream with origin", what, r.Code, r.Body)
		}
	}
	for _, p := range []string{
		"/r/r/y", "/r/r/y/rev/" + y1, "/r/r/y/rev/" + y1 + "/log",
		"/r/r/x", "/r/r/x/rev/" + x2, "/r/r/x/rev/" + x1,
		"/r/rx/y", "/r/rx/x/rev/" + x2, "/r/rx/z/rev/" + zx, "/r/r/z",
	} {
		upstream(b.get(p), p)
	}
	// The namespace's listings still list them: only the resources answer.
	expect(t, b.get("/ns/r/rev/"+b.nsHead("r")+"/heads"), 200)
	// B's own resources, and purged ones, answer as before.
	expect(t, b.get("/r/r/mine"), 302)
	expect(t, b.get("/r/r/mine/rev/"+mine), 200)
	expect(t, b.get("/r/r/gone"), 410)
	expect(t, b.get("/r/rx/gone"), 410)

	// Writes: the 502 comes at step 2.1, before the retry lookup, which
	// would otherwise answer this resent append 200.
	upstream(b.write("PATCH", "r", "x", x1, ops(op("replace", "/v", 10.0))), "retried append")
	upstream(b.write("PATCH", "r", "y", y1, ops(op("test", "/v", 2.0))), "probing append")
	upstream(b.write("DELETE", "r", "y", y1, nil), "delete")
	upstream(b.write("PATCH", "rx", "z", zx, ops(op("replace", "/v", 31.0))), "append in the local branch")
	r := b.do(req{method: "POST", path: "/ns/r/batch", author: "alice", body: map[string]any{"items": []any{
		map[string]any{"resource": "mine", "ifMatch": mine, "steps": []any{ops(op("add", "/w", 1.0))}},
		map[string]any{"resource": "y", "ifMatch": y1, "steps": []any{ops(op("add", "/w", 1.0))}},
	}}})
	expectCode(t, r, 502, "batch")
	if items, _ := r.Obj()["items"].([]any); len(items) != 1 || items[0].(map[string]any)["code"] != "upstream" || items[0].(map[string]any)["index"] != 1.0 {
		t.Fatalf("batch items %s", r.Body)
	}
	// Step 2.1 answers the 502 and a purged resource's 410 in one pass:
	// the first failing item in request order sets the batch's status.
	for _, c := range []struct {
		first, second string
		status        int
	}{{"gone", "y", 410}, {"y", "gone", 502}} {
		heads := map[string]string{"gone": gone1, "y": y1}
		r := b.do(req{method: "POST", path: "/ns/r/batch", author: "alice", body: map[string]any{"items": []any{
			map[string]any{"resource": c.first, "ifMatch": heads[c.first], "steps": []any{ops(op("add", "/w", 1.0))}},
			map[string]any{"resource": c.second, "ifMatch": heads[c.second], "steps": []any{ops(op("add", "/w", 1.0))}},
		}}})
		expectCode(t, r, c.status, "batch")
		if items, _ := r.Obj()["items"].([]any); len(items) != 2 {
			t.Fatalf("batch %s, %s: %s", c.first, c.second, r.Body)
		}
	}
	// B's own resources take writes.
	b.appendRev("r", "mine", mine, ops(op("add", "/w", 1.0)))
	// A purge works, and the resource is 410 from then on.
	expect(t, b.purge("r", "y", y1, "admin"), 204)
	expect(t, b.get("/r/r/y"), 410)
	expect(t, b.get("/r/rx/y"), 410)

	ctx := context.Background()
	ls, err := b.e.RemoteLevels(ctx, "r")
	if err != nil || len(ls) != 1 || !ls[0].Lacks || ls[0].Level != "sealed" {
		t.Fatalf("levels %+v %v", ls, err)
	}
	ns, _ := b.e.RemoteNotices(ctx, "r")
	if len(ns) != 1 || ns[0].Kind != "config" || ns[0].Applied {
		t.Fatalf("notices %+v", ns)
	}
	// Following again records nothing new.
	if err := syncRemotes(t, b); err != nil {
		t.Fatal(err)
	}
	if ns2, _ := b.e.RemoteNotices(ctx, "r"); len(ns2) != 1 {
		t.Fatalf("notices after a second sync %+v", ns2)
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

// CIS-32, ENC-45: a base whose log B can't open, because A seals it now and
// gives B no keys, is still seen to be sealed (its documents are served
// sealed): on a server without a key store the remote branch answers 502
// upstream, and following reports that the log can't be read.
func TestV073RemoteSealedLogUnreadable(t *testing.T) {
	t.Parallel()
	a, b, rt := pair(t, []envOpt{withKeyStore(newKeyStore(t)), withEncTuning}, nil)
	a.mkNS("m", map[string]any{"read": "public"})
	a.create("m", "x", map[string]any{"v": 1.0})
	expect(t, b.mkRemote("r", remoteGenesis("m", a.nsHead("m"), nil)), 201)
	rt.set(proxyA(t, a, func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/keys") {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(403)
			w.Write([]byte(`{"code":"forbidden"}`))
			return true
		}
		return false
	}, "", nil), "")
	expect(t, a.patchNS("m", ops(op("add", "/encryption", map[string]any{"level": "sealed"})), ""), 201)
	if err := syncRemotes(t, b); err == nil {
		t.Fatal("following a log B can't open succeeded")
	}
	ls, _ := b.e.RemoteLevels(context.Background(), "r")
	if len(ls) != 1 || ls[0].Level != "sealed" || !ls[0].Lacks {
		t.Fatalf("levels %+v", ls)
	}
	r := b.get("/r/r/x")
	expectCode(t, r, 502, "upstream")
	if !bytes.Contains(r.Body, []byte(originA)) {
		t.Fatalf("502 without origin: %s", r.Body)
	}
}

// ENC-47 (MF-40): a config write that makes a remote branch public, raises
// it to e2e or turns off a nonce requirement is judged by its base's
// current namespace document, read for that write: not by what the base
// was at creation. A base that doesn't answer is 502 upstream, one B can't
// read 422, and nothing is applied either way (§G.5.2, CONFORMANCE
// Protection 38–40, Levels 39).
func TestV073RemoteConfigJudgedBySource(t *testing.T) {
	t.Parallel()
	a, b, rt := pair(t, nil, []envOpt{withKeyStore(newKeyStore(t)), withEncTuning})
	a.mkNS("m", map[string]any{"read": "public"})
	a.create("m", "x", map[string]any{"v": 1.0})
	at := a.nsHead("m")
	expect(t, b.mkRemote("r", remoteGenesis("m", at, map[string]any{"read": "grant", "nonce": "required"})), 201)
	expect(t, b.mkRemote("q", remoteGenesis("m", at, map[string]any{"read": "grant"})), 201)

	// A became private after creation: making r public is refused, as for
	// a local branch, though A was public when r was created.
	expect(t, a.patchNS("m", ops(op("replace", "/read", "grant")), ""), 201)
	expectCode(t, b.patchNS("r", ops(op("replace", "/read", "public")), ""), 422, "invalid")
	// A batch's config change takes the same path, its dry run included.
	cfgChange := func(ns string, patches []any) map[string]any {
		return map[string]any{"ifMatch": b.configID(ns), "patches": patches}
	}
	r := b.do(req{method: "POST", path: "/ns/r/batch", author: "admin", body: map[string]any{"items": []any{}, "config": cfgChange("r", ops(op("replace", "/read", "public")))}})
	expectCode(t, r, 422, "invalid")
	r = b.do(req{method: "POST", path: "/ns/r/batch?dry-run=1", author: "admin", body: map[string]any{"items": []any{}, "config": cfgChange("r", ops(op("replace", "/read", "public")))}})
	expect(t, r, 200)
	if rep, _ := r.Obj()["config"].(map[string]any); rep["status"] != 422.0 {
		t.Fatalf("dry run %s", r.Body)
	}

	// A requires nonces now; r was created requiring them while A didn't:
	// turning them off is refused by A's current document.
	expect(t, a.patchNS("m", ops(op("add", "/nonce", "required")), ""), 201)
	expectCode(t, b.patchNS("r", ops(op("remove", "/nonce")), ""), 422, "invalid")
	// p, created while A requires them, requires them too (§G.3); once A no
	// longer does, p may turn them off, whatever A was at p's creation.
	expect(t, b.mkRemote("p", remoteGenesis("m", a.nsHead("m"), map[string]any{"read": "grant", "nonce": "required"})), 201)
	expect(t, a.patchNS("m", ops(op("remove", "/nonce")), ""), 201)
	expect(t, b.patchNS("p", ops(op("remove", "/nonce")), ""), 201)
	expect(t, b.patchNS("r", ops(op("remove", "/nonce")), ""), 201)

	// A raise to e2e over a base that isn't e2e is 422, as a branch field.
	r = b.patchNS("q", ops(op("add", "/encryption", map[string]any{"level": "e2e"})), "")
	expectCode(t, r, 422, "invalid")
	if !strings.Contains(r.Str("message"), "base") {
		t.Fatalf("e2e raise refused for another reason: %s", r.Body)
	}

	// A public again: q may become public.
	expect(t, a.patchNS("m", ops(op("replace", "/read", "public")), ""), 201)
	expect(t, b.patchNS("q", ops(op("replace", "/read", "public")), ""), 201)
	expect(t, b.patchNS("q", ops(op("replace", "/read", "grant")), ""), 201)

	// A unreachable: 502 upstream naming A, not applied.
	cfg := b.configID("q")
	rt.set("http://127.0.0.1:1", "")
	r = b.patchNS("q", ops(op("replace", "/read", "public")), "")
	expectCode(t, r, 502, "upstream")
	if r.Str("origin") != originA || b.configID("q") != cfg {
		t.Fatalf("unreachable base: %s, config %s → %s", r.Body, cfg, b.configID("q"))
	}
	// A config write the base doesn't judge needs no read of it.
	expect(t, b.patchNS("q", ops(op("add", "/x-note", "n")), ""), 201)
	// A answers, but B can't read its document: 422, not applied.
	rt.set(proxyA(t, a, func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path == "/ns/m" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(403)
			w.Write([]byte(`{"code":"forbidden"}`))
			return true
		}
		return false
	}, "", nil), "")
	cfg = b.configID("q")
	expectCode(t, b.patchNS("q", ops(op("replace", "/read", "public")), ""), 422, "invalid")
	if b.configID("q") != cfg {
		t.Fatal("applied")
	}
}
