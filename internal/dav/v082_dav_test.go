package dav_test

import (
	"encoding/json"
	"fmt"
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

// Spec v0.82, the gateway (TOOLS §H.4 "The base", §H.6; BT-8): a failed
// read (408, 429, 5xx) of anything a save decides by, theirs and the
// user's own entries included, fails the save: 503 with Retry-After after
// the core's 429 or 503, else 502. Never 409, and never a save that takes
// someone else's entry for the user's own.

// v82Failed are the core's failures and what a save answers for each;
// status 0 is no answer in time (failRT), which stays 503 with
// Retry-After.
var v82Failed = []struct{ status, want int }{{408, 502}, {429, 503}, {500, 502}, {503, 503}, {0, 503}}

// v82ExpectFailed checks a save's answer to a failed read.
func v82ExpectFailed(t *testing.T, e *env, r resp, want int, what string) {
	t.Helper()
	e.expect(r, want, what)
	if want == 503 && r.header.Get("Retry-After") == "" {
		t.Fatalf("%s: 503 without Retry-After", what)
	}
}

// BT-8, whose entry it is, with grants: alice's grant is verified under
// kid k. While k named another key, a grant of that key for the same sub
// wrote (or deleted) the file: not alice's entry, which only the
// namespace's key history tells (§H.7 "Users"). A save of alice's from
// before, over it, is a conflict (409). While a read of that history
// fails (the namespace head, its log, a config write's document), the
// save fails, 503 or 502, and nothing is written: v0.27.0 took the entry
// for alice's own and saved over it. Once the core answers, the 409.
func TestV082SaveKeyHistoryFailedRead(t *testing.T) {
	t.Parallel()
	reads := map[string]func(r *http.Request) bool{
		"the namespace head": at("GET", "/ns/docs"),
		"the namespace log": func(r *http.Request) bool {
			return r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/ns/docs/rev/") && strings.HasSuffix(r.URL.Path, "/log")
		},
		"a config write's document": func(r *http.Request) bool {
			return r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/ns/docs/rev/") && !strings.HasSuffix(r.URL.Path, "/log")
		},
	}
	for _, kind := range []string{"write", "delete"} {
		for what, match := range reads {
			for _, c := range v82Failed {
				t.Run(fmt.Sprintf("%s/%s/%d", kind, what, c.status), func(t *testing.T) {
					t.Parallel()
					rt := &failRT{status: c.status}
					e, k := authEnv(t, true, func(o *dav.Options) {
						o.Client = o.Client.With(client.WithHTTPClient(&http.Client{Transport: rt}))
					})
					writer := []string{"read", "create", "append", "restore", "delete"}
					alice := k.Grant(t, e.s.Now(), "user:alice", []string{"docs"}, writer)
					e.create("docs", "x", map[string]any{"a": "1", "b": "1"})
					g := e.expect(e.doAs(alice, "GET", "/docs/x.json", ""), 200, "alice's GET")

					// Kid k names another key for a while, whose grant for
					// the same sub writes the file.
					config := must(e.c.NSHead(e.ctx, "docs")).Config
					// setKey gives kid k to key to, in a config write under
					// a grant of the key it names now.
					setKey := func(from, to clienttest.Key) {
						admin := e.s.Client(t, client.WithBearer(from.Grant(t, e.s.Now(), "user:admin", []string{"docs"}, []string{"config"})))
						config = must(admin.PatchConfig(e.ctx, "docs", config, []any{replace("/keys", []any{to.Entry("*")})})).Config
					}
					h, _ := e.load("docs", "x")
					other := clienttest.NewKey("k")
					setKey(k, other)
					them := e.s.Client(t, client.WithBearer(other.Grant(t, e.s.Now(), "user:alice", []string{"docs"}, writer)))
					if kind == "write" {
						must(them.Append(e.ctx, "docs", "x", h.ID, []any{replace("/b", "theirs")}))
					} else {
						must(them.Delete(e.ctx, "docs", "x", h.ID))
					}
					setKey(other, k)
					before, _ := e.load("docs", "x")

					save := func() resp {
						return e.doAs(alice, "PUT", "/docs/x.json", edit(t, g.body, `"b": "1"`, `"b": "mine"`), "If-Match", g.header.Get("ETag"))
					}
					rt.match.Store(match)
					rt.armed.Store(true)
					v82ExpectFailed(t, e, save(), c.want, "alice's save, "+what+" failing")
					if after, _ := e.load("docs", "x"); after.ID != before.ID || after.State != before.State {
						t.Fatalf("the failed save wrote: %+v, was %+v", after, before)
					}
					// Nothing of the failed read is kept: the core answers
					// again, and the entry is someone else's.
					rt.armed.Store(false)
					r := e.expect(save(), 409, "alice's save, the core answering")
					if kind == "delete" && !strings.Contains(r.body, "deleted by someone else") {
						t.Fatalf("the 409: %s", r.body)
					}
					if after, _ := e.load("docs", "x"); after.ID != before.ID {
						t.Fatalf("the refused save wrote: %+v", after)
					}
				})
			}
		}
	}
}

// v82FailingEnv is failingEnv with a clock for the WebDAV server, which
// later advances it past what the server keeps of the core's answers.
func v82FailingEnv(t *testing.T, status int) (*env, *failRT, *atomic.Int64) {
	t.Helper()
	e := newEnv(t, []string{"docs"}, nil, nil)
	rt := &failRT{status: status}
	var later atomic.Int64
	start := time.Now()
	opt := e.opt
	opt.Client = e.s.Client(t, client.WithAuthor("dav"), client.WithHTTPClient(&http.Client{Transport: rt}))
	opt.Now = func() time.Time { return start.Add(time.Duration(later.Load())) }
	g := *e
	g.opt = opt
	g.dav = newTestServer(t, must(dav.New(opt)))
	return &g, rt, &later
}

// BT-8, who the user is, and the log between base and head (local mode,
// authentication disabled): a save over someone else's overlapping write
// reads who the user is in the namespace (GET /ns/{ns}/principal, once
// what it was told has aged) and the resource's log, to tell theirs from
// its own. A failed read of either fails the save, 503 or 502, and
// nothing is written; once the core answers, the conflict is the 409.
func TestV082SaveOverWriteFailedReads(t *testing.T) {
	t.Parallel()
	for _, read := range []string{"the principal", "the log"} {
		for _, c := range v82Failed {
			t.Run(fmt.Sprintf("%s/%d", read, c.status), func(t *testing.T) {
				t.Parallel()
				e, rt, later := v82FailingEnv(t, c.status)
				e.create("docs", "x", map[string]any{"a": "1", "b": "1"})
				g := e.expect(e.do("GET", "/docs/x.json", ""), 200, "GET")
				e.theirs("docs", "x", replace("/b", "theirs"))
				head, _ := e.load("docs", "x")
				switch read {
				case "the principal":
					rt.match.Store(at("GET", "/ns/docs/principal"))
					later.Store(int64(time.Minute))
				case "the log":
					rt.match.Store(at("GET", "/r/docs/x/rev/"+head.ID+"/log"))
				}
				save := func() resp {
					return e.do("PUT", "/docs/x.json", edit(t, g.body, `"b": "1"`, `"b": "mine"`), "If-Match", g.header.Get("ETag"))
				}
				rt.armed.Store(true)
				v82ExpectFailed(t, e, save(), c.want, "PUT, "+read+" failing")
				if after, _ := e.load("docs", "x"); after.ID != head.ID {
					t.Fatalf("the failed save wrote %s", after.ID)
				}
				rt.armed.Store(false)
				e.expect(save(), 409, "PUT, the core answering")
				if after, _ := e.load("docs", "x"); after.ID != head.ID {
					t.Fatalf("the refused save wrote %s", after.ID)
				}
			})
		}
	}
}

// BT-8, §H.6's restore by a write (local mode): a save over someone
// else's delete reads the tombstone's log entry, and who the user is in
// the namespace, to tell whether the delete is its own. A failed read of either fails the
// save with the same split, and the file stays deleted; once the core
// answers, the delete is someone else's (409).
func TestV082SaveOverDeleteFailedReads(t *testing.T) {
	t.Parallel()
	for _, read := range []string{"the principal", "the tombstone's log"} {
		for _, c := range v82Failed {
			t.Run(fmt.Sprintf("%s/%d", read, c.status), func(t *testing.T) {
				t.Parallel()
				e, rt, later := v82FailingEnv(t, c.status)
				e.create("docs", "x", map[string]any{"a": "1", "b": "1"})
				g := e.expect(e.do("GET", "/docs/x.json", ""), 200, "GET")
				h, _ := e.load("docs", "x")
				tomb := must(e.c.Delete(e.ctx, "docs", "x", h.ID))
				if read == "the principal" {
					rt.match.Store(at("GET", "/ns/docs/principal"))
					later.Store(int64(time.Minute))
				} else {
					rt.match.Store(func(r *http.Request) bool {
						return r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/r/docs/x/rev/"+tomb.ID+"/log")
					})
				}
				save := func() resp {
					return e.do("PUT", "/docs/x.json", edit(t, g.body, `"a": "1"`, `"a": "mine"`), "If-Match", g.header.Get("ETag"))
				}
				rt.armed.Store(true)
				v82ExpectFailed(t, e, save(), c.want, "PUT, "+read+" failing")
				e.expectTombstoned("docs", "x", "after the failed read")
				rt.armed.Store(false)
				e.expect(save(), 409, "PUT, the core answering")
				e.expectTombstoned("docs", "x", "after the refused save")
			})
		}
	}
}

// v82Ancestors is a tree service in front of a real one that rewrites
// the answers to …/ancestors as shape says, from the paths the real one
// gave, each as node names from a root down to the node asked of.
type v82Ancestors struct {
	shape atomic.Value // func(paths [][]string) map[string]any: the members to answer with
	asked atomic.Int64
}

func (a *v82Ancestors) front(t *testing.T, backend string) string {
	t.Helper()
	rp := proxyTo(backend)
	rp.ModifyResponse = func(res *http.Response) error {
		if res.StatusCode != http.StatusOK || !strings.HasSuffix(res.Request.URL.Path, "/ancestors") {
			return nil
		}
		raw, err := io.ReadAll(res.Body)
		res.Body.Close()
		if err != nil {
			return err
		}
		var body map[string]any
		if err := json.Unmarshal(raw, &body); err != nil {
			return err
		}
		// The real answer's paths, in the shape before v0.82 (objects with
		// a name, the node's ancestors alone) or v0.82's (names, ending at
		// the node), read as names ending at the node.
		of := res.Request.URL.Query().Get("of")
		var paths [][]string
		for _, p := range body["paths"].([]any) {
			var names []string
			for _, x := range p.([]any) {
				switch x := x.(type) {
				case string:
					names = append(names, x)
				case map[string]any:
					names = append(names, x["name"].(string))
				}
			}
			if len(names) == 0 || names[len(names)-1] != of {
				names = append(names, of)
			}
			paths = append(paths, names)
		}
		for _, k := range []string{"paths", "tooDeep", "truncated", "node", "nodes"} {
			delete(body, k)
		}
		for k, v := range a.shape.Load().(func([][]string) map[string]any)(paths) {
			body[k] = v
		}
		out, _ := json.Marshal(body)
		res.Body = io.NopCloser(strings.NewReader(string(out)))
		res.ContentLength = int64(len(out))
		res.Header.Set("Content-Length", strconv.Itoa(len(out)))
		a.asked.Add(1)
		return nil
	}
	return newTestServer(t, rp).URL
}

// BT-7g (TOOLS §H.5 Copy, SERVICES §B.5; scenario 130): for a reader who
// lists the tree through the tree service, a folder copied into itself or
// a descendant is judged from ancestors' paths in the shape v0.82 gives
// them (node names from a root down to the node, tooDeep and truncated
// JSON booleans) and in the one before (objects with a name, tooDeep a
// count): 403 where TR is on a path, made where it isn't. An answer that
// reports a cut either way, has no paths, or isn't in a shape the gateway
// reads leaves it unchecked: 403, nothing written, never the 502 a
// v0.27.0 gateway gave a conforming "tooDeep": true, and never a copy.
func TestV082FolderCopyAncestorsShapes(t *testing.T) {
	t.Parallel()
	w := newDerivedWorld(t)
	embargoTR(t, w)
	must(w.ops.CreateDoc(w.ctx, "cat", "inner", map[string]any{"title": "Inner", "parents": parents("cat", "tr")}))
	must(w.ops.CreateDoc(w.ctx, "cat", "both", map[string]any{"title": "Both", "parents": parents("cat", "season", "inner"),
		"$access": map[string]any{"group:match-desk": []any{"desk"}}}))
	w.caughtUp(t)
	var stub v82Ancestors
	names := func(paths [][]string) []any {
		out := []any{}
		for _, p := range paths {
			arr := []any{}
			for _, n := range p {
				arr = append(arr, n)
			}
			out = append(out, arr)
		}
		return out
	}
	// The shape before v0.82: objects, without the node itself.
	objects := func(paths [][]string) []any {
		out := []any{}
		for _, p := range paths {
			arr := []any{}
			for _, n := range p[:len(p)-1] {
				arr = append(arr, map[string]any{"name": n, "href": "/r/cat/" + n, "title": n})
			}
			out = append(out, arr)
		}
		return out
	}
	nodes := func(paths [][]string) map[string]any {
		out := map[string]any{}
		for _, p := range paths {
			for _, n := range p {
				out[n] = map[string]any{"href": "/r/cat/" + n, "title": n}
			}
		}
		return out
	}
	stub.shape.Store(func(paths [][]string) map[string]any { return map[string]any{"paths": names(paths)} })
	g := w.derivedGateway(t, func(o *dav.Options) { o.TreeService = stub.front(t, w.catURL) })
	ed := w.user(t, "user:ed", "editors-in-chief", "match-desk")

	const itself, unchecked = "into itself", "didn't list every path"
	n := 0
	for _, c := range []struct {
		what  string
		shape func(paths [][]string) map[string]any
		// Sub is beside TR, Both below it through a second parent: what a
		// COPY of TR into each answers, "" for made (201).
		sub, both string
	}{
		{"v0.82", func(p [][]string) map[string]any { return map[string]any{"paths": names(p), "nodes": nodes(p)} }, "", itself},
		{"v0.82, cuts false", func(p [][]string) map[string]any {
			return map[string]any{"paths": names(p), "tooDeep": false, "truncated": false}
		}, "", itself},
		{"before v0.82", func(p [][]string) map[string]any {
			return map[string]any{"paths": objects(p), "node": map[string]any{"name": "x"}}
		}, "", itself},
		{"before v0.82, tooDeep 0", func(p [][]string) map[string]any { return map[string]any{"paths": objects(p), "tooDeep": 0} }, "", itself},
		{"tooDeep true", func(p [][]string) map[string]any { return map[string]any{"paths": names(p), "tooDeep": true} }, unchecked, unchecked},
		{"truncated true", func(p [][]string) map[string]any { return map[string]any{"paths": names(p), "truncated": true} }, unchecked, unchecked},
		{"tooDeep a count", func(p [][]string) map[string]any { return map[string]any{"paths": objects(p), "tooDeep": 2} }, unchecked, unchecked},
		{"tooDeep a string", func(p [][]string) map[string]any { return map[string]any{"paths": names(p), "tooDeep": "no"} }, unchecked, unchecked},
		{"truncated null", func(p [][]string) map[string]any { return map[string]any{"paths": names(p), "truncated": nil} }, unchecked, unchecked},
		{"no paths", func(p [][]string) map[string]any { return map[string]any{} }, unchecked, unchecked},
		{"paths null", func(p [][]string) map[string]any { return map[string]any{"paths": nil} }, unchecked, unchecked},
		{"paths an object", func(p [][]string) map[string]any { return map[string]any{"paths": map[string]any{}} }, unchecked, unchecked},
		{"paths of numbers", func(p [][]string) map[string]any { return map[string]any{"paths": []any{[]any{1, 2}}} }, unchecked, unchecked},
		{"objects without a name", func(p [][]string) map[string]any {
			return map[string]any{"paths": []any{[]any{map[string]any{"href": "/r/cat/season"}}}}
		}, unchecked, unchecked},
		{"names that don't end at the node", func(p [][]string) map[string]any {
			return map[string]any{"paths": []any{[]any{"root", "season"}}}
		}, unchecked, unchecked},
	} {
		stub.shape.Store(c.shape)
		for _, d := range []struct{ dir, want string }{{"/cat/Season%202026/Sub", c.sub}, {"/cat/Season%202026/Both", c.both}} {
			n++
			title := fmt.Sprintf("TR copy %d", n)
			what := fmt.Sprintf("%s: ed's COPY of TR to %s", c.what, d.dir)
			asked := stub.asked.Load()
			r := g.doAs(ed, "COPY", "/cat/Season%202026/TR", "", "Destination", d.dir+"/"+strings.ReplaceAll(title, " ", "%20"))
			if stub.asked.Load() == asked {
				t.Fatalf("%s: the tree service's ancestors weren't asked", what)
			}
			if d.want == "" {
				g.expect(r, 201, what)
				if folder, _ := w.titled(t, title); folder == "" {
					t.Fatalf("%s: no folder made", what)
				}
				continue
			}
			g.expect(r, 403, what)
			if !strings.Contains(r.body, d.want) {
				t.Fatalf("%s: %s, want %q", what, r.body, d.want)
			}
			if folder, _ := w.titled(t, title); folder != "" {
				t.Fatalf("%s: the refused copy made %s", what, folder)
			}
		}
	}
}

// v82With is e served by another WebDAV server, whose core requests go
// through rt.
func v82With(t *testing.T, e *env, rt http.RoundTripper) *env {
	t.Helper()
	opt := e.opt
	opt.Client = e.s.Client(t, client.WithAuthor("dav"), client.WithHTTPClient(&http.Client{Transport: rt}))
	g := *e
	g.opt = opt
	g.dav = newTestServer(t, must(dav.New(opt)))
	return &g
}

// BT-8 changes saves only (TOOLS §H.4 "The base"): to a request that
// isn't one, the core's 408 to what a namespace's writes need (GET
// /ns/{ns}/principal, the namespace's head and document) is the answer
// it was before v0.82, kept as any refusal of them is, and the request
// is answered as v0.27.0 answered it.
func TestV082OtherRequestsKeepA408(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		read, method, path string
		want               int
	}{
		{"principal", "GET", "/docs/x.json", 200},
		{"principal", "PROPFIND", "/docs/", 207},
		{"principal", "PROPFIND", "/", 207},
		{"principal", "GET", "/cat/Season/derby.json", 200},
		{"principal", "PROPFIND", "/cat/Season/", 207},
		{"principal", "PROPFIND", "/cat/", 207},
		{"principal", "DELETE", "/docs/x.json", 403},
		{"principal", "MKCOL", "/cat/Season/New", 201},
		{"nsdoc", "GET", "/docs/x.json", 200},
		{"nsdoc", "PROPFIND", "/docs/", 503},
		{"nsdoc", "PROPFIND", "/", 207},
		{"nsdoc", "GET", "/cat/Season/derby.json", 503},
		{"nsdoc", "PROPFIND", "/cat/Season/", 503},
		{"nsdoc", "PROPFIND", "/cat/", 503},
		{"nsdoc", "DELETE", "/docs/x.json", 403},
		{"nsdoc", "MKCOL", "/cat/Season/New", 503},
	} {
		t.Run(c.read+" "+c.method+" "+c.path, func(t *testing.T) {
			t.Parallel()
			rt := &failRT{status: 408}
			e := newEnv(t, []string{"docs"}, []string{"cat"}, map[string]map[string]any{"cat": {"catalog": treeCatalog("docs")}})
			e.create("docs", "x", map[string]any{"a": "1"})
			e.create("docs", "derby", map[string]any{"title": "Derby"})
			e.create("cat", "root", map[string]any{"title": "Root", "parents": []any{}})
			e.create("cat", "season", map[string]any{"title": "Season", "parents": parents("cat", "root")})
			e.create("cat", "docs.derby", map[string]any{"title": "derby.json", "parents": parents("cat", "season")})
			e = v82With(t, e, rt)
			rt.match.Store(func(q *http.Request) bool {
				if q.Method != "GET" {
					return false
				}
				if c.read == "principal" {
					return strings.HasSuffix(q.URL.Path, "/principal")
				}
				for _, ns := range []string{"cat", "docs"} {
					if q.URL.Path == "/ns/"+ns || strings.HasPrefix(q.URL.Path, "/ns/"+ns+"/rev/") {
						return true
					}
				}
				return false
			})
			rt.armed.Store(true)
			e.expect(e.do(c.method, c.path, ""), c.want, c.method+" "+c.path+", the core answering 408 to the "+c.read+" reads")
		})
	}
}

// BT-8, the window after another request kept the core's 408 (flat and
// tree): a GET is served while GET /ns/{ns}/principal answers 408, which
// the server keeps a while as what the namespace's writes need. A save
// right after doesn't go by what was kept: it asks again, and while the
// core still answers 408 it fails (502), nothing written. Once the core
// answers, the save is made.
func TestV082SaveAfterAKept408(t *testing.T) {
	t.Parallel()
	for _, path := range []string{"/docs/x.json", "/cat/Season/derby.json", "/cat/Season/new.json"} {
		t.Run(path, func(t *testing.T) {
			t.Parallel()
			rt := &failRT{status: 408}
			e := newEnv(t, []string{"docs", "matches"}, []string{"cat"}, map[string]map[string]any{"cat": {"catalog": treeCatalog("matches")}})
			e.create("docs", "x", map[string]any{"a": "1"})
			e.create("matches", "derby", map[string]any{"a": "1"})
			e.create("cat", "root", map[string]any{"title": "Root", "parents": []any{}})
			e.create("cat", "season", map[string]any{"title": "Season", "parents": parents("cat", "root")})
			e.create("cat", "matches.derby", map[string]any{"title": "derby.json", "parents": parents("cat", "season")})
			e = v82With(t, e, rt)
			var asked atomic.Int64
			// The namespace the save writes: the tree's files.ns, or the
			// flat one.
			ns := "matches"
			if strings.HasPrefix(path, "/docs/") {
				ns = "docs"
			}
			rt.match.Store(func(q *http.Request) bool {
				if q.Method == "GET" && q.URL.Path == "/ns/"+ns+"/principal" {
					asked.Add(1)
					return true
				}
				return false
			})
			rt.armed.Store(true)
			read := strings.Replace(path, "new.json", "derby.json", 1)
			g := e.expect(e.do("GET", read, ""), 200, "GET, the core answering 408 to the principal reads")
			if asked.Load() == 0 {
				t.Fatal("the GET didn't ask who writes the namespace")
			}
			before := len(e.liveNames("matches"))
			head, _ := e.load("docs", "x")
			derby, _ := e.load("matches", "derby")
			body, hdr := `{"a": "2"}`, []string{}
			if path == read {
				hdr = []string{"If-Match", g.header.Get("ETag")}
			}
			was := asked.Load()
			v82ExpectFailed(t, e, e.do("PUT", path, body, hdr...), 502, "PUT after the kept 408")
			if asked.Load() == was {
				t.Fatal("the save went by the kept 408: it didn't ask again")
			}
			x, _ := e.load("docs", "x")
			d, _ := e.load("matches", "derby")
			if x.ID != head.ID || d.ID != derby.ID || len(e.liveNames("matches")) != before {
				t.Fatalf("the failed save wrote: x %s, derby %s, %v", x.ID, d.ID, e.liveNames("matches"))
			}
			rt.armed.Store(false)
			if r := e.do("PUT", path, body, hdr...); r.status != 201 && r.status != 204 {
				t.Fatalf("PUT, the core answering: %d %s", r.status, r.body)
			}
		})
	}
}

// v82NthRT answers the nth GET (from 1) the core gets once armed with
// status, and passes every other request through.
type v82NthRT struct {
	next   http.RoundTripper
	armed  atomic.Bool
	n      int64
	seen   atomic.Int64
	status int
	hit    atomic.Value // string: the path it answered
}

func (f *v82NthRT) RoundTrip(r *http.Request) (*http.Response, error) {
	if f.armed.Load() && r.Method == "GET" && f.seen.Add(1) == f.n {
		f.hit.Store(r.URL.Path)
		return &http.Response{StatusCode: f.status, Header: http.Header{"Retry-After": {"5"}, "Content-Type": {"application/json"}},
			Body: io.NopCloser(strings.NewReader(`{"code":"unavailable","message":"try later"}`)), Request: r}, nil
	}
	if f.next != nil {
		return f.next.RoundTrip(r)
	}
	return http.DefaultTransport.RoundTrip(r)
}

// v82Sweep fails each of a PUT's reads of the core in turn, one per
// world, with the core's 503 and 408, and checks the save's answer: 503
// with Retry-After and 502 (§H.4 "The base"). world builds the gateway
// over rt and warms it, and returns the PUT to make; ok is its status
// with no read failing. It returns how many reads the PUT made.
func v82Sweep(t *testing.T, ok int, world func(t *testing.T, rt *v82NthRT) (e *env, put func() resp)) int64 {
	t.Helper()
	var reads int64
	for _, c := range []struct{ status, want int }{{503, 503}, {408, 502}} {
		for n := int64(1); ; n++ {
			if n > 60 {
				t.Fatalf("the PUT made over %d reads", n)
			}
			rt := &v82NthRT{n: n, status: c.status}
			e, put := world(t, rt)
			rt.armed.Store(true)
			r := put()
			rt.armed.Store(false)
			hit, _ := rt.hit.Load().(string)
			if hit == "" {
				e.expect(r, ok, "the PUT with no read failing")
				reads = n - 1
				break
			}
			if r.status != c.want || c.want == 503 && r.header.Get("Retry-After") == "" {
				t.Errorf("the core's %d on GET %s (read %d of the PUT): %d %s (Retry-After %q), want %d", c.status, hit, n, r.status, strings.TrimSpace(r.body), r.header.Get("Retry-After"), c.want)
			}
		}
	}
	return reads
}

// BT-8, every read of a save: whichever read of the core a PUT makes
// fails, the save answers 503 with Retry-After after the core's 503 and
// 502 after its 408, for a flat file, a file of a tree, and a new one
// there, JSON or raw, whose placement node's head is read to see that
// its name is free (v0.82's first cut left those two reads with the
// answers of other requests, swapped), and for the restore of a file
// the user deleted moments ago. Cold, the server has kept nothing of
// the core's answers, so the PUT's reads include what its namespaces'
// writes need.
func TestV082SaveEveryFailedRead(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		what, path, body string
		prep             func(e *env) []string // the PUT's headers
	}{
		{"a flat file", "/docs/x.json", `{"a": "2"}`, nil},
		{"a new flat file", "/docs/new.json", `{"a": 1}`, nil},
		{"a new raw flat file", "/docs/new.bin", "raw\x00bytes", nil},
		{"a flat file with If-Match", "/docs/x.json", `{"a": "2"}`, func(e *env) []string {
			return []string{"If-Match", e.expect(e.do("GET", "/docs/x.json", ""), 200, "GET").header.Get("ETag")}
		}},
		{"a file of a tree", "/cat/Season/derby.json", `{"title": "Derby 2"}`, nil},
		{"a new file of a tree", "/cat/Season/new.json", `{"a": 1}`, nil},
		{"a new raw file of a tree", "/cat/Season/new.bin", "raw\x00bytes", nil},
		{"a file of a tree with If-Match", "/cat/Season/derby.json", `{"title": "Derby 2"}`, func(e *env) []string {
			return []string{"If-Match", e.expect(e.do("GET", "/cat/Season/derby.json", ""), 200, "GET").header.Get("ETag")}
		}},
		{"the restore of a file of a tree", "/cat/Season/derby.json", `{"title": "Derby 2"}`, func(e *env) []string {
			e.expect(e.do("DELETE", "/cat/Season/derby.json", ""), 204, "DELETE")
			return nil
		}},
	} {
		for _, cold := range []bool{false, true} {
			if cold && c.prep != nil {
				continue
			}
			what := c.what
			if cold {
				what += ", cold"
			}
			t.Run(what, func(t *testing.T) {
				t.Parallel()
				reads := v82Sweep(t, 201, func(t *testing.T, rt *v82NthRT) (*env, func() resp) {
					e := newEnv(t, []string{"docs", "matches"}, []string{"cat"}, map[string]map[string]any{"cat": {"catalog": treeCatalog("matches")}})
					e.create("docs", "x", map[string]any{"a": "1"})
					e.create("matches", "derby", map[string]any{"title": "Derby"})
					e.create("cat", "root", map[string]any{"title": "Root", "parents": []any{}})
					e.create("cat", "season", map[string]any{"title": "Season", "parents": parents("cat", "root")})
					e.create("cat", "matches.derby", map[string]any{"title": "derby.json", "parents": parents("cat", "season")})
					e = v82With(t, e, rt)
					var hdr []string
					if !cold {
						// Warm what the server keeps, so the reads that
						// fail are the PUT's own.
						e.expect(e.do("GET", "/cat/Season/derby.json", ""), 200, "GET")
						e.expect(e.do("GET", "/docs/x.json", ""), 200, "GET")
					}
					if c.prep != nil {
						hdr = c.prep(e)
					}
					return e, func() resp { return e.do("PUT", c.path, c.body, hdr...) }
				})
				if reads == 0 {
					t.Fatal("the PUT read nothing of the core")
				}
			})
		}
	}
}

// BT-8, every read of a save, where grants come from the catalog
// (§B.11): a new file's placement is made first there, under a grant the
// tree service issues, and the node's head is read for it all the same.
func TestV082SaveEveryFailedReadDerived(t *testing.T) {
	t.Parallel()
	reads := v82Sweep(t, 201, func(t *testing.T, rt *v82NthRT) (*env, func() resp) {
		w := newDerivedWorld(t)
		g := w.derivedGateway(t, func(o *dav.Options) {
			o.Client = o.Client.With(client.WithTransport(func(next http.RoundTripper) http.RoundTripper {
				rt.next = next
				return rt
			}))
		})
		bob := w.user(t, "user:bob", "match-desk")
		g.expect(g.doAs(bob, "GET", "/cat/Season%202026/derby.json", ""), 200, "bob's GET")
		return g, func() resp { return g.doAs(bob, "PUT", "/cat/Season%202026/new.json", `{"a": 1}`) }
	})
	if reads == 0 {
		t.Fatal("the PUT read nothing of the core")
	}
}

// BT-8 changes saves only: a MKCOL reads the head of the folder node it
// makes as a new file's save reads its placement node's, and a failed
// read of it is answered as any request's (§H.4 "Answers"): 502 after
// the core's 503, 503 with Retry-After after its 408. No folder is made.
func TestV082MkcolFailedReadUnchanged(t *testing.T) {
	t.Parallel()
	for _, c := range []struct{ status, want int }{{503, 502}, {408, 503}} {
		t.Run(strconv.Itoa(c.status), func(t *testing.T) {
			t.Parallel()
			rt := &failRT{status: c.status}
			e := v82With(t, treeEnv(t), rt)
			e.expect(e.do("PROPFIND", "/cat/Season/", "", "Depth", "1"), 207, "PROPFIND")
			before := len(e.liveNames("cat"))
			var hit atomic.Int64
			rt.match.Store(func(q *http.Request) bool {
				// The head of a node that isn't there yet: the new
				// folder's.
				if q.Method != "GET" || !strings.HasPrefix(q.URL.Path, "/r/cat/") || strings.Count(q.URL.Path, "/") != 3 {
					return false
				}
				switch strings.TrimPrefix(q.URL.Path, "/r/cat/") {
				case "root", "season", "empty", "matches.derby":
					return false
				}
				hit.Add(1)
				return true
			})
			rt.armed.Store(true)
			r := e.expect(e.do("MKCOL", "/cat/Season/New", ""), c.want, "MKCOL, its node's head read failing")
			if hit.Load() == 0 {
				t.Fatal("the MKCOL didn't read its node's head")
			}
			if c.want == 503 && r.header.Get("Retry-After") == "" {
				t.Fatal("503 without Retry-After")
			}
			if got := len(e.liveNames("cat")); got != before {
				t.Fatalf("the failed MKCOL made a node: %d live, were %d", got, before)
			}
			rt.armed.Store(false)
			e.expect(e.do("MKCOL", "/cat/Season/New", ""), 201, "MKCOL, the core answering")
		})
	}
}
