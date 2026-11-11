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

// v82Failed are the core's failures and what a save answers for each.
var v82Failed = []struct{ status, want int }{{408, 502}, {429, 503}, {500, 502}, {503, 503}}

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
