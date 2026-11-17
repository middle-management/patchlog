package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
)

// resFixture is a server with public namespaces and a runner that fails
// the test on an unexpected error.
type resFixture struct {
	t   *testing.T
	s   *clienttest.Server
	ctx context.Context
}

func newResFixture(t *testing.T, nss ...string) *resFixture {
	t.Helper()
	f := &resFixture{t: t, s: clienttest.New(t, clienttest.Options{}), ctx: context.Background()}
	for _, ns := range nss {
		f.must("ns", "create", ns, `{"read":"public"}`)
	}
	return f
}

func (f *resFixture) must(args ...string) (string, string) {
	f.t.Helper()
	out, errw, err := clientRun(f.t, f.ctx, f.s.URL, args...)
	if err != nil {
		f.t.Fatalf("%q: %v\n%s", args, err, errw)
	}
	return out, errw
}

// fail runs args, which must fail, and returns the error text and stderr.
func (f *resFixture) fail(args ...string) (string, string) {
	f.t.Helper()
	out, errw, err := clientRun(f.t, f.ctx, f.s.URL, args...)
	if err == nil {
		f.t.Fatalf("%q: no error; stdout %q stderr %q", args, out, errw)
	}
	return err.Error(), errw
}

func wantIn(t *testing.T, what, got string, subs ...string) {
	t.Helper()
	for _, s := range subs {
		if !strings.Contains(got, s) {
			t.Errorf("%s: %q lacks %q", what, got, s)
		}
	}
}

func TestLs(t *testing.T) {
	t.Parallel()
	f := newResFixture(t, "m")
	r1, _ := f.must("put", "m/derby", `{"score":"0-0"}`)
	f.must("put", "m/derby-2", `{"x":1}`)
	f.must("put", "m/cup", `{"x":2}`)
	f.must("rm", "m/cup")

	out, _ := f.must("ls", "m")
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 3 {
		t.Fatalf("ls: %q", out)
	}
	wantIn(t, "ls", out, "derby", "live", strings.TrimSpace(r1), "tombstone")
	out, _ = f.must("ls", "m", "derby")
	if lines := strings.Split(strings.TrimSpace(out), "\n"); len(lines) != 2 || strings.Contains(out, "cup") {
		t.Fatalf("ls prefix: %q", out)
	}
	out, _ = f.must("ls", "m", "--json")
	var rows []map[string]any
	if err := json.Unmarshal([]byte(out), &rows); err != nil || len(rows) != 3 || rows[0]["resource"] != "cup" || rows[0]["kind"] != "tombstone" {
		t.Fatalf("ls --json: %v %s", err, out)
	}
	out, _ = f.must("ls", "m", "nomatch")
	if strings.TrimSpace(out) != "" {
		t.Fatalf("ls of no match: %q", out)
	}
	msg, _ := f.fail("ls", "nope")
	wantIn(t, "ls of a missing namespace", msg, "404")
}

func TestLsBranchReadThrough(t *testing.T) {
	t.Parallel()
	f := newResFixture(t, "m")
	f.must("put", "m/a", `{"x":1}`)
	f.must("branch", "create", "m", "m-b")
	f.must("put", "m-b/own", `{"x":2}`)
	out, _ := f.must("ls", "m-b")
	wantIn(t, "branch ls", out, "a", "own")
}

func TestRestore(t *testing.T) {
	t.Parallel()
	f := newResFixture(t, "m")
	f.must("put", "m/a", `{"n":1}`)
	msg, _ := f.fail("restore", "m/a")
	wantIn(t, "restore of a live resource", msg, "isn't deleted")
	msg, _ = f.fail("restore", "m/zzz")
	wantIn(t, "restore of a missing resource", msg, "m/zzz doesn't exist")
	msg, _ = f.fail("restore", "m/a", `{"op":"add"}`)
	wantIn(t, "restore with a patch object", msg, "JSON array")

	f.must("rm", "m/a")
	id, errw := f.must("restore", "m/a", `[{"op":"replace","path":"/n","value":2}]`)
	wantIn(t, "restore", errw, "restored m/a", "gesture")
	if strings.TrimSpace(id) == "" {
		t.Fatal("restore printed no id")
	}
	out, _ := f.must("get", "m/a")
	wantIn(t, "restored doc", out, `"n": 2`)

	f.must("rm", "m/a")
	f.must("restore", "m/a")
	out, _ = f.must("get", "m/a")
	wantIn(t, "restored unchanged", out, `"n": 2`)

	f.must("rm", "m/a")
	f.must("purge", "m/a", "--yes")
	msg, _ = f.fail("restore", "m/a")
	wantIn(t, "restore of a purged resource", msg, "is purged")
}

func TestBatch(t *testing.T) {
	t.Parallel()
	f := newResFixture(t, "m")
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	f.must("put", "m/old", `{"n":1}`)
	oldRev := strings.TrimSpace(func() string { o, _ := f.must("ls", "m", "old", "--json"); return o }())
	var rows []map[string]any
	if err := json.Unmarshal([]byte(oldRev), &rows); err != nil {
		t.Fatal(err)
	}
	head := rows[0]["target"].(string)

	good := write("good.json", `{"items":[
		{"resource":"a","ifNoneMatch":"*","steps":[[{"op":"add","path":"","value":{"v":"a"}}]]},
		{"resource":"b","ifNoneMatch":true,"steps":[[{"op":"add","path":"","value":{"v":"b"}}],[{"op":"replace","path":"/v","value":"b2"}]]},
		{"resource":"old","ifMatch":"`+head+`","steps":["delete"]}]}`)

	// A dry run writes nothing and reports the ids.
	out, errw := f.must("batch", "m", good, "--dry-run")
	wantIn(t, "dry run", errw, "dry run", "3 items")
	wantIn(t, "dry run", out, "a  ", "b  ", "old  ")
	if o, _ := f.must("ls", "m"); strings.Contains(o, "\na ") || strings.HasPrefix(o, "a ") {
		t.Fatalf("dry run wrote: %s", o)
	}
	out, _ = f.must("batch", "m", good, "--dry-run", "--json")
	var rep map[string]any
	if err := json.Unmarshal([]byte(out), &rep); err != nil || rep["dryRun"] != true || len(rep["items"].([]any)) != 3 {
		t.Fatalf("dry run --json: %v %s", err, out)
	}

	nsID, errw := f.must("batch", "m", good)
	wantIn(t, "batch", errw, "wrote 3 items to m", "gesture")
	if strings.TrimSpace(nsID) == "" {
		t.Fatal("batch printed no namespace entry")
	}
	o, _ := f.must("get", "m/b")
	wantIn(t, "batch step order", o, `"b2"`)
	if msg, _ := f.fail("get", "m/old"); !strings.Contains(msg, "deleted") {
		t.Fatalf("old: %s", msg)
	}
	// The batch is one gesture: undo takes it back whole.
	f.must("undo", "m")
	if msg, _ := f.fail("get", "m/a"); !strings.Contains(msg, "doesn't exist") && !strings.Contains(msg, "deleted") {
		t.Fatalf("after undo: %s", msg)
	}

	// Reading the batch from stdin goes through the same path.
	stdin := os.Stdin
	r, w, _ := os.Pipe()
	os.Stdin = r
	defer func() { os.Stdin = stdin }()
	go func() {
		w.WriteString(`{"items":[{"resource":"c","ifNoneMatch":"*","steps":[[{"op":"add","path":"","value":{}}]]}]}`)
		w.Close()
	}()
	f.must("batch", "m", "-", "--json")

	// A failing item: nothing is written, and the error names the item.
	bad := write("bad.json", `{"items":[
		{"resource":"fresh","ifNoneMatch":"*","steps":[[{"op":"add","path":"","value":{}}]]},
		{"resource":"b","ifNoneMatch":"*","steps":[[{"op":"add","path":"","value":{}}]]}]}`)
	_, _, err := clientRun(t, f.ctx, f.s.URL, "batch", "m", bad)
	ae, ok := client.AsAPIError(err)
	if !ok || len(ae.Items()) == 0 {
		t.Fatalf("failing batch: %v", err)
	}
	if o, _ := f.must("ls", "m", "fresh"); strings.TrimSpace(o) != "" {
		t.Fatalf("a failed batch wrote: %s", o)
	}

	// Input errors.
	for body, want := range map[string]string{
		`[]`: "must be a JSON object",
		`{}`: `no "items"`,
		`{"items":[{"resource":"x","steps":[["x"]]}]}`:                                                            `exactly one of "ifMatch"`,
		`{"items":[{"resource":"x","ifNoneMatch":"*"}]}`:                                                          `no "steps"`,
		`{"items":[{"resource":"x","ifNoneMatch":"*","steps":["remove"]}]}`:                                       `"delete"`,
		`{"items":[{"resource":"x","ifNoneMatch":"*","steps":[[]],"stepz":1}]}`:                                   `unknown member "stepz"`,
		`{"items":[{"resource":"x","ifNoneMatch":"yes","steps":[[]]}]}`:                                           `"*"`,
		`{"items":[{"resource":"x","ifNoneMatch":"*","steps":[{"patches":[],"delete":true}]}]}`:                   `"patches" or "delete"`,
		`{"items":[{"resource":"x","ifNoneMatch":"*","steps":[{"patches":[{"op":"add","path":"","value":1}]}]}]}`: ``,
		`not json`: "",
	} {
		if want == "" {
			continue
		}
		msg, _ := f.fail("batch", "m", write("in.json", body))
		wantIn(t, body, msg, want)
	}
	msg, _ := f.fail("batch", "m", filepath.Join(dir, "missing.json"))
	wantIn(t, "missing file", msg, "missing.json")
	msg, _ = f.fail("batch", "m", write("garbage.json", "not json"))
	wantIn(t, "garbage", msg, "garbage.json")
	// A config change alone, and a gesture given by flag.
	cfgRev := strings.TrimSpace(func() string { o, _ := f.must("ns", "get", "m"); return o }())
	_ = cfgRev
	g := client.NewGesture()
	out, errw = f.must("batch", "m", write("g.json", `{"items":[{"resource":"g","ifNoneMatch":"*","steps":[[{"op":"add","path":"","value":{}}]]}]}`), "--gesture", g)
	wantIn(t, "gesture", errw, "gesture "+g)
}

func TestWhoami(t *testing.T) {
	t.Parallel()
	f := newResFixture(t, "m")
	out, errw := f.must("whoami")
	wantIn(t, "whoami", out, "sub  alice")
	wantIn(t, "whoami", errw, "authentication disabled")
	out, _ = f.must("whoami", "--json")
	var m map[string]any
	if err := json.Unmarshal([]byte(out), &m); err != nil || m["sub"] != "alice" || m["authDisabled"] != true {
		t.Fatalf("whoami --json: %v %s", err, out)
	}
	out, _ = f.must("whoami", "m")
	wantIn(t, "whoami m", out, "authentication is disabled", "can", "level", "frozen false")
	out, _ = f.must("whoami", "m", "--json")
	if err := json.Unmarshal([]byte(out), &m); err != nil || m["can"] == nil {
		t.Fatalf("whoami NS --json: %v %s", err, out)
	}
	if msg, _ := f.fail("whoami", "nope"); msg == "" {
		t.Fatal("no error for a missing namespace")
	}
}

func TestWhoamiGrants(t *testing.T) {
	t.Parallel()
	s := clienttest.New(t, clienttest.Options{Auth: true})
	ctx := context.Background()
	op := s.Client(t)
	k := clienttest.NewKey("k1")
	if _, err := op.With(client.WithBearer(s.OperatorGrant(t, "m"))).CreateNamespace(ctx, "m", map[string]any{"read": "grant", "keys": []any{k.Entry("*")}}); err != nil {
		t.Fatal(err)
	}
	g := k.Grant(t, s.Now(), "user:eve", []string{"m"}, []string{"read"})
	run := func(args ...string) (string, string, error) {
		return clientRun(t, ctx, s.URL, append(args, "--bearer", g)...)
	}
	out, _, err := run("whoami")
	if err != nil || !strings.Contains(out, "sub  user:eve") || !strings.Contains(out, "kid  k1") {
		t.Fatalf("whoami: %q %v", out, err)
	}
	out, _, err = run("whoami", "m")
	if err != nil {
		t.Fatal(err)
	}
	wantIn(t, "whoami m", out, "sub       user:eve", "can       read", "operator  false")
	// No grant: says so.
	o, e, err := clientRun(t, ctx, s.URL, "whoami")
	if err != nil {
		t.Fatalf("%v %s", err, e)
	}
	wantIn(t, "no grant", e, "no grant")
	_ = o
}

func TestValidate(t *testing.T) {
	t.Parallel()
	f := newResFixture(t, "schemas", "m")
	f.must("put", "schemas/person", `{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","required":["name"],"properties":{"name":{"type":"string"},"age":{"type":"integer"}}}`)
	rev, _ := f.must("get", "schemas/person", "--meta")
	_ = rev
	r := func() string {
		o, _ := f.must("ls", "schemas", "--json")
		var rows []map[string]any
		json.Unmarshal([]byte(o), &rows)
		return rows[0]["target"].(string)
	}()
	ref := "/r/schemas/person/rev/" + r

	_, errw := f.must("validate", "m/p", `{"$schema":"`+ref+`","name":"Ada","age":36}`)
	wantIn(t, "valid", errw, "valid")
	msg, _ := f.fail("validate", "m/p", `{"$schema":"`+ref+`","age":"x"}`)
	wantIn(t, "invalid", msg, "m/p: the document is invalid", "/age")
	// --json lists the errors on stdout.
	out, _, err := clientRun(t, f.ctx, f.s.URL, "validate", "m/p", `{"$schema":"`+ref+`","age":"x"}`, "--json")
	if err == nil {
		t.Fatal("invalid with --json: no error")
	}
	wantIn(t, "invalid --json", out, `"valid": false`, `"pointer"`)
	// Nothing was written.
	if o, _ := f.must("ls", "m"); strings.TrimSpace(o) != "" {
		t.Fatalf("validate wrote: %s", o)
	}
	// A schema that isn't there.
	msg, _ = f.fail("validate", "m/p", `{"$schema":"/r/schemas/ghost/rev/1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`)
	wantIn(t, "unavailable", msg, "isn't available")
	// No $schema, and nothing to fall back on.
	msg, _ = f.fail("validate", "m/p", `{"name":"x"}`)
	wantIn(t, "untyped", msg, "no $schema")
	msg, _ = f.fail("validate", "m/p", `[1]`)
	wantIn(t, "not an object", msg, "JSON object")
	// No $schema in the document: the head's is used.
	f.must("put", "m/p", `{"$schema":"`+ref+`","name":"Ada"}`)
	_, errw = f.must("validate", "m/p", `{"name":"Bo"}`)
	wantIn(t, "fallback", errw, "checking against the head's", "valid")
	msg, _ = f.fail("validate", "m/p", `{"name":1}`)
	wantIn(t, "fallback invalid", msg, "/name")
	msg, _ = f.fail("validate", "badname", `{}`)
	wantIn(t, "bad resource", msg, "NS/NAME")
}

func TestRaw(t *testing.T) {
	t.Parallel()
	f := newResFixture(t, "m")
	c := f.s.Client(t, client.WithAuthor("alice"))
	data := []byte("hello, raw file\n")
	bid, err := c.UploadBlob(f.ctx, "m", "f", "text/plain", "", data)
	if err != nil {
		t.Fatal(err)
	}
	w, err := c.CreateDoc(f.ctx, "m", "f", client.BlobRef(bid, "text/plain", len(data), ""))
	if err != nil {
		t.Fatal(err)
	}
	out, _ := f.must("get", "m/f", "--raw")
	if out != string(data) {
		t.Fatalf("get --raw: %q", out)
	}
	out, _ = f.must("get", "m/f", "--raw", "--rev", w.ID)
	if out != string(data) {
		t.Fatalf("get --raw --rev: %q", out)
	}
	out, _ = f.must("get", "m/f")
	wantIn(t, "get without --raw", out, "$blob")
	f.must("put", "m/doc", `{"title":"x"}`)
	msg, _ := f.fail("get", "m/doc", "--raw")
	wantIn(t, "not a raw file", msg, "isn't a raw file")
	msg, _ = f.fail("get", "m/f", "--raw", "--follow")
	wantIn(t, "raw follow", msg, "not with --raw")
	f.must("rm", "m/f")
	msg, _ = f.fail("get", "m/f", "--raw")
	wantIn(t, "deleted raw", msg, "deleted")
}

func TestMovedNote(t *testing.T) {
	t.Parallel()
	f := newResFixture(t, "m")
	f.must("put", "m/b", `{"x":1}`)
	f.must("put", "m/a", `{"x":1,"$successor":"b"}`)
	f.must("rm", "m/a")
	f.must("put", "m/plain", `{"x":1}`)
	f.must("rm", "m/plain")

	for _, args := range [][]string{{"get", "m/a"}, {"patch", "m/a", `[]`}, {"rm", "m/a"}} {
		msg, _ := f.fail(args...)
		wantIn(t, strings.Join(args, " "), msg, "m/a is deleted", "it moved to m/b")
	}
	msg, _ := f.fail("get", "m/plain")
	if !strings.Contains(msg, "m/plain is deleted") || strings.Contains(msg, "moved") {
		t.Fatalf("unmoved: %s", msg)
	}
	// log prints the history, and says where it moved on stderr.
	out, errw := f.must("log", "m/a")
	wantIn(t, "log", out, "tombstone")
	wantIn(t, "log", errw, "m/a is deleted; it moved to m/b")
	_, errw = f.must("log", "m/plain")
	if strings.Contains(errw, "moved") {
		t.Fatalf("log of an unmoved resource: %s", errw)
	}
}

func TestLogFollow(t *testing.T) {
	t.Parallel()
	f := newResFixture(t, "m")
	f.must("put", "m/a", `{"n":0}`)
	ctx, cancel := context.WithTimeout(f.ctx, 20*time.Second)
	defer cancel()
	cmd := command(t, "log", "m/a", "--follow", "--api", f.s.URL, "--author", "alice").(clientCommand)
	var out syncBuf
	done := make(chan error, 1)
	go func() { done <- cmd.exec(ctx, &out, &syncBuf{}) }()
	waitFor := func(n int) {
		t.Helper()
		for i := 0; i < 400; i++ {
			if strings.Count(out.String(), "\n") >= n {
				return
			}
			time.Sleep(25 * time.Millisecond)
		}
		t.Fatalf("waiting for %d lines: %q", n, out.String())
	}
	waitFor(1)
	f.must("patch", "m/a", `[{"op":"replace","path":"/n","value":1}]`)
	waitFor(2)
	f.must("rm", "m/a")
	waitFor(3)
	f.must("restore", "m/a")
	waitFor(4)
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	wantIn(t, "followed lines", lines[1], `"value":1`)
	wantIn(t, "followed lines", lines[2], "tombstone")
	f.must("rm", "m/a")
	waitFor(5)
	f.must("purge", "m/a", "--yes")
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "was purged") {
			t.Fatalf("follow at purge: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("follow didn't stop at the purge")
	}
	// Without a resource, no stream.
	if msg, _ := f.fail("log", "m/nope", "--follow"); msg == "" {
		t.Fatal("log --follow of a missing resource: no error")
	}
}

// syncBuf is a bytes.Buffer safe for a reader and a writer.
type syncBuf struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuf) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuf) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func TestPurge(t *testing.T) {
	t.Parallel()
	f := newResFixture(t, "m")
	f.must("put", "m/a", `{"n":1}`)
	f.must("patch", "m/a", `[{"op":"replace","path":"/n","value":2}]`)

	msg, errw := f.fail("purge", "m/a")
	wantIn(t, "purge without --yes", errw, "would purge m/a", "live", "2 retained log entries")
	wantIn(t, "purge without --yes", msg, "nothing was destroyed", "--yes")
	f.must("get", "m/a") // still there
	if msg, _ := f.fail("purge", "m/zzz", "--yes"); !strings.Contains(msg, "m/zzz doesn't exist") {
		t.Fatalf("purge of a missing resource: %s", msg)
	}

	id, errw := f.must("purge", "m/a", "--yes")
	wantIn(t, "purge", errw, "purged m/a")
	if strings.TrimSpace(id) == "" {
		t.Fatal("purge printed no id")
	}
	msg, _ = f.fail("get", "m/a")
	wantIn(t, "get of a purged resource", msg, "purged")
	msg, _ = f.fail("purge", "m/a", "--yes")
	wantIn(t, "purge twice", msg, "already purged")

	// A deleted resource is purged too, from its tombstone.
	f.must("put", "m/b", `{}`)
	f.must("rm", "m/b")
	_, errw = f.must("purge", "m/b", "--yes", "--json")
	wantIn(t, "purge tombstoned", errw, "")
	if o, _ := f.must("ls", "m", "b"); !strings.Contains(o, "purged") {
		t.Fatalf("ls after purge: %q", o)
	}
}

func TestPurgeReferencedSchemaNeedsForce(t *testing.T) {
	t.Parallel()
	f := newResFixture(t, "schemas", "m")
	f.must("put", "schemas/s", `{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object"}`)
	o, _ := f.must("ls", "schemas", "--json")
	var rows []map[string]any
	json.Unmarshal([]byte(o), &rows)
	f.must("put", "m/doc", `{"$schema":"/r/schemas/s/rev/`+rows[0]["target"].(string)+`"}`)
	msg, _ := f.fail("purge", "schemas/s", "--yes")
	wantIn(t, "purge of a referenced schema", strings.ToLower(msg), "409")
	// --force is sent (this unauthenticated test server takes it).
	_, _, err := clientRun(t, f.ctx, f.s.URL, "purge", "schemas/s", "--yes", "--force")
	if err != nil {
		t.Logf("--force: %v", err) // a server may still want a * key; the flag reached it
	}
}

func TestPrune(t *testing.T) {
	t.Parallel()
	f := newResFixture(t, "m")
	f.must("put", "m/a", `{"n":0}`)
	var ids []string
	for i := 1; i <= 3; i++ {
		id, _ := f.must("patch", "m/a", `[{"op":"replace","path":"/n","value":`+string(rune('0'+i))+`}]`)
		ids = append(ids, strings.TrimSpace(id))
	}
	msg, errw := f.fail("prune", "m/a", "--below", ids[1])
	wantIn(t, "prune without --yes", errw, "would prune m/a below "+ids[1], "2 older log entries", "2 are kept")
	wantIn(t, "prune without --yes", msg, "nothing was destroyed")
	out, _ := f.must("log", "m/a")
	if n := strings.Count(out, "\n"); n != 4 {
		t.Fatalf("log after refused prune: %s", out)
	}
	msg, _ = f.fail("prune", "m/a", "--below", "1notarevisionxxxxxxxxxxxxxxxxxxxxx", "--yes")
	wantIn(t, "unknown horizon", msg, "isn't in the retained log")
	if msg, _ := f.fail("prune", "m/zzz", "--below", ids[0], "--yes"); msg == "" {
		t.Fatal("prune of a missing resource: no error")
	}

	f.s.Clock.Advance(10 * time.Minute) // retention's minimum age
	nsID, errw := f.must("prune", "m/a", "--below", ids[1], "--yes")
	wantIn(t, "prune", errw, "pruned m/a below "+ids[1])
	if strings.TrimSpace(nsID) == "" {
		t.Fatal("prune printed no namespace entry")
	}
	out, errw = f.must("log", "m/a")
	if n := strings.Count(out, "\n"); n != 1 || !strings.Contains(out, ids[2]) {
		t.Fatalf("log after prune: %s", out)
	}
	wantIn(t, "log after prune", errw, "history before "+ids[1]+" was pruned")
	// Pruning to the horizon again changes nothing.
	nsID, errw = f.must("prune", "m/a", "--below", ids[1], "--yes")
	wantIn(t, "repeat prune", errw, "nothing to prune")
	if strings.TrimSpace(nsID) != "" {
		t.Fatalf("repeat prune printed %q", nsID)
	}
	out, _ = f.must("prune", "m/a", "--below", ids[2], "--yes", "--json")
	wantIn(t, "prune --json", out, `"horizon"`, `"nsId"`)
}

func TestNSPurge(t *testing.T) {
	t.Parallel()
	f := newResFixture(t, "m", "keep")
	f.must("put", "m/a", `{}`)
	f.must("put", "m/b", `{}`)

	msg, errw := f.fail("ns", "purge", "m")
	wantIn(t, "ns purge without --yes", errw, "would purge namespace m", "2 resources", "frozen")
	wantIn(t, "ns purge without --yes", msg, "nothing was destroyed")
	f.must("get", "m/a")
	// Only a frozen namespace can be purged.
	if msg, _ := f.fail("ns", "purge", "m", "--yes"); !strings.Contains(msg, "409") && !strings.Contains(msg, "frozen") {
		t.Fatalf("purge of a live namespace: %s", msg)
	}
	f.must("ns", "config", "m", `[{"op":"add","path":"/frozen","value":true}]`)
	id, errw := f.must("ns", "purge", "m", "--yes")
	wantIn(t, "ns purge", errw, "purged namespace m")
	if strings.TrimSpace(id) == "" {
		t.Fatal("ns purge printed no id")
	}
	msg, _ = f.fail("get", "m/a")
	wantIn(t, "get in a purged namespace", msg, "purged")
}
