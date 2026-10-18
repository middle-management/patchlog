package tree_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/derived"
	"github.com/middle-management/patchlog/internal/files"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/keystore"
	"github.com/middle-management/patchlog/internal/seal"
	"github.com/middle-management/patchlog/internal/tree"
)

// filesCatalog is a catalog document making cat a file tree over ns.
func filesCatalog(trust ...string) map[string]any {
	t := make([]any, len(trust))
	for i, ns := range trust {
		t[i] = ns
	}
	return map[string]any{"trust": t, "mode": "tree", "files": map[string]any{"ns": trust[0], "root": "root"}}
}

// entriesOf maps a children listing's entries by name.
func entriesOf(t *testing.T, body map[string]any) map[string]map[string]any {
	t.Helper()
	out := map[string]map[string]any{}
	list, _ := body["children"].([]any)
	for _, x := range list {
		e := x.(map[string]any)
		out[e["name"].(string)] = e
	}
	return out
}

// createdOf is the created of a resource's head as /heads gives it.
func createdOf(t *testing.T, c *client.Client, ns, name string) string {
	t.Helper()
	ctx := context.Background()
	items, _ := must2(c.HeadsPage(ctx, ns, must(c.NSHead(ctx, ns)).ID, ""))
	for _, it := range items {
		if it.Resource == name {
			return it.Created
		}
	}
	t.Fatalf("%s/%s not in /heads", ns, name)
	return ""
}

func must2[A, B any](a A, b B, err error) (A, B) {
	if err != nil {
		panic(err)
	}
	return a, b
}

func fileOf(e map[string]any) map[string]any { f, _ := e["file"].(map[string]any); return f }

// §H.3: a tree service following a file tree adds to each placement
// file: { size, type, modified } from the item's head: a raw file's
// reference, a JSON file's rendering and application/json, and the head's
// created, read once per revision.
func TestFileTreeMetadata(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{LongPoll: 150 * time.Millisecond})
	c := s.Client(t, client.WithAuthor("tester"))
	must(c.CreateNamespace(ctx, "files", map[string]any{"read": "public"}))
	must(c.CreateNamespace(ctx, "cat", map[string]any{"read": "public", "catalog": filesCatalog("files")}))
	must(c.CreateDoc(ctx, "cat", "root", map[string]any{"title": "Files", "parents": []any{}}))
	must(c.CreateDoc(ctx, "cat", "sub", map[string]any{"title": "Sub", "parents": parents("root@a2")}))
	x := startSvc(t, c, svcOpts{})

	// A JSON file with a fresh $nonce and keys that look like indices,
	// whose rendering leaves the nonce out and keeps JCS's order.
	notes := map[string]any{"title": "Notes", "10": "x", "2": []any{1, map[string]any{}}, "$nonce": seal.NewNonce()}
	must(c.CreateDoc(ctx, "files", "notes", notes))
	data := []byte("\x89PNG not really")
	bid := must(c.UploadBlob(ctx, "files", "pic", "image/png", "", data))
	must(c.CreateDoc(ctx, "files", "pic", map[string]any{"$blob": bid, "type": "image/png", "size": len(data)}))
	must(c.CreateDoc(ctx, "cat", "files.notes", map[string]any{"title": "notes.json", "parents": parents("root@a0")}))
	must(c.CreateDoc(ctx, "cat", "files.pic", map[string]any{"title": "pic.png", "parents": parents("root@a1")}))
	must(c.CreateDoc(ctx, "cat", "files.gone", map[string]any{"title": "gone.txt", "parents": parents("root@a3")}))
	x.caughtUp("cat", "files")

	es := entriesOf(t, x.get("/cat/children?of=root", ""))
	want := map[string]any{"size": float64(len(files.Rendering(jsonv.FromGo(notes)))), "type": "application/json", "modified": createdOf(t, c, "files", "notes")}
	if got := fileOf(es["files.notes"]); !reflect.DeepEqual(got, want) {
		t.Fatalf("notes file %v, want %v", got, want)
	}
	if !strings.Contains(string(files.Rendering(jsonv.FromGo(notes))), "\"10\": \"x\",\n  \"2\": [") {
		t.Fatalf("rendering %s", files.Rendering(jsonv.FromGo(notes)))
	}
	want = map[string]any{"size": float64(len(data)), "type": "image/png", "modified": createdOf(t, c, "files", "pic")}
	if got := fileOf(es["files.pic"]); !reflect.DeepEqual(got, want) {
		t.Fatalf("pic file %v, want %v", got, want)
	}
	// Folders have none, and dangling placements aren't listed.
	if _, has := es["sub"]["file"]; has || es["sub"]["kind"] != "folder" {
		t.Fatalf("folder %v", es["sub"])
	}
	if _, listed := es["files.gone"]; listed {
		t.Fatalf("dangling placement listed: %v", es["files.gone"])
	}
	// Other listings carry it too.
	sub := x.get("/cat/subtree?of=root", "")
	if !strings.Contains(fmt.Sprint(sub), "image/png") {
		t.Fatalf("subtree %v", sub)
	}

	// A new head is read again; a tombstone leaves none.
	at := x.s.At()
	h := must(c.Head(ctx, "files", "notes"))
	must(c.Append(ctx, "files", "notes", h.ID, []any{map[string]any{"op": "add", "path": "/body", "value": strings.Repeat("y", 100)}}))
	x.caughtUp("files")
	if x.s.At() == at {
		t.Fatal("at didn't move")
	}
	es = entriesOf(t, x.get("/cat/children?of=root", ""))
	notes["body"] = strings.Repeat("y", 100)
	want = map[string]any{"size": float64(len(files.Rendering(jsonv.FromGo(notes)))), "type": "application/json", "modified": createdOf(t, c, "files", "notes")}
	if got := fileOf(es["files.notes"]); !reflect.DeepEqual(got, want) {
		t.Fatalf("notes file after an append %v, want %v", got, want)
	}
	must(c.Delete(ctx, "files", "pic", must(c.Head(ctx, "files", "pic")).ID))
	x.caughtUp("files")
	if _, listed := entriesOf(t, x.get("/cat/children?of=root", ""))["files.pic"]; listed {
		t.Fatal("tombstoned item listed")
	}
	x.s.View(func(g *tree.Graph, _ map[string]string) {
		if n := g.Node("files.pic"); n == nil || n.ItemFile != nil || n.State != tree.StateDangling {
			t.Errorf("tombstoned item keeps file metadata: %+v", n)
		}
	})
}

// §H.3, §B.5: catalog.files coming or going moves listings to a new at
// with file metadata read for every live item, or none; a database whose
// items lack it is filled in on start.
func TestFileTreeRefile(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{LongPoll: 150 * time.Millisecond})
	c := s.Client(t, client.WithAuthor("tester"))
	must(c.CreateNamespace(ctx, "files", map[string]any{"read": "public"}))
	must(c.CreateNamespace(ctx, "cat", map[string]any{"read": "public", "catalog": map[string]any{"trust": []any{"files"}, "mode": "tree"}}))
	must(c.CreateDoc(ctx, "cat", "root", map[string]any{"parents": []any{}}))
	doc := map[string]any{"a": []any{}}
	must(c.CreateDoc(ctx, "files", "a", doc))
	must(c.CreateDoc(ctx, "cat", "files.a", map[string]any{"parents": parents("root")}))
	db := filepath.Join(t.TempDir(), "tree.db")
	x := startSvc(t, c, svcOpts{db: db})
	x.caughtUp("cat", "files")
	if f := fileOf(entriesOf(t, x.get("/cat/children?of=root", ""))["files.a"]); f != nil {
		t.Fatalf("file outside a file tree: %v", f)
	}
	want := map[string]any{"size": float64(len("{\n  \"a\": []\n}\n")), "type": "application/json", "modified": createdOf(t, c, "files", "a")}

	setFiles := func(on bool) {
		t.Helper()
		var op map[string]any
		if on {
			op = map[string]any{"op": "add", "path": "/catalog/files", "value": map[string]any{"ns": "files", "root": "root"}}
		} else {
			op = map[string]any{"op": "remove", "path": "/catalog/files"}
		}
		must(c.PatchConfig(ctx, "cat", must(c.NSHead(ctx, "cat")).Config, []any{op}))
		x.caughtUp("cat")
	}
	setFiles(true)
	if got := fileOf(entriesOf(t, x.get("/cat/children?of=root", ""))["files.a"]); !reflect.DeepEqual(got, want) {
		t.Fatalf("file once a file tree %v, want %v", got, want)
	}
	setFiles(false)
	if f := fileOf(entriesOf(t, x.get("/cat/children?of=root", ""))["files.a"]); f != nil {
		t.Fatalf("file once no file tree: %v", f)
	}
	setFiles(true)

	// A database from before file metadata: the rows lose it, and a start
	// fills it in again.
	x.stop()
	sq := must(sql.Open("sqlite", db))
	if _, err := sq.Exec(`UPDATE items SET file = NULL`); err != nil {
		t.Fatal(err)
	}
	if _, err := sq.Exec(`DELETE FROM meta WHERE k = 'filed'`); err != nil {
		t.Fatal(err)
	}
	sq.Close()
	x = startSvc(t, c, svcOpts{db: db})
	x.caughtUp("cat", "files")
	waitFor(t, "backfill", func() bool {
		return reflect.DeepEqual(fileOf(entriesOf(t, x.get("/cat/children?of=root", ""))["files.a"]), want)
	})
}

// §H.3, §E.2.6: items of a sealed namespace carry file sealed per entry
// under their own K_r, bound to the listing's view; items of an e2e one
// carry none, even for a service that reads them.
func TestFileTreeSealed(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ks := must(keystore.New(keystore.Generate()))
	s := clienttest.New(t, clienttest.Options{Auth: true, KeyStore: ks, LongPoll: 150 * time.Millisecond})
	k := clienttest.NewKey("k")
	for ns, doc := range map[string]map[string]any{
		"files":  {"read": "grant", "keys": []any{k.Entry("*")}, "encryption": map[string]any{"level": "sealed"}},
		"secret": {"read": "grant", "keys": []any{k.Entry("*")}, "encryption": map[string]any{"level": "e2e"}},
		"cat":    {"read": "grant", "keys": []any{k.Entry("*")}, "catalog": filesCatalog("files", "secret")},
	} {
		must(s.Client(t, client.WithBearer(s.OperatorGrant(t, ns))).CreateNamespace(ctx, ns, doc))
	}
	svcJWK, svcPriv, err := seal.GenerateRecipient()
	if err != nil {
		t.Fatal(err)
	}
	wJWK, wPriv, err := seal.GenerateRecipient()
	if err != nil {
		t.Fatal(err)
	}
	all := []string{"cat", "files", "secret"}
	w := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:w", all, []string{"read", "create", "append", "config"}, map[string]any{"enc": wJWK})),
		client.WithKeys(client.NewKeys(wPriv)))
	x2 := w.E2E(wPriv)
	must(x2.InitKeyring(ctx, "secret", svcPriv.PublicKey()))
	must(w.CreateDoc(ctx, "cat", "root", map[string]any{"parents": []any{}}))

	sc := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "svc:tree", all, []string{"read"}, map[string]any{"enc": svcJWK})),
		client.WithKeys(client.NewKeys(svcPriv)))
	x := startSvc(t, sc, svcOpts{now: s.Now}, func(o *tree.Options) { o.Recipient = svcPriv })
	x.caughtUp("cat", "files", "secret")

	doc := map[string]any{"title": "Sealed q7zv"}
	createNonced(t, w, "files", "notes", doc)
	must(x2.CreateDocSealed(ctx, "secret", "s1", map[string]any{"title": "e2e"}))
	must(w.CreateDoc(ctx, "cat", "files.notes", map[string]any{"parents": parents("root@a0")}))
	must(w.CreateDoc(ctx, "cat", "secret.s1", map[string]any{"parents": parents("root@a1")}))
	x.caughtUp("cat", "files", "secret")

	reader := k.Grant(t, s.Now(), "user:r", all, []string{"read"})
	f := x.fetch("/cat/children?of=root", reader)
	if strings.Contains(string(f.body), "application/json") || strings.Contains(string(f.body), "\"size\"") {
		t.Fatalf("file metadata in the clear: %s", f.body)
	}
	es := entriesOf(t, decode(t, f.body))
	if _, has := es["secret.s1"]["file"]; has || es["secret.s1"]["head"] == nil {
		t.Fatalf("e2e item %v", es["secret.s1"])
	}
	jwe, _ := fileOf(es["files.notes"])["sealed"].(string)
	if jwe == "" {
		t.Fatalf("sealed item %v", es["files.notes"])
	}
	epoch := map[string][]byte{}
	kr := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:keys", []string{"files"}, []string{"read"})))
	for _, e := range must(kr.FetchKeys(ctx, "files", nil, nil)) {
		epoch[e.Kid] = e.Key
	}
	keyOf := func(kid string) []byte { return epoch[kid] }
	v := derived.View{NS: "cat", Target: f.path}
	var got struct {
		File map[string]any `json:"file"`
	}
	if err := json.Unmarshal(must(derived.OpenItem(jwe, derived.ItemKey(keyOf, "files", "notes"), v, "files", "notes")), &got); err != nil {
		t.Fatal(err)
	}
	// The document as stored: with its fresh $nonce, which the rendering
	// leaves out.
	h, dd := must2(w.Load(ctx, "files", "notes"))
	if got.File["size"] != float64(len(files.Rendering(dd.Value))) || got.File["type"] != "application/json" || got.File["modified"] == nil {
		t.Fatalf("opened file %v (head %s)", got.File, h.ID)
	}
	if _, err := derived.OpenItem(jwe, derived.ItemKey(keyOf, "files", "other"), v, "files", "other"); err == nil {
		t.Fatal("opened as another item")
	}
	// Sealed once, served unchanged.
	if again := x.fetch(f.path, reader); string(again.body) != string(f.body) {
		t.Fatal("resealed on a second read")
	}
}

// §E.2.6: in a sealed catalog, a reader of the whole catalog gets the
// listing as one JWE under the catalog's epoch key, and inside it a sealed
// item's file is still sealed under the item's K_r: the catalog's keys
// open no content-derived value.
func TestFileTreeSealedCatalog(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ks := must(keystore.New(keystore.Generate()))
	s := clienttest.New(t, clienttest.Options{Auth: true, KeyStore: ks, LongPoll: 150 * time.Millisecond})
	k := clienttest.NewKey("k")
	sealed := map[string]any{"level": "sealed"}
	for ns, doc := range map[string]map[string]any{
		"files": {"read": "grant", "keys": []any{k.Entry("*")}, "encryption": sealed},
		"cat":   {"read": "grant", "keys": []any{k.Entry("*")}, "encryption": sealed, "catalog": filesCatalog("files")},
	} {
		must(s.Client(t, client.WithBearer(s.OperatorGrant(t, ns))).CreateNamespace(ctx, ns, doc))
	}
	all := []string{"cat", "files"}
	w := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:w", all, []string{"read", "create"})), client.WithKeys(client.NewKeys(nil)))
	sc := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "svc:tree", all, []string{"read"})), client.WithKeys(client.NewKeys(nil)))
	x := startSvc(t, sc, svcOpts{now: s.Now})
	createNonced(t, w, "cat", "root", map[string]any{"parents": []any{}})
	createNonced(t, w, "files", "notes", map[string]any{"n": 1})
	createNonced(t, w, "cat", "files.notes", map[string]any{"title": "notes.json", "parents": parents("root")})
	x.caughtUp("cat", "files")

	keys := func(ns string) func(string) []byte {
		m := map[string][]byte{}
		for _, e := range must(w.FetchKeys(ctx, ns, nil, nil)) {
			m[e.Kid] = e.Key
		}
		return func(kid string) []byte { return m[kid] }
	}
	f := x.fetch("/cat/children?of=root", k.Grant(t, s.Now(), "user:r", all, []string{"read"}))
	if ct := f.header.Get("Content-Type"); ct != seal.ContentType {
		t.Fatalf("listing %q %s", ct, f.body)
	}
	v := derived.View{NS: "cat", Target: f.path}
	body := must(derived.OpenView(string(f.body), keys("cat"), v))
	if strings.Contains(string(body), "application/json") {
		t.Fatalf("file metadata under the catalog's key alone: %s", body)
	}
	e := entriesOf(t, decode(t, body))["files.notes"]
	jwe, _ := fileOf(e)["sealed"].(string)
	if e["title"] != "notes.json" || jwe == "" {
		t.Fatalf("entry %v", e)
	}
	if _, err := derived.OpenItem(jwe, derived.ItemKey(keys("cat"), "files", "notes"), v, "files", "notes"); err == nil {
		t.Fatal("the catalog's key opened the item's file")
	}
	got := decode(t, must(derived.OpenItem(jwe, derived.ItemKey(keys("files"), "files", "notes"), v, "files", "notes")))
	if f, _ := got["file"].(map[string]any); f["type"] != "application/json" || f["size"] != float64(len("{\n  \"n\": 1\n}\n")) {
		t.Fatalf("file %v", got)
	}
}

// §2.1, §C.4: a read grant from a key with readScope "resource" that
// doesn't fix /resource is refused, by the core and by the service alike:
// listings show it no item's head or file metadata.
func TestFileTreeReadScope(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{Auth: true, LongPoll: 150 * time.Millisecond})
	k := clienttest.NewKey("k")
	rk := clienttest.NewKey("rk")
	scoped := rk.Entry("read")
	scoped["readScope"] = "resource"
	for ns, doc := range map[string]map[string]any{
		"files": {"read": "grant", "keys": []any{k.Entry("*"), scoped}},
		"cat":   {"read": "public", "keys": []any{k.Entry("*"), rk.Entry("read")}, "catalog": filesCatalog("files")},
	} {
		must(s.Client(t, client.WithBearer(s.OperatorGrant(t, ns))).CreateNamespace(ctx, ns, doc))
	}
	all := []string{"cat", "files"}
	w := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:w", all, []string{"read", "create", "append", "config"})))
	must(w.CreateDoc(ctx, "cat", "root", map[string]any{"parents": []any{}}))
	must(w.CreateDoc(ctx, "files", "secret", map[string]any{"title": "x"}))
	must(w.CreateDoc(ctx, "cat", "files.secret", map[string]any{"title": "s.json", "parents": parents("root@a0")}))
	x := startSvc(t, s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "svc:tree", all, []string{"read"}))), svcOpts{now: s.Now})
	x.caughtUp("cat", "files")

	bad := rk.Grant(t, s.Now(), "user:r", all, []string{"read"})
	if h, _, err := s.Client(t, client.WithBearer(bad)).Load(ctx, "files", "secret"); err == nil && h.State == client.Live {
		t.Fatal("the core reads with it")
	}
	e := entriesOf(t, x.get("/cat/children?of=root", bad))["files.secret"]
	if e == nil || e["head"] != nil || e["file"] != nil {
		t.Fatalf("entry under a grant the core refuses: %v", e)
	}
	// Fixing /resource, it reads that item.
	good := rk.Grant(t, s.Now(), "user:r", all, []string{"read"}, map[string]any{"rules": []any{map[string]any{"op": "test", "path": "/resource", "value": "secret"}}})
	if e := entriesOf(t, x.get("/cat/children?of=root", good))["files.secret"]; e["head"] == nil || fileOf(e) == nil {
		t.Fatalf("entry under a grant fixing /resource: %v", e)
	}
}
