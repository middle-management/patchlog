package tree_test

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/derived"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/keystore"
	"github.com/middle-management/patchlog/internal/seal"
	"github.com/middle-management/patchlog/internal/tree"
)

// v82Sealed is a sealed (E2) file-tree catalog cat over the sealed
// namespace files: root holds the folder old and the placement
// files.notes. w writes both; svc is a client for the service, whose
// grant reaches back before any rotation; full reads both whole.
type v82Sealed struct {
	t    *testing.T
	s    *clienttest.Server
	k    clienttest.Key
	w    *client.Client
	db   string
	full string
	keys map[string][]byte
}

// v82Title has what encoding/json writes otherwise than canonical JSON
// does: U+2028, which it escapes, and with the astral and private-use
// keys of other members, another key order.
const v82Title = "Old\u2028title \U0001F600"

func newV82Sealed(t *testing.T) *v82Sealed {
	t.Helper()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{Auth: true, KeyStore: must(keystore.New(keystore.Generate())), LongPoll: 150 * time.Millisecond})
	k := clienttest.NewKey("k")
	for ns, doc := range map[string]map[string]any{
		"files": {"read": "grant", "keys": []any{k.Entry("*")}, "encryption": map[string]any{"level": "sealed"}},
		"cat": {"read": "grant", "keys": []any{k.Entry("*")}, "encryption": map[string]any{"level": "sealed"},
			"catalog": filesCatalog("files")},
	} {
		must(s.Client(t, client.WithBearer(s.OperatorGrant(t, ns))).CreateNamespace(ctx, ns, doc))
	}
	all := []string{"cat", "files"}
	q := &v82Sealed{t: t, s: s, k: k, db: filepath.Join(t.TempDir(), "tree.db"), keys: map[string][]byte{}}
	q.w = s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:w", append(all, "cat-r7"), []string{"read", "create", "config", "branch"})), client.WithKeys(client.NewKeys(nil)))
	createNonced(t, q.w, "cat", "root", map[string]any{"parents": []any{}})
	createNonced(t, q.w, "cat", "old", map[string]any{"title": v82Title, "parents": parents("root")})
	createNonced(t, q.w, "files", "notes", map[string]any{"n": 1})
	createNonced(t, q.w, "cat", "files.notes", map[string]any{"parents": parents("root")})
	q.full = k.Grant(t, s.Now(), "user:r", append(all, "cat-r7"), []string{"read"})
	q.addKeys("cat", "files")
	return q
}

// addKeys reads the epoch keys of nss as they are now (keyOf).
func (q *v82Sealed) addKeys(nss ...string) {
	q.t.Helper()
	for _, ns := range nss {
		for _, e := range must(q.w.FetchKeys(context.Background(), ns, nil, nil)) {
			q.keys[e.Kid] = e.Key
		}
	}
}

func (q *v82Sealed) keyOf(kid string) []byte { return q.keys[kid] }

// svc is a client for the tree service, with opts added.
func (q *v82Sealed) svc(opts ...client.Option) *client.Client {
	return q.s.Client(q.t, append([]client.Option{client.WithBearer(q.k.Grant(q.t, q.s.Now(), "svc:tree", []string{"cat", "files", "cat-r7"}, []string{"read"},
		map[string]any{"nbf": q.s.Now().Add(-24 * time.Hour).Format(time.RFC3339)})), client.WithKeys(client.NewKeys(nil))}, opts...)...)
}

func (q *v82Sealed) exec(stmts ...string) {
	q.t.Helper()
	sq := must(sql.Open("sqlite", q.db))
	defer sq.Close()
	for _, s := range stmts {
		if _, err := sq.Exec(s); err != nil {
			q.t.Fatalf("%s: %v", s, err)
		}
	}
}

// v82Canonical fails unless pt, a sealed plaintext less its padding, is
// canonical JSON: the bytes a reader gets serialising it again.
func v82Canonical(t *testing.T, what string, pt []byte) {
	t.Helper()
	parsed, err := jsonv.Parse(pt)
	if err != nil || !bytes.Equal(jsonv.Canonical(parsed), pt) {
		t.Errorf("%s: the plaintext isn't canonical JSON (%v): %s", what, err, pt)
	}
}

// SVC-03 (SERVICES §E.2.6 What gets sealed): the plaintext of a listing
// sealed whole is the response body in canonical JSON, and of an entry
// the object of the members it replaces. SVC-04 (Values of another
// resource): a placement's file, drawn from its item, is sealed apart,
// its pl naming the item's namespace and name in the clear.
func TestV082SealedListingCanonical(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	q := newV82Sealed(t)
	x := startSvc(t, q.svc(), svcOpts{now: q.s.Now, db: q.db})
	x.caughtUp("cat", "files")

	f := x.fetch("/cat/children?of=root", q.full)
	if f.header.Get("Content-Type") != seal.ContentType {
		t.Fatalf("a listing of one epoch for a whole reader: %s", f.header.Get("Content-Type"))
	}
	pt := must(derived.OpenView(string(f.body), q.keyOf, derived.View{NS: "cat", Target: f.path}))
	v82Canonical(t, "a listing sealed whole", pt)
	if !bytes.Contains(pt, []byte(v82Title)) || bytes.Contains(pt, []byte(`\u2028`)) {
		t.Errorf("a listing sealed whole: U+2028 isn't written as itself: %s", pt)
	}
	// The file metadata nests inside, sealed as a value of files/notes.
	es := entriesOf(t, decode(t, pt))
	jwe, _ := fileOf(es["files.notes"])["sealed"].(string)
	if jwe == "" || len(fileOf(es["files.notes"])) != 1 {
		t.Fatalf("file of files.notes: %v", es["files.notes"])
	}
	h := must(seal.ParseHeader(jwe))
	if h.Kid != "files#1" || len(h.PL) != 3 || h.PL["ns"] != "files" || h.PL["name"] != "notes" || h.PL["view"] != f.path {
		t.Errorf("a placement's file: kid %s pl %v, want files#1 and { ns: files, name: notes, view }", h.Kid, h.PL)
	}
	fpt := must(derived.OpenItem(jwe, derived.ItemKey(q.keyOf, "files", "notes"), derived.View{NS: "cat", Target: f.path}, "files", "notes"))
	v82Canonical(t, "a placement's file", fpt)
	if m := decode(t, fpt); len(m) != 1 || m["file"] == nil {
		t.Errorf("a placement's file: plaintext %s, want an object of that one member", fpt)
	}
	// A reader comparing with another resource is refused on pl.
	if _, err := derived.OpenItem(jwe, derived.ItemKey(q.keyOf, "files", "memo"), derived.View{NS: "cat", Target: f.path}, "files", "memo"); !errors.Is(err, seal.ErrMismatch) {
		t.Errorf("a placement's file opened as another item's: %v, want ErrMismatch", err)
	}

	// Per entry, once the listing mixes epochs.
	must(q.s.Engine.RotateEpoch(ctx, "cat", "system:rotate"))
	q.addKeys("cat")
	createNonced(t, q.w, "cat", "new", map[string]any{"title": "New\u2028", "parents": parents("root")})
	x.caughtUp("cat")
	f = x.fetch("/cat/children?of=root", q.full)
	if f.header.Get("Content-Type") != "application/json" {
		t.Fatalf("a listing mixing epochs: %s", f.header.Get("Content-Type"))
	}
	for name, e := range entriesOf(t, decode(t, f.body)) {
		jwe, _ := e["sealed"].(string)
		if jwe == "" {
			continue
		}
		ept := must(derived.OpenItem(jwe, derived.ItemKey(q.keyOf, "cat", name), derived.View{NS: "cat", Target: f.path}, "cat", name))
		v82Canonical(t, "the entry of "+name, ept)
		if bytes.Contains(ept, []byte(`\u2028`)) {
			t.Errorf("the entry of %s: U+2028 escaped: %s", name, ept)
		}
	}
}

// v82NameOnly fails unless e, a listing's entry, carries its clear
// members only: nothing sealed, no title, no born.
func v82NameOnly(t *testing.T, what string, e map[string]any) {
	t.Helper()
	if e == nil || e["name"] == nil || e["href"] == nil || e["sealed"] != nil || e["title"] != nil || e["born"] != nil {
		t.Errorf("%s: %v, want it by name only", what, e)
	}
}

// SVC-05, scenario 73 (SERVICES §E.2.6 Per-entry sealing): until the
// service can judge the epoch of a revision it seals nothing derived
// from it. On a database whose heads' epochs aren't read in yet (meta
// "epochs" pending, nodes.epoch NULL, file metadata without an epoch), a
// listing served meanwhile gives those nodes by name only and their file
// metadata as { "absent": "pending" }: nothing is sealed under the
// current epoch, which here is cat#2 and files#2, one after the heads'.
// Once they are read in, the listing at that at is no longer the one by
// name only, and the values are sealed under the heads' epoch.
func TestV082UnjudgedEpochByNameOnly(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	q := newV82Sealed(t)
	x := startSvc(t, q.svc(), svcOpts{now: q.s.Now, db: q.db})
	x.caughtUp("cat", "files")
	x.stop()
	// The current epochs move on: a value sealed unjudged would be under
	// cat#2 or files#2, not its revision's epoch.
	must(q.s.Engine.RotateEpoch(ctx, "cat", "system:rotate"))
	must(q.s.Engine.RotateEpoch(ctx, "files", "system:rotate"))
	q.addKeys("cat", "files")
	q.exec(`UPDATE nodes SET epoch = NULL`, `UPDATE items SET file = json_remove(file, '$.epoch') WHERE file IS NOT NULL`,
		`INSERT INTO meta (k, v) VALUES ('epochs', 'pending') ON CONFLICT (k) DO NOTHING`, `DELETE FROM sealed_views`)

	release := make(chan struct{})
	x = startSvc(t, q.svc(v077Blocking("/r/", release)), svcOpts{now: q.s.Now, db: q.db})
	x.caughtUp("cat", "files")
	waitFor(t, "a listing during the fill", func() bool { return x.listingAs("/cat/children?of=root", q.full).status == http.StatusOK })
	during := x.fetch("/cat/children?of=root", q.full)
	if during.header.Get("Content-Type") != "application/json" {
		t.Fatalf("during the fill: a listing with unjudged nodes sealed whole (%s)", during.header.Get("Content-Type"))
	}
	if bytes.Contains(during.body, []byte("eyJ")) || bytes.Contains(during.body, []byte("Old")) {
		t.Errorf("during the fill: the listing carries a sealed or clear value: %s", during.body)
	}
	es := entriesOf(t, decode(t, during.body))
	v82NameOnly(t, "during the fill: old", es["old"])
	v82NameOnly(t, "during the fill: files.notes", es["files.notes"])
	if f := fileOf(es["files.notes"]); len(f) != 1 || f["absent"] != "pending" {
		t.Errorf("during the fill: file of files.notes %v, want { absent: pending }", es["files.notes"]["file"])
	}
	// Its values in other entries are left out too: breadcrumbs.
	if a := x.fetch("/cat/ancestors?of=old", q.full); a.header.Get("Content-Type") != "application/json" || bytes.Contains(a.body, []byte("sealed")) || bytes.Contains(a.body, []byte("Old")) {
		t.Errorf("during the fill: ancestors carry a value of old: %s %s", a.header.Get("Content-Type"), a.body)
	}
	var jwes int
	sq := must(sql.Open("sqlite", q.db))
	if err := sq.QueryRow(`SELECT count(*) FROM sealed_views WHERE json = 0 OR instr(CAST(body AS TEXT), 'eyJ') > 0`).Scan(&jwes); err != nil || jwes != 0 {
		t.Errorf("during the fill: %d stored views hold a JWE (%v)", jwes, err)
	}
	sq.Close()

	close(release)
	waitFor(t, "the epochs backfill", func() bool { return !x.s.EpochsPending() })
	after := x.fetch(during.path, q.full)
	if bytes.Equal(after.body, during.body) {
		t.Fatalf("after the fill: the listing by name only is still served at its at")
	}
	var body map[string]any
	if after.header.Get("Content-Type") == seal.ContentType {
		if kid := must(seal.ParseHeader(string(after.body))).Kid; kid != "cat#1" {
			t.Errorf("after the fill: sealed whole under %s, want cat#1, the heads' epoch", kid)
		}
		body = decode(t, must(derived.OpenView(string(after.body), q.keyOf, derived.View{NS: "cat", Target: after.path})))
	} else {
		body = decode(t, after.body)
	}
	es = entriesOf(t, body)
	if jwe, _ := es["old"]["sealed"].(string); jwe != "" {
		if kid := must(seal.ParseHeader(jwe)).Kid; kid != "cat#1" {
			t.Errorf("after the fill: old under %s, want cat#1", kid)
		}
	} else if es["old"]["title"] != v82Title {
		t.Errorf("after the fill: old %v, want its title", es["old"])
	}
	jwe, _ := fileOf(es["files.notes"])["sealed"].(string)
	if jwe == "" || must(seal.ParseHeader(jwe)).Kid != "files#1" {
		t.Errorf("after the fill: file of files.notes %v, want it sealed under files#1", es["files.notes"]["file"])
	}
}

// SVC-05: outside a fill too. A head stored without the epoch it is
// served under (at E2 one read before the namespace was sealed, or by an
// earlier release) is never sealed under the epoch current when a listing
// meets it, here cat#2 and files#2: the node is by name only, its file
// metadata pending, the head is read again for its kid, and its values
// are then sealed under that epoch, cat#1 and files#1.
func TestV082KidlessHeadIsReadAgain(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	q := newV82Sealed(t)
	x := startSvc(t, q.svc(), svcOpts{now: q.s.Now, db: q.db})
	x.caughtUp("cat", "files")
	x.stop()
	must(q.s.Engine.RotateEpoch(ctx, "cat", "system:rotate"))
	must(q.s.Engine.RotateEpoch(ctx, "files", "system:rotate"))
	q.addKeys("cat", "files")
	// No fill is pending: the epochs are simply not there.
	q.exec(`UPDATE nodes SET epoch = NULL WHERE name = 'old'`, `UPDATE items SET file = json_remove(file, '$.epoch') WHERE file IS NOT NULL`,
		`DELETE FROM meta WHERE k = 'epochs'`, `DELETE FROM sealed_views`)
	x = startSvc(t, q.svc(), svcOpts{now: q.s.Now, db: q.db})
	x.caughtUp("cat", "files")
	// Every kid a value of old or of the file was seen sealed under,
	// whole or per entry, until both are.
	seen := map[string]bool{}
	waitFor(t, "old and the file of files.notes to be sealed under their heads' epoch", func() bool {
		if x.listingAs("/cat/children?of=root", q.full).status != http.StatusOK {
			return false
		}
		f := x.fetch("/cat/children?of=root", q.full)
		body, old := f.body, false
		if f.header.Get("Content-Type") == seal.ContentType {
			kid := must(seal.ParseHeader(string(f.body))).Kid
			seen[kid] = true
			if q.keys[kid] == nil {
				return false
			}
			body = must(derived.OpenView(string(f.body), q.keyOf, derived.View{NS: "cat", Target: f.path}))
			old = entriesOf(t, decode(t, body))["old"]["title"] == v82Title
		}
		es := entriesOf(t, decode(t, body))
		if oj, _ := es["old"]["sealed"].(string); oj != "" {
			seen[must(seal.ParseHeader(oj)).Kid], old = true, true
		}
		fj, _ := fileOf(es["files.notes"])["sealed"].(string)
		if fj != "" {
			seen[must(seal.ParseHeader(fj)).Kid] = true
		}
		return old && fj != ""
	})
	for kid := range seen {
		if kid != "cat#1" && kid != "files#1" {
			t.Errorf("a value of a head whose epoch wasn't judged was sealed under %s", kid)
		}
	}
	if !seen["cat#1"] || !seen["files#1"] {
		t.Errorf("sealed under %v, want cat#1 and files#1", seen)
	}
	if e, _ := v077Epochs(t, q.db, "old"); e != 1 {
		t.Errorf("old's epoch %d stored, want 1 read in", e)
	}
}

// SVC-05 (stored data): tree migration 006 resets every born_epoch and
// marks the epochs pending again, so a born's epoch an earlier release
// judged as it was applied is read in again from the first revision
// (backfillEpochs), whatever markBornEpochs' "bornsnap" marker says.
func TestV082MigrationRejudgesBornEpochs(t *testing.T) {
	t.Parallel()
	q := newV82Sealed(t)
	x := startSvc(t, q.svc(), svcOpts{now: q.s.Now, db: q.db})
	x.caughtUp("cat", "files")
	waitFor(t, "the first start's fill", func() bool { return !x.s.EpochsPending() })
	x.stop()
	if _, b := v077Epochs(t, q.db, "old"); b != 1 {
		t.Fatalf("setup: old's born_epoch %d, want 1", b)
	}
	// As v0.27.0 left it: migration 006 not applied, a born_epoch that
	// isn't its first revision's, no fill pending, bornsnap recorded.
	q.exec(`DELETE FROM mmmigrate_applied WHERE namespace = 'tree' AND name = 'v082_rejudge'`,
		`UPDATE nodes SET born_epoch = 7 WHERE name = 'old'`, `DELETE FROM meta WHERE k = 'epochs'`)
	sq := must(sql.Open("sqlite", q.db))
	var snap string
	if err := sq.QueryRow(`SELECT v FROM meta WHERE k = 'bornsnap'`).Scan(&snap); err != nil {
		t.Fatalf("setup: bornsnap: %v", err)
	}
	sq.Close()

	release := make(chan struct{})
	x = startSvc(t, q.svc(v077Blocking("/r/", release), v077Blocking("/ns/cat/log", release)), svcOpts{now: q.s.Now, db: q.db})
	if !x.s.EpochsPending() {
		t.Fatal("after the migration: no fill pending")
	}
	if _, b := v077Epochs(t, q.db, "old"); b != 0 {
		t.Errorf("after the migration: old's born_epoch %d, want it reset", b)
	}
	close(release)
	waitFor(t, "the born epochs to be read in again", func() bool { _, b := v077Epochs(t, q.db, "old"); return b == 1 && !x.s.EpochsPending() })
}

// SVC-07, scenario 72 (SERVICES §E.2.6 Per-entry sealing, §B.5 Previews;
// SPEC §E.2.5): a release preview's entries, those read through from the
// base included, are sealed under the branch's K_r and epoch, never the
// base's: kid and pl.ns name the branch, while view keeps the URL as
// served. A reader holding the base's keys alone opens none. The
// branch's rotation moves the preview's epoch; the base's changes
// nothing.
func TestV082PreviewSealedUnderBranchKeys(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	q := newV82Sealed(t)
	must(q.w.CreateBranch(ctx, "cat", client.BranchRequest{Name: "cat-r7"}))
	q.addKeys("cat-r7")
	preview := func(o *tree.Options) { o.Branches = map[string]string{"cat": "cat-r7"} }
	x := startSvc(t, q.svc(), svcOpts{now: q.s.Now, db: q.db}, preview)
	reach := func() {
		t.Helper()
		waitFor(t, "the preview to reach cat-r7", func() bool {
			h, err := q.w.NSHead(ctx, "cat-r7")
			return err == nil && x.s.Checkpoint("cat") == h.ID
		})
	}
	reach()
	x.caughtUp("files")
	// entry is old's entry, its kid and the listing's path.
	entry := func() (kid string, pl seal.PL, jwe, path string, whole bool) {
		t.Helper()
		waitFor(t, "a listing", func() bool { return x.listingAs("/cat/children?of=root", q.full).status == http.StatusOK })
		f := x.fetch("/cat/children?of=root", q.full)
		if f.header.Get("Content-Type") == seal.ContentType {
			h := must(seal.ParseHeader(string(f.body)))
			return h.Kid, h.PL, string(f.body), f.path, true
		}
		jwe, _ = entriesOf(t, decode(t, f.body))["old"]["sealed"].(string)
		if jwe == "" {
			t.Fatalf("old isn't sealed: %s", f.body)
		}
		h := must(seal.ParseHeader(jwe))
		return h.Kid, h.PL, jwe, f.path, false
	}
	open := func(jwe, path, ns string, whole bool, keyOf func(string) []byte) (map[string]any, error) {
		v := derived.View{NS: ns, Target: path}
		if whole {
			pt, err := derived.OpenView(jwe, keyOf, v)
			if err != nil {
				return nil, err
			}
			return entriesOf(t, decode(t, pt))["old"], nil
		}
		pt, err := derived.OpenItem(jwe, derived.ItemKey(keyOf, ns, "old"), v, ns, "old")
		if err != nil {
			return nil, err
		}
		return decode(t, pt), nil
	}
	kid, pl, jwe, path, whole := entry()
	if kid != "cat-r7#1" || pl["ns"] != "cat-r7" || pl["view"] != path || !strings.HasPrefix(path, "/cat/") {
		t.Fatalf("a read-through node in the preview: kid %s, pl %v at %s; want the branch's kid and ns, the view as served", kid, pl, path)
	}
	if vals, err := open(jwe, path, "cat-r7", whole, q.keyOf); err != nil || vals["title"] != v82Title {
		t.Errorf("opened with the branch's key: %v %v", vals, err)
	}
	// The base's key of the same epoch number opens nothing.
	baseKey := func(string) []byte { return q.keys["cat#1"] }
	if _, err := open(jwe, path, "cat-r7", whole, baseKey); !errors.Is(err, seal.ErrDecrypt) {
		t.Errorf("opened with the base's key: %v, want ErrDecrypt", err)
	}
	if _, err := open(jwe, path, "cat", whole, q.keyOf); !errors.Is(err, seal.ErrMismatch) {
		t.Errorf("opened as the base's: %v, want ErrMismatch", err)
	}

	// A rotation of the base changes nothing in the preview.
	must(q.s.Engine.RotateEpoch(ctx, "cat", "system:rotate"))
	createNonced(t, q.w, "cat-r7", "draft", map[string]any{"title": "Draft", "parents": parents("root")})
	reach()
	f := x.fetch("/cat/children?of=root", q.full)
	if f.header.Get("Content-Type") != seal.ContentType || must(seal.ParseHeader(string(f.body))).Kid != "cat-r7#1" {
		t.Errorf("after the base's rotation: %s %s, want the listing whole under cat-r7#1", f.header.Get("Content-Type"), f.body[:min(len(f.body), 80)])
	}
	// The branch's rotation moves its epoch, without a restart: a node
	// written since is sealed under cat-r7#2, old still under cat-r7#1.
	must(q.s.Engine.RotateEpoch(ctx, "cat-r7", "system:rotate"))
	q.addKeys("cat-r7")
	createNonced(t, q.w, "cat-r7", "later", map[string]any{"title": "Later", "parents": parents("root")})
	reach()
	f = x.fetch("/cat/children?of=root", q.full)
	if f.header.Get("Content-Type") != "application/json" {
		t.Fatalf("after the branch's rotation: a listing mixing its epochs is %s", f.header.Get("Content-Type"))
	}
	for name, want := range map[string]string{"old": "cat-r7#1", "draft": "cat-r7#1", "later": "cat-r7#2"} {
		jwe, _ := entriesOf(t, decode(t, f.body))[name]["sealed"].(string)
		if jwe == "" || must(seal.ParseHeader(jwe)).Kid != want {
			t.Errorf("after the branch's rotation: %s sealed %.40q, want kid %s", name, jwe, want)
		} else if _, err := derived.OpenItem(jwe, derived.ItemKey(q.keyOf, "cat-r7", name), derived.View{NS: "cat-r7", Target: f.path}, "cat-r7", name); err != nil {
			t.Errorf("after the branch's rotation: %s: %v", name, err)
		}
	}
}
