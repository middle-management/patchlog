package merge_test

import (
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/grant"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/keystore"
	"github.com/middle-management/patchlog/internal/merge"
	"github.com/middle-management/patchlog/internal/release"
	"github.com/middle-management/patchlog/internal/seal"
)

// Spec v0.56–v0.73 for the merge, rebase and release tools (P06).

func cp(from, path string) map[string]any {
	return map[string]any{"op": "copy", "from": from, "path": path}
}

// §F.3 (neither): the branch side's writes count the from of every copy
// too; the target side's don't.
func TestV073BranchCopyFromConflicts(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.branch("matches", "r7")
	e.append("r7", "derby", cp("/title", "/subtitle"))
	e.append("matches", "derby", op("replace", "/title", "The Derby"))
	// The target copies from what the branch changes: no conflict.
	e.append("r7", "cup", op("replace", "/score", "2-1"))
	e.append("matches", "cup", cp("/score", "/half"))

	p := e.plan("matches", "r7", merge.Options{})
	r := p.Resource("derby")
	if !hasConflict(r, merge.ConflictOverlap) {
		t.Fatalf("derby: a replayed copy from a path the target changed doesn't conflict: %+v", r)
	}
	if !reflect.DeepEqual(r.BranchWrites, []string{"/subtitle", "/title"}) {
		t.Fatalf("branch writes %v", r.BranchWrites)
	}
	c := p.Resource("cup")
	if c.NeedsPerson() || !reflect.DeepEqual(c.BaseWrites, []string{"/half"}) {
		t.Fatalf("cup: %+v", c)
	}

	// The exported forms, with the array rule applied to the from.
	doc := map[string]any{"a": []any{1, 2}, "b": map[string]any{}}
	steps := []client.Step{client.PatchStep(ops(cp("/a/0", "/b/x")))}
	if w := must(merge.BranchWrites(doc, true, steps)); !reflect.DeepEqual(w, []string{"/a", "/b/x"}) {
		t.Fatalf("branch writes %v", w)
	}
	if w := must(merge.Writes(doc, true, steps)); !reflect.DeepEqual(w, []string{"/b/x"}) {
		t.Fatalf("target writes %v", w)
	}
}

// §6.4.1 (v0.67) in the merge tools: an insertion or removal that shifts
// an array's elements writes the array itself, which under the array rule
// (§F.3) is an element of its parent array when arrays nest.
func TestV073MergeWritesShiftedArray(t *testing.T) {
	t.Parallel()
	doc := map[string]any{"rows": []any{[]any{"a", "b"}, []any{"c"}}}
	for _, c := range []struct {
		patch map[string]any
		want  []string
	}{
		{op("add", "/rows/0/0", "z"), []string{"/rows", "/rows/0"}},
		{rm("/rows/0/0"), []string{"/rows", "/rows/0"}},
		{op("add", "/rows/0/-", "z"), []string{"/rows/0"}},
		{rm("/rows/1/0"), []string{"/rows/1"}},
	} {
		w := must(merge.Writes(doc, true, []client.Step{client.PatchStep(ops(c.patch))}))
		if !reflect.DeepEqual(w, c.want) {
			t.Fatalf("%v: writes %v want %v", c.patch, w, c.want)
		}
	}
	// So a branch inserting into one row and a target editing another
	// conflict: the insertion shifted the row, an element of rows.
	e := newEnv(t)
	e.create("matches", "grid", doc)
	e.branch("matches", "r7")
	e.append("r7", "grid", op("add", "/rows/0/0", "z"))
	e.append("matches", "grid", op("replace", "/rows/1/0", "d"))
	if r := e.plan("matches", "r7", merge.Options{}).Resource("grid"); !hasConflict(r, merge.ConflictOverlap) {
		t.Fatalf("grid: %+v", r)
	}
}

// §6.2 step 3 (v0.65) in the merge tools: a create's patch set applies to
// the document null, so the tools fold a branch's create of [test "" null,
// add "" …] as the server does.
func TestV073MergeFoldsCreateOntoNull(t *testing.T) {
	steps := []client.Step{client.PatchStep(ops(op("test", "", nil), op("add", "", map[string]any{"a": 1.0})))}
	w, err := merge.Writes(nil, false, steps)
	if err != nil || !reflect.DeepEqual(w, []string{""}) {
		t.Fatalf("writes %v, %v", w, err)
	}
	d, deleted, err := merge.ApplySteps(nil, false, false, append(steps, client.PatchStep(ops(op("replace", "/a", 2.0)))))
	if err != nil || deleted || !reflect.DeepEqual(d, map[string]any{"a": 2.0}) {
		t.Fatalf("fold %v %v %v", d, deleted, err)
	}
	// A root replace on null creates too.
	if _, _, err := merge.ApplySteps(nil, false, false, []client.Step{client.PatchStep(ops(op("replace", "", map[string]any{})))}); err != nil {
		t.Fatalf("root replace on null: %v", err)
	}
}

func nsDoc(t *testing.T, c *client.Client, ns string) map[string]any {
	t.Helper()
	h := must(c.NSHead(ctx, ns))
	return must(c.NSDoc(ctx, ns, h.ID)).Value
}

// §F.5 step 1, §2.1 (v0.68, v0.69): the successor of a sealed branch whose
// read is public is created with read "grant": as a target a sealed public
// namespace ranks public, below the old branch, which ranks sealed as a
// source whatever its read. The replay then goes in.
func TestV073RebaseSealedPublicSuccessorGrant(t *testing.T) {
	t.Parallel()
	ks, err := keystore.New(keystore.Generate())
	noErr(t, err)
	s := clienttest.New(t, clienttest.Options{KeyStore: ks})
	c := s.Client(t, client.WithAuthor("alice")).With(client.WithKeys(client.NewKeys(nil)))
	e := &env{t: t, s: s, c: c}
	must(c.CreateNamespace(ctx, "matches", map[string]any{"read": "public", "encryption": map[string]any{"level": "sealed"}}))
	nonced := func(ps ...map[string]any) []any { return append(ops(ps...), op("add", "/$nonce", seal.NewNonce())) }
	must(c.Create(ctx, "matches", "derby", nonced(op("add", "", map[string]any{"score": "0-0"}))))
	e.branch("matches", "r7") // no read patch: read public, sealed
	if d := nsDoc(t, c, "r7"); d["read"] != "public" {
		t.Fatalf("r7 %v", d)
	}
	must(c.Append(ctx, "r7", "derby", e.head("r7", "derby").ID, nonced(op("replace", "/score", "1-0"))))

	res, err := merge.Rebase(ctx, c, merge.RebaseOptions{Branch: "r7", New: "r7-b", Switch: true})
	noErr(t, err)
	if !res.Created || res.FirstResult == nil || !res.Switched {
		t.Fatalf("rebase %+v", res)
	}
	if d := nsDoc(t, c, "r7-b"); d["read"] != "grant" {
		t.Fatalf("successor read %v, want grant", d["read"])
	}
	if e.head("r7-b", "derby").ID != e.head("r7", "derby").ID {
		t.Fatal("derby didn't fast-forward into the successor")
	}
}

// §F.5 step 1: the old branch's read is its document's, "grant" by
// default; a successor copying a base that became public since doesn't
// take the base's.
func TestV073RebaseSuccessorKeepsDefaultRead(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	must(e.c.CreateNamespace(ctx, "drafts", map[string]any{}))
	e.create("drafts", "memo", map[string]any{"t": "a"})
	e.branch("drafts", "d7")
	e.append("d7", "memo", op("replace", "/t", "b"))
	h := must(e.c.NSHead(ctx, "drafts"))
	must(e.c.PatchConfig(ctx, "drafts", h.Config, ops(op("add", "/read", "public"))))
	if _, ok := nsDoc(t, e.c, "d7")["read"]; ok {
		t.Fatal("d7 has a read member")
	}
	res := must(merge.Rebase(ctx, e.c, merge.RebaseOptions{Branch: "d7", New: "d7-b"}))
	if !res.Created || res.FirstResult == nil {
		t.Fatalf("rebase %+v", res)
	}
	if d := nsDoc(t, e.c, "d7-b"); d["read"] != "grant" {
		t.Fatalf("successor read %v, want grant", d["read"])
	}
}

// §F.5 step 1 (v0.68): a rebase never replays into a successor that ranks
// below the old branch, a resumed one included; the error names both
// ranks, and nothing is written.
func TestV073RebaseRefusesLowerSuccessor(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	must(e.c.CreateBranch(ctx, "matches", client.BranchRequest{Name: "r7", Patches: ops(op("add", "/read", "grant"))}))
	e.append("r7", "derby", op("replace", "/score", "1-0"))
	e.branch("matches", "r7-b") // public, as matches
	before := must(e.c.NSHead(ctx, "r7-b")).ID
	_, err := merge.Rebase(ctx, e.c, merge.RebaseOptions{Branch: "r7", New: "r7-b", Switch: true})
	if err == nil || !strings.Contains(err.Error(), "ranks public") || !strings.Contains(err.Error(), "ranks private") {
		t.Fatalf("rebase into a public successor of a private branch: %v", err)
	}
	if after := must(e.c.NSHead(ctx, "r7-b")).ID; after != before {
		t.Fatal("something was replayed into the successor")
	}
	if f, _ := nsDoc(t, e.c, "r7")["frozen"].(bool); f {
		t.Fatal("the old branch was switched")
	}
}

// §7.4, §F.5 (v0.63): a successor may be a branch of a namespace further up
// the old branch's base chain, so Switch is allowed when Onto is in it
// (retargeting a stacked branch after a fast-forward merge, §F.4), and
// refused when it isn't.
func TestV073RebaseSwitchUpTheChain(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.branch("matches", "r7")
	e.append("r7", "derby", op("replace", "/score", "1-0"))
	e.branch("r7", "b2")
	e.append("b2", "derby", op("replace", "/score", "2-0"))
	must(e.plan("matches", "r7", merge.Options{}).Apply(ctx))
	must(e.c.CreateNamespace(ctx, "elsewhere", map[string]any{"read": "public"}))
	if _, err := merge.Rebase(ctx, e.c, merge.RebaseOptions{Branch: "b2", New: "b2-x", Onto: "elsewhere", Switch: true}); err == nil || !strings.Contains(err.Error(), "base chain") {
		t.Fatalf("switch to a successor outside the base chain: %v", err)
	}
	res, err := merge.Rebase(ctx, e.c, merge.RebaseOptions{Branch: "b2", New: "b2-b", Onto: "matches", Switch: true})
	if res == nil || !res.Created || res.FirstResult == nil {
		t.Fatalf("rebase onto the base's base: %+v, %v", res, err)
	}
	// The switch is the server's to accept (§7.4), and the core accepts a
	// successor up the chain since v0.73 (wave 2): the old branch is
	// frozen naming it.
	if err != nil || !res.Switched {
		t.Fatalf("switch: %+v, %v", res, err)
	}
	doc := nsDoc(t, e.c, "b2")
	if f, _ := doc["frozen"].(bool); !f || doc["successor"] != "b2-b" {
		t.Fatalf("old branch after the switch: %v", doc)
	}
}

// blobLog records a client's blob PUTs: "copy <status>" for a Blob-From
// copy, "upload <status>" for one with a body.
type blobLog struct {
	mu   sync.Mutex
	puts []string
}

func (l *blobLog) wrap(rt http.RoundTripper) http.RoundTripper {
	return rtFunc(func(r *http.Request) (*http.Response, error) {
		resp, err := rt.RoundTrip(r)
		if r.Method == "PUT" && strings.Contains(r.URL.Path, "/blob/") && err == nil {
			kind := "upload"
			if r.Header.Get("Blob-From") != "" {
				kind = "copy"
			}
			l.mu.Lock()
			l.puts = append(l.puts, fmt.Sprintf("%s %d", kind, resp.StatusCode))
			l.mu.Unlock()
		}
		return resp, err
	})
}

func (l *blobLog) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Join(l.puts, ", ")
}

type rtFunc func(*http.Request) (*http.Response, error)

func (f rtFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// §F.3 Blobs, §7.8, §2.1 (v0.66): a merger without unrestricted read on
// the branch (here a batch grant fixed to one resource, as a catalog's
// merge grant is) copies the blobs its items reference into the target
// first, since the batch's source makes none available to it; where the
// ranks refuse the copy (a private branch into a public base: 404) it
// uploads the bytes. A merger with unrestricted read copies nothing.
func TestV073MergeCopiesBlobs(t *testing.T) {
	t.Parallel()
	s := clienttest.New(t, clienttest.Options{Auth: true})
	k := clienttest.NewKey("ops")
	for ns, read := range map[string]string{"pics": "grant", "pub": "public"} {
		must(s.Client(t, client.WithBearer(s.OperatorGrant(t, ns))).CreateNamespace(ctx, ns, map[string]any{"read": read, "keys": []any{k.Entry("*")}}))
	}
	all := []string{"pics", "pics-r7", "pub", "pub-r7"}
	owner := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:ed", all, grant.Verbs)))
	png := []byte("\x89PNG not really")
	setup := func(base, br string, patches ...map[string]any) string {
		must(owner.CreateDoc(ctx, base, "derby", map[string]any{"title": "Derby"}))
		req := client.BranchRequest{Name: br}
		if len(patches) > 0 {
			req.Patches = ops(patches...)
		}
		must(owner.CreateBranch(ctx, base, req))
		bid := must(owner.UploadBlob(ctx, br, "derby", "image/png", "", png))
		h := must(owner.Head(ctx, br, "derby"))
		must(owner.Append(ctx, br, "derby", h.ID, ops(op("add", "/img", client.BlobRef(bid, "image/png", len(png), "")))))
		return bid
	}
	bid := setup("pics", "pics-r7")
	setup("pub", "pub-r7", op("add", "/read", "grant"))

	// The batch goes in under a grant fixed to derby: no unrestricted read
	// on the branch, so its source makes no blobs available.
	fixed := func(l *blobLog) *client.Client {
		return s.Client(t, client.WithTransport(l.wrap), client.WithBearer(k.Grant(t, s.Now(), "svc:merge", all, []string{"read", "create", "append", "restore"},
			map[string]any{"rules": []any{op("test", "/resource", "derby")}})))
	}
	for _, c := range []struct{ base, branch, want string }{
		{"pics", "pics-r7", "copy 201"},
		{"pub", "pub-r7", "copy 404, upload 201"},
	} {
		l := &blobLog{}
		p := must(merge.NewPlan(ctx, owner, c.base, c.branch, merge.Options{BatchClient: fixed(l)}))
		must(p.DryRun(ctx))
		res, err := p.Apply(ctx)
		if err != nil {
			t.Fatalf("%s: merge: %v (blob PUTs: %s)", c.branch, err, l)
		}
		if res.NSID == "" || l.String() != c.want {
			t.Fatalf("%s: blob PUTs %q, want %q (%+v)", c.branch, l, c.want, res)
		}
	}
	if b := must(owner.GetBlob(ctx, "pub", "derby", bid, "")); string(b.Data) != string(png) {
		t.Fatalf("pub/derby blob %q", b.Data)
	}

	// With unrestricted read the batch's source serves: nothing is copied.
	must(owner.CreateDoc(ctx, "pics-r7", "cup", map[string]any{"title": "Cup"}))
	cb := must(owner.UploadBlob(ctx, "pics-r7", "cup", "image/png", "", png))
	h := must(owner.Head(ctx, "pics-r7", "cup"))
	must(owner.Append(ctx, "pics-r7", "cup", h.ID, ops(op("add", "/img", client.BlobRef(cb, "image/png", len(png), "")))))
	l := &blobLog{}
	full := s.Client(t, client.WithTransport(l.wrap), client.WithBearer(k.Grant(t, s.Now(), "svc:merge", all, grant.Verbs)))
	must(must(merge.NewPlan(ctx, full, "pics", "pics-r7", merge.Options{})).Apply(ctx))
	if l.String() != "" {
		t.Fatalf("a merger with unrestricted read made blob PUTs: %s", l)
	}
	if b := must(owner.GetBlob(ctx, "pics", "cup", cb, "")); string(b.Data) != string(png) {
		t.Fatalf("pics/cup blob %q", b.Data)
	}
}

// §F.9 Merging (v0.63): before approval each listed branch's base must be
// the namespace it is keyed by; a branch of a branch of it no longer
// passes because its base chain reaches it.
func TestV073ReleaseBaseIsKeyedNamespace(t *testing.T) {
	t.Parallel()
	w := newRelWorld(t)
	w.branch("schemas", "schemas-r7")
	w.branch("schemas-r7", "schemas-r7-b")
	w.appendTo("schemas-r7-b", "match", op("add", "/properties/venue", map[string]any{"type": "string"}))
	w.writeRelease("release-x", map[string]string{"schemas": "schemas-r7-b"})
	rp := must(merge.PlanRelease(ctx, w.anna, w.opts("release-x")))
	if got := conflictKinds(rp)[merge.RCBaseChain]; len(got) != 1 || got[0] != "schemas/" {
		t.Fatalf("conflicts %+v", rp.Conflicts)
	}
	if !strings.Contains(rp.Conflicts[0].Message, "schemas-r7") {
		t.Fatalf("message %q", rp.Conflicts[0].Message)
	}
	// Its own base is fine.
	w.writeRelease("release-y", map[string]string{"schemas": "schemas-r7"})
	if rp := must(merge.PlanRelease(ctx, w.anna, w.opts("release-y"))); len(conflictKinds(rp)[merge.RCBaseChain]) != 0 {
		t.Fatalf("conflicts %+v", rp.Conflicts)
	}
}

// §F.9 (v0.63, v0.56, v0.65): the digest is over the plan shape the spec
// defines; approval keeps each branch's ns_id from before its freeze as
// every batch's source.at; the merge lock is { holder, plan } in the
// release document's own namespace (whatever StateNS says), taken, given
// its plan, and released to {}.
func TestV073ReleaseDigestAtAndLock(t *testing.T) {
	t.Parallel()
	w := newRelWorld(t)
	w.startCatalog()
	w.branch("cat-season", "cat-season-r8")
	w.appendTo("cat-season-r8", "season", op("replace", "/title", "Season 2026"))
	w.writeRelease("release-8", map[string]string{"cat-season": "cat-season-r8"})
	// The stored plan lives elsewhere; the lock doesn't.
	must(w.s.Client(t, client.WithBearer(w.s.OperatorGrant(t, "schemas-x"))).CreateNamespace(ctx, "schemas-x",
		map[string]any{"read": "grant", "keys": []any{w.opsKey.Entry("*"), w.idp.Entry(grant.Verbs...)}}))
	o := w.opts("release-8")
	o.StateNS = "schemas-x"

	rp := must(merge.PlanRelease(ctx, w.anna, o))
	if !rp.Clean() || rp.Format != merge.PlanFormat {
		t.Fatalf("plan %+v", rp)
	}
	before := must(w.anna.NSHead(ctx, "cat-season-r8")).ID
	rel := must(release.Load(ctx, w.anna, "/r/releases/release-8"))
	want := map[string]any{
		"release": "/r/releases/release-8/rev/" + rel.Ref.Rev,
		"batches": []any{map[string]any{
			"ns":     "cat-season",
			"source": map[string]any{"ns": "cat-season-r8", "at": before},
			"items": []any{map[string]any{"resource": "season", "ifMatch": must(w.anna.Head(ctx, "cat-season", "season")).ID,
				"steps": []any{[]any{map[string]any{"op": "replace", "path": "/title", "value": "Season 2026"}}}}},
		}},
	}
	if got := merge.PlanDigest(want); rp.Digest != got {
		t.Fatalf("digest %s, want %s over %s", rp.Digest, got, jsonv.Canonical(jsonv.FromGo(want)))
	}
	noErr(t, merge.SaveReleasePlan(ctx, w.anna, o, rp))
	if h := must(w.anna.Head(ctx, "schemas-x", merge.PlanName("release-8"))); h.State != client.Live {
		t.Fatal("the plan isn't stored in StateNS")
	}
	rp = must(merge.ApproveRelease(ctx, w.anna, o))
	if b := rp.Branches[0]; b.At != before || must(w.anna.NSHead(ctx, "cat-season-r8")).ID == before {
		t.Fatalf("branch at %s, want the ns_id before the freeze %s", b.At, before)
	}
	// Planning again after the approval still classifies from before the
	// freeze, so the digest holds.
	o2 := o
	o2.AcceptFrozen = rp.FrozenBy()
	if again := must(merge.PlanRelease(ctx, w.anna, o2)); again.Digest != rp.Digest {
		t.Fatalf("planned again after the freeze: %s, approved %s", again.Digest, rp.Digest)
	}

	rp = must(merge.ApplyRelease(ctx, w.anna, o))
	if rp.State != merge.ReleaseDone {
		t.Fatalf("state %s", rp.State)
	}
	for _, st := range rp.Steps {
		if st.Done == "noop" {
			continue
		}
		if e := entryOf(t, w.anna, "cat-season", st.Done); e.Source["at"] != before {
			t.Fatalf("step %d source %v, want at %s", st.Step, e.Source, before)
		}
	}
	// The lock: taken, given its plan, released; in releases, not in
	// StateNS.
	lock := merge.LockName("cat-season")
	if h := must(w.anna.Head(ctx, "schemas-x", lock)); h.State != client.NotFound {
		t.Fatalf("a lock in StateNS: %+v", h)
	}
	h := must(w.anna.Head(ctx, "releases", lock))
	var docs []string
	for _, e := range must(w.anna.Log(ctx, "releases", lock, h.ID, "")) {
		docs = append(docs, string(jsonv.Canonical(must(w.anna.Doc(ctx, "releases", lock, e.ID)).Value)))
	}
	wantDocs := []string{`{"holder":"user:anna"}`, `{"holder":"user:anna","plan":"` + rp.Digest + `"}`, `{}`}
	if !reflect.DeepEqual(docs, wantDocs) {
		t.Fatalf("lock documents %q, want %q", docs, wantDocs)
	}
}

// §F.9 The merge lock: a resuming service takes over only a lock whose
// plan is its stored plan's digest; a lock held without a plan, for
// another plan, or by an earlier version ({ "release" }) is ErrLocked,
// naming holder and plan; an earlier version's free lock is free.
func TestV073ReleaseLockTakeover(t *testing.T) {
	t.Parallel()
	w := newRelWorld(t)
	w.startCatalog()
	w.branch("cat-season", "cat-season-r8")
	w.appendTo("cat-season-r8", "season", op("replace", "/title", "Season 2026"))
	w.writeRelease("release-8", map[string]string{"cat-season": "cat-season-r8"})
	o := w.opts("release-8")
	noErr(t, merge.SaveReleasePlan(ctx, w.anna, o, must(merge.PlanRelease(ctx, w.anna, o))))
	rp := must(merge.ApproveRelease(ctx, w.anna, o))
	lock := merge.LockName("cat-season")
	setLock := func(doc map[string]any) {
		t.Helper()
		if h := must(w.anna.Head(ctx, "releases", lock)); h.State == client.Live {
			must(w.anna.Append(ctx, "releases", lock, h.ID, ops(op("replace", "", doc))))
		} else {
			must(w.anna.CreateDoc(ctx, "releases", lock, doc))
		}
	}
	for _, c := range []struct {
		doc  map[string]any
		want string
	}{
		{map[string]any{"holder": "svc:other"}, "svc:other holds releases/" + lock + " for plan (none)"},
		{map[string]any{"holder": "svc:other", "plan": "1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}, "for plan 1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		{map[string]any{"release": "/r/releases/release-6", "since": "2026-01-01T00:00:00Z"}, "an earlier version's merge of /r/releases/release-6"},
	} {
		setLock(c.doc)
		_, err := merge.ApplyRelease(ctx, w.anna, o)
		if !errors.Is(err, merge.ErrLocked) || !strings.Contains(err.Error(), c.want) {
			t.Fatalf("lock %v: %v", c.doc, err)
		}
	}
	// Another service crashed holding this plan's lock: taken over.
	setLock(map[string]any{"holder": "svc:other", "plan": rp.Digest})
	o.AfterStep = func(*merge.ReleaseStep) error { return errors.New("stop") }
	if _, err := merge.ApplyRelease(ctx, w.anna, o); err == nil || errors.Is(err, merge.ErrLocked) {
		t.Fatalf("takeover: %v", err)
	}
	if l := must(merge.ReadLock(ctx, w.anna, o, "cat-season")); l.Holder != "user:anna" || l.Plan != rp.Digest {
		t.Fatalf("lock after takeover %+v", l)
	}
	// An earlier version's free lock is free: release it as one would have.
	setLock(map[string]any{"release": nil})
	if l := must(merge.ReadLock(ctx, w.anna, o, "cat-season")); !l.Free() {
		t.Fatalf("legacy free lock %+v", l)
	}
	o.AfterStep = nil
	if rp, err := merge.ApplyRelease(ctx, w.anna, o); err != nil || rp.State != merge.ReleaseDone {
		t.Fatalf("apply over a free legacy lock: %v", err)
	}
}

// §F.9: the stored-plan format changed with the digest, so a plan stored
// or approved before needs planning and approving again.
func TestV073ReleaseOldPlanFormat(t *testing.T) {
	t.Parallel()
	w := newRelWorld(t)
	w.branch("schemas", "schemas-r7")
	w.appendTo("schemas-r7", "match", op("add", "/properties/venue", map[string]any{"type": "string"}))
	w.writeRelease("release-x", map[string]string{"schemas": "schemas-r7"})
	o := w.opts("release-x")
	rp := must(merge.PlanRelease(ctx, w.anna, o))
	rp.Format = 0
	noErr(t, merge.SaveReleasePlan(ctx, w.anna, o, rp))
	if _, err := merge.ApproveRelease(ctx, w.anna, o); !errors.Is(err, merge.ErrDigest) || !strings.Contains(err.Error(), "format") {
		t.Fatalf("approving an old-format plan: %v", err)
	}
	stored := must(merge.LoadReleasePlan(ctx, w.anna, o))
	stored.State = merge.ReleaseApproved
	noErr(t, merge.SaveReleasePlan(ctx, w.anna, o, stored))
	if _, err := merge.ApplyRelease(ctx, w.anna, o); !errors.Is(err, merge.ErrInvalidPlan) {
		t.Fatalf("applying an old-format approval: %v", err)
	}
	if h := must(w.anna.Head(ctx, "schemas", "match")); h.ID != w.T0 {
		t.Fatal("something was merged")
	}
}

// §F.9 "a merge that stops part-way resumes from that plan and never
// reverts", across the upgrade: a merge an earlier version started and
// stopped after step 1 left its plan in state merging without a format,
// branch ats or digests of today's rendering, and its { "release" } lock
// held (in StateNS, where that version kept its locks). It can't be
// approved again, so ApplyRelease resumes it: the step digests checked as
// that version rendered them (here step 3's differ, matches requiring
// nonces), every batch's source.at the branch's ns_id before the freeze,
// the lock taken over only if it names this release, and released.
func TestV073ReleaseResumesOldFormatMerge(t *testing.T) {
	t.Parallel()
	for _, stateNS := range []string{"", "schemas-x"} {
		t.Run("state-ns="+stateNS, func(t *testing.T) {
			t.Parallel()
			testReleaseResumesOldFormatMerge(t, stateNS)
		})
	}
}

func testReleaseResumesOldFormatMerge(t *testing.T, stateNS string) {
	w := newRelWorld(t)
	w.startCatalog()
	h := must(w.ops.NSHead(ctx, "matches"))
	must(w.ops.PatchConfig(ctx, "matches", h.Config, ops(op("add", "/nonce", "required"))))
	w.branch("schemas", "schemas-r7", op("add", "/drafts", map[string]any{"for": sAny("matches-r7")}))
	w.branch("matches", "matches-r7")
	w.branch("cat-season", "cat-season-r7")
	w.appendTo("schemas-r7", "match", op("add", "/properties/venue", map[string]any{"type": "string"}))
	w.appendTo("matches-r7", "derby", op("replace", "/home", "Z"), op("add", "/$nonce", seal.NewNonce()))
	w.appendTo("cat-season-r7", "season", op("replace", "/title", "Season 2026"))
	w.writeRelease("release-7", map[string]string{"schemas": "schemas-r7", "matches": "matches-r7", "cat-season": "cat-season-r7"})
	o := w.opts("release-7")
	lockNS := "releases"
	if stateNS != "" {
		must(w.s.Client(t, client.WithBearer(w.s.OperatorGrant(t, stateNS))).CreateNamespace(ctx, stateNS,
			map[string]any{"read": "grant", "keys": []any{w.opsKey.Entry("*"), w.idp.Entry(grant.Verbs...)}}))
		o.StateNS, lockNS = stateNS, stateNS
	}
	noErr(t, merge.SaveReleasePlan(ctx, w.anna, o, must(merge.PlanRelease(ctx, w.anna, o))))
	rp := must(merge.ApproveRelease(ctx, w.anna, o))
	if got := stepsOf(rp); !reflect.DeepEqual(got, []string{"1 schemas match", "3 matches derby", "4 cat-season season"}) {
		t.Fatalf("steps %q", got)
	}
	ats := map[string]string{}
	for _, b := range rp.Branches {
		ats[b.Key] = b.At
	}
	stop := errors.New("stop")
	o.AfterStep = func(st *merge.ReleaseStep) error {
		if st.Step == 1 {
			return stop
		}
		return nil
	}
	if _, err := merge.ApplyRelease(ctx, w.anna, o); !errors.Is(err, stop) {
		t.Fatalf("apply: %v", err)
	}
	o.AfterStep = nil

	// As the earlier version left it.
	stored := must(merge.LoadReleasePlan(ctx, w.anna, o))
	step3 := stored.Steps[1].Digest
	noErr(t, merge.LegacyPlan(ctx, w.anna, o, stored))
	if stored.Steps[1].Digest == step3 {
		t.Fatal("step 3's digest renders the same in both formats; the test shows nothing")
	}
	noErr(t, merge.SaveReleasePlan(ctx, w.anna, o, stored))
	lock := merge.LockName("cat-season")
	setLock := func(ns string, doc map[string]any) {
		t.Helper()
		if h := must(w.anna.Head(ctx, ns, lock)); h.State == client.Live {
			must(w.anna.Append(ctx, ns, lock, h.ID, ops(op("replace", "", doc))))
		} else {
			must(w.anna.CreateDoc(ctx, ns, lock, doc))
		}
	}
	if lockNS != "releases" {
		setLock("releases", map[string]any{})
	}
	if _, err := merge.ApproveRelease(ctx, w.anna, o); err == nil {
		t.Fatal("approved a merging plan again")
	}
	// Another release's earlier-version lock isn't this one's.
	setLock(lockNS, map[string]any{"release": "/r/releases/release-6", "since": "2026-01-01T00:00:00Z"})
	if _, err := merge.ApplyRelease(ctx, w.anna, o); !errors.Is(err, merge.ErrLocked) {
		t.Fatalf("resumed over another release's lock: %v", err)
	}
	setLock(lockNS, map[string]any{"release": "/r/releases/release-7", "since": "2026-01-01T00:00:00Z"})

	rp, err := merge.ApplyRelease(ctx, w.anna, o)
	if err != nil {
		t.Fatalf("resuming a merge an earlier version stopped part-way: %v", err)
	}
	if rp.State != merge.ReleaseDone {
		t.Fatalf("state %s", rp.State)
	}
	if d := w.doc("matches", "derby"); d["home"] != "Z" {
		t.Fatalf("derby %v", d)
	}
	if d := w.doc("cat-season", "season"); d["title"] != "Season 2026" {
		t.Fatalf("season %v", d)
	}
	for _, st := range rp.Steps[1:] {
		ns := rp.Branch(st.Key).Target
		if e := entryOf(t, w.anna, ns, st.Done); e.Source["at"] != ats[st.Key] {
			t.Fatalf("step %d source %v, want at %s, the ns_id before the freeze", st.Step, e.Source, ats[st.Key])
		}
	}
	// Both locks are free; the one in releases was taken over and given
	// the plan when it was the earlier version's.
	for _, ns := range []string{"releases", lockNS} {
		if !w.live(ns, lock) || len(w.doc(ns, lock)) != 0 {
			t.Fatalf("lock %s/%s: %v", ns, lock, w.doc(ns, lock))
		}
	}
	lh := must(w.anna.Head(ctx, "releases", lock))
	var docs []string
	for _, e := range must(w.anna.Log(ctx, "releases", lock, lh.ID, "")) {
		docs = append(docs, string(jsonv.Canonical(must(w.anna.Doc(ctx, "releases", lock, e.ID)).Value)))
	}
	if held := `{"holder":"user:anna","plan":"` + rp.Digest + `"}`; !strings.Contains(strings.Join(docs, " "), held) || docs[len(docs)-1] != `{}` {
		t.Fatalf("lock documents %q", docs)
	}
}

// §F.9 split nodes: each half of a person's split must change the node.
// A first half that is the catalog base's document as it is (the change
// only widens) left step 2 without an item, so the plan's digest had no
// { batch, item } for the second half's precondition and planning failed
// outright; a second half that is the first (the change only narrows)
// gave the digest a step-4 item that the merge then never submitted, so
// step 4 stopped as changed from the approved plan after step 2 went in.
// Both are now a bad split, and the change plans whole once it is dropped.
func TestV073ReleaseSplitHalvesChangeTheNode(t *testing.T) {
	t.Parallel()
	w := newRelWorld(t)
	w.startCatalog()
	w.branch("cat-season", "cat-season-r8")
	w.appendTo("cat-season-r8", "season", op("add", "/$access/inherit", false))              // narrows only
	w.appendTo("cat-season-r8", "embargo", op("add", "/$access/group:fans", sAny("reader"))) // widens only
	w.writeRelease("release-8", map[string]string{"cat-season": "cat-season-r8"})
	o := w.opts("release-8")
	for _, c := range []struct {
		node string
		half any
		want string
	}{
		{"embargo", w.doc("cat-season", "embargo"), "first half is the catalog base's document"},
		{"season", w.doc("cat-season-r8", "season"), "second half is its first"},
	} {
		o.Splits = map[string]map[string]any{"cat-season": {c.node: c.half}}
		rp, err := merge.PlanRelease(ctx, w.anna, o)
		if err != nil {
			t.Fatalf("split of %s: %v", c.node, err)
		}
		if got := conflictKinds(rp)[merge.RCBadSplit]; len(got) != 1 || got[0] != "cat-season/"+c.node || !strings.Contains(rp.Conflicts[0].Message, c.want) {
			t.Fatalf("split of %s: conflicts %+v", c.node, rp.Conflicts)
		}
	}
	o.Splits = nil
	rp := must(merge.PlanRelease(ctx, w.anna, o))
	if got := stepsOf(rp); !rp.Clean() || !reflect.DeepEqual(got, []string{"2 cat-season season", "4 cat-season embargo"}) {
		t.Fatalf("plan %q, conflicts %+v", got, rp.Conflicts)
	}
	noErr(t, merge.SaveReleasePlan(ctx, w.anna, o, rp))
	must(merge.ApproveRelease(ctx, w.anna, o))
	if rp := must(merge.ApplyRelease(ctx, w.anna, o)); rp.State != merge.ReleaseDone {
		t.Fatalf("state %s", rp.State)
	}
}
