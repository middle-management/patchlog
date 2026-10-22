package janitor_test

import (
	"crypto/ed25519"
	"errors"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/core"
	"github.com/middle-management/patchlog/internal/grant"
	"github.com/middle-management/patchlog/internal/janitor"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/keystore"
	"github.com/middle-management/patchlog/internal/merge"
	"github.com/middle-management/patchlog/internal/pgtest"
	"github.com/middle-management/patchlog/internal/seal"
	"github.com/middle-management/patchlog/internal/server"
	"github.com/middle-management/patchlog/internal/testenv"
)

// patchConfig writes a config change to ns as c.
func patchConfig(t *testing.T, c *client.Client, ns string, patches ...map[string]any) {
	t.Helper()
	ps := make([]any, len(patches))
	for i, p := range patches {
		ps[i] = p
	}
	must(c.PatchConfig(ctx, ns, must(c.NSHead(ctx, ns)).Config, ps))
}

// authEnv is a deployment with authentication on: a base "matches" whose
// * keys are ops and tmp, with editor's key allowing everything else, and
// a document derby.
type authEnv struct {
	t                  *testing.T
	s                  *clienttest.Server
	ops, tmp, editor   clienttest.Key
	admin, ed, janitor *client.Client
	nss                []string
}

var allVerbs = []string{"read", "create", "append", "config", "branch", "purge-ns"}

func newAuthEnv(t *testing.T, nss []string, base map[string]any) *authEnv {
	s := clienttest.New(t, clienttest.Options{Auth: true})
	a := &authEnv{t: t, s: s, ops: clienttest.NewKey("ops"), tmp: clienttest.NewKey("tmp"), editor: clienttest.NewKey("editor"),
		nss: append([]string{"matches"}, nss...)}
	a.admin, a.ed, a.janitor = a.as(a.ops, "user:ops"), a.as(a.editor, "user:ed"), a.as(a.ops, "svc:janitor")
	doc := map[string]any{"read": "grant", "keys": []any{a.ops.Entry("*"), a.tmp.Entry("*"), a.editor.Entry(allVerbs...)}}
	for k, v := range base {
		doc[k] = v
	}
	must(s.Client(t, client.WithBearer(s.OperatorGrant(t, "matches"))).CreateNamespace(ctx, "matches", doc))
	must(a.admin.CreateDoc(ctx, "matches", "derby", map[string]any{"score": "0-0"}))
	return a
}

// as is a client with a grant of k for sub on every namespace of the
// environment, valid for 30 days.
func (a *authEnv) as(k clienttest.Key, sub string) *client.Client {
	return must(client.New(a.s.URL, client.WithBearer(k.Grant(a.t, a.s.Now(), sub, a.nss, allVerbs,
		map[string]any{"exp": a.s.Now().Add(30 * day).Format(time.RFC3339)}))))
}

// branch creates a branch of base with an edit of derby of its own and
// cleanup, as the editor.
func (a *authEnv) branch(t *testing.T, base, name string, cleanup map[string]any) {
	t.Helper()
	must(a.ed.CreateBranch(ctx, base, client.BranchRequest{Name: name, Patches: []any{op("add", "/cleanup", cleanup)}}))
	h := must(a.ed.Head(ctx, name, "derby"))
	must(a.ed.Append(ctx, name, "derby", h.ID, []any{op("replace", "/score", "1-0")}))
}

func (a *authEnv) check(t *testing.T, base, ns string, after time.Duration) janitor.Decision {
	t.Helper()
	later := func() time.Time { return a.s.Now().Add(after) }
	return must(janitor.New(a.janitor, janitor.Options{Now: later}).Check(ctx, base, ns))
}

// §F.6 (v0.63): a branch is purged as a state only by a member of its own
// cleanup for that state; the base's cleanup sets minimums only, and cleanup
// isn't copied into branches (§7.6). Here the base declares its period
// after the branch was created, so the branch has none of its own whatever
// the branch's genesis copies.
func TestV073BaseCleanupAloneNeverPurges(t *testing.T) {
	t.Parallel()
	e := newEnv(t, nil)
	e.branch("matches", "r7", nil)
	e.edit("r7", "derby", "1-0")
	e.config("matches", op("add", "/cleanup", map[string]any{"merged": "P1D"}))
	must(merge.Freeze(ctx, e.c, "r7", e.merge("r7")))
	e.s.Clock.Advance(30 * day)
	d := e.sweep(false)["r7"]
	wantKeep(t, d, "merged, but no cleanup period for merged in the branch")
	if d.Claim != "merged" {
		t.Fatalf("decision %+v: the claim is verified", d)
	}
	if e.purged("r7") {
		t.Fatal("purged on the base's cleanup alone")
	}
}

// §F.6: without a member for one verified state the branch isn't purged as
// that state, but may be as another. A branch with no document entries of
// its own counts as merged; with cleanup only for abandoned, it is purged
// as abandoned (the flag set in development mode, which counts while the
// deployment runs with authentication disabled, §1).
func TestV073PurgedAsTheStateWithAPeriod(t *testing.T) {
	t.Parallel()
	e := newEnv(t, nil)
	e.branch("matches", "empty", map[string]any{"abandoned": "PT1H"})
	e.config("empty", op("add", "/frozen", true), op("add", "/abandoned", true))
	e.s.Clock.Advance(2 * time.Hour)
	if d := e.sweep(false)["empty"]; d.Action != janitor.ActionPurged || d.Claim != "abandoned" {
		t.Fatalf("decision %+v, want purged as abandoned", d)
	}
}

// §F.6 (v0.63): the cleanup period counts from the last config write that
// froze the branch or set merged, successor or abandoned, not from the
// first freezing write; other config writes, such as one changing
// cleanup, don't restart it.
func TestV073PeriodFromLastClaimWrite(t *testing.T) {
	t.Parallel()
	e := newEnv(t, nil)
	e.branch("matches", "r7", map[string]any{"merged": "P10D"})
	e.branch("matches", "r8", map[string]any{"merged": "P10D"})
	e.edit("r7", "derby", "1-0")
	must(merge.Freeze(ctx, e.c, "r7", e.merge("r7")))
	must(e.c.CreateDoc(ctx, "r8", "cup", map[string]any{"score": "2-0"}))
	must(merge.Freeze(ctx, e.c, "r8", e.merge("r8")))
	t0 := e.s.Clock.Now()

	e.s.Clock.Advance(5 * day)
	t5 := e.s.Clock.Now()
	e.config("r7", op("add", "/abandoned", true))                                                    // sets a claim: restarts
	e.config("r8", op("replace", "/cleanup", map[string]any{"merged": "P10D", "superseded": "P1D"})) // doesn't

	e.s.Clock.Advance(6 * day) // t0+11d
	ds := e.sweep(false)
	wantKeep(t, ds["r7"], "merged; cleanup period runs until "+t5.Add(10*day).UTC().Format(time.RFC3339))
	if !ds["r7"].FrozenAt.Equal(t5) || !ds["r7"].EligibleAt.Equal(t5.Add(10*day)) {
		t.Fatalf("r7 %+v, want the period from %v", ds["r7"], t5)
	}
	if ds["r8"].Action != janitor.ActionPurged || !ds["r8"].FrozenAt.Equal(t0) {
		t.Fatalf("r8 %+v, want purged, its period from %v", ds["r8"], t0)
	}

	e.s.Clock.Advance(5 * day) // t5+11d
	if d := e.sweep(false)["r7"]; d.Action != janitor.ActionPurged || d.Claim != "merged" {
		t.Fatalf("r7 %+v", d)
	}
}

// §F.6 (v0.63): abandoned counts only if the write that set it was under a
// grant chaining to a current * key of the branch, its own or a local
// base's (§C.4): a * key removed since, from the branch or from the base,
// no longer counts, also where the branch still lists its copy of a base
// key, which never falls back once the base drops it.
func TestV073AbandonedNeedsCurrentStarKey(t *testing.T) {
	t.Parallel()
	a := newAuthEnv(t, []string{"r1", "r2", "r3", "r4"}, nil)
	for _, b := range []string{"r1", "r2", "r3", "r4"} {
		a.branch(t, "matches", b, map[string]any{"abandoned": "P1D"})
	}
	abandon := func(c *client.Client, ns string) {
		t.Helper()
		patchConfig(t, c, ns, op("add", "/frozen", true), op("add", "/abandoned", true))
	}
	// r1: a * key of the branch's own, added with a base * key, sets
	// abandoned, and is removed again.
	own := clienttest.NewKey("own")
	patchConfig(t, a.admin, "r1", op("add", "/keys/-", own.Entry("*")))
	a.nss = append(a.nss, "r1")
	abandon(a.as(own, "user:own"), "r1")
	keys := must(a.admin.NSDoc(ctx, "r1", must(a.admin.NSHead(ctx, "r1")).ID)).Value["keys"].([]any)
	patchConfig(t, a.admin, "r1", op("remove", "/keys/"+strconv.Itoa(len(keys)-1), nil))
	// r2: the base's * key tmp sets abandoned; then the base drops tmp.
	abandon(a.as(a.tmp, "user:tmp"), "r2")
	patchConfig(t, a.admin, "matches", op("remove", "/keys/1", nil))
	// r3: the base's * key ops, still in force.
	abandon(a.admin, "r3")
	// r4: ops too, but under a grant the base has revoked since.
	abandon(a.as(a.ops, "user:revoked"), "r4")
	log := must(a.admin.NSLog(ctx, "r4", must(a.admin.NSHead(ctx, "r4")).ID, ""))
	patchConfig(t, a.admin, "matches", op("add", "/revoked", []any{log[len(log)-1].Grant.ID}))

	for _, ns := range []string{"r1", "r2"} {
		d := a.check(t, "matches", ns, 2*day)
		wantKeep(t, d, "isn't one the branch accepts now")
		if d.Claim != "" {
			t.Fatalf("%s: %+v", ns, d)
		}
	}
	wantKeep(t, a.check(t, "matches", "r4", 2*day), "is revoked in the branch")
	if d := a.check(t, "matches", "r3", 2*day); d.Action != janitor.ActionPurged || d.Claim != "abandoned" {
		t.Fatalf("r3: %+v", d)
	}
}

// remoteDeployment is a second deployment, with authentication on and its
// own origin, that reaches the clienttest servers' origin at aURL for
// remote branches (§G.3).
type remoteDeployment struct {
	url string
	op  ed25519.PrivateKey
}

type nopPurger struct{}

func (nopPurger) PurgeTags([]string) {}

func newRemoteDeployment(t *testing.T, aURL string) *remoteDeployment {
	t.Helper()
	pub, priv := grant.GenerateKey()
	ks, err := grant.ParseKeys(jsonv.FromGo([]any{map[string]any{"kid": "operator", "alg": "ed25519", "pub": pub, "can": []any{"*"}}}))
	if err != nil {
		t.Fatal(err)
	}
	o := core.Options{Path: pgtest.DB(t), BlobDir: t.TempDir(), Origin: "https://b.example", OperatorKeys: ks,
		Purger: nopPurger{}, RetentionInterval: -1, LongPollInterval: 300 * time.Millisecond,
		Remote: core.RemoteOptions{FollowInterval: -1, Resolve: func(origin string) (core.RemoteEndpoint, error) {
			if origin != clienttest.Origin {
				return core.RemoteEndpoint{}, errors.New("unknown origin " + origin)
			}
			return core.RemoteEndpoint{BaseURL: aURL}, nil
		}}}
	testenv.Apply(&o)
	e, err := core.Open(o)
	if err != nil {
		t.Fatal(err)
	}
	hs := httptest.NewServer(server.New(e))
	t.Cleanup(func() {
		hs.CloseClientConnections()
		hs.Close()
		e.Close()
	})
	return &remoteDeployment{url: hs.URL, op: priv}
}

// operator is a client with an operator grant to create ns (§C.4).
func (d *remoteDeployment) operator(t *testing.T, ns string) *client.Client {
	return must(client.New(d.url, client.WithBearer(clienttest.Mint(t, d.op, map[string]any{"kid": "operator", "sub": "op:root",
		"ns": []any{ns}, "can": []any{"config"}, "exp": time.Now().Add(time.Hour).Format(time.RFC3339)}))))
}

// §F.6, §C.4 (v0.71, v0.72): inherited * keys come only from local bases.
// A local branch of a remote branch inherits the remote branch's keys, but
// not those of the remote branch's base, which lives in another
// deployment, nor those of a namespace here that shares its name.
func TestV073InheritedKeysOnlyFromLocalBases(t *testing.T) {
	t.Parallel()
	a := clienttest.New(t, clienttest.Options{})
	ac := a.Client(t, client.WithAuthor("alice"))
	must(ac.CreateNamespace(ctx, "matches", map[string]any{"read": "public"}))
	must(ac.CreateDoc(ctx, "matches", "derby", map[string]any{"score": "0-0"}))
	at := must(ac.NSHead(ctx, "matches")).ID

	b := newRemoteDeployment(t, a.URL)
	ops := clienttest.NewKey("ops")
	must(b.operator(t, "rel").CreateNamespace(ctx, "rel", map[string]any{"read": "grant",
		"keys": []any{ops.Entry("read", "create", "config", "branch", "purge-ns")},
		"base": map[string]any{"origin": clienttest.Origin, "ns": "matches", "at": at}}))
	// B's own matches, where ops is a * key.
	must(b.operator(t, "matches").CreateNamespace(ctx, "matches", map[string]any{"read": "grant", "keys": []any{ops.Entry("*")}}))
	ed := must(client.New(b.url, client.WithBearer(ops.Grant(t, time.Now(), "user:ed", []string{"rel", "loc", "matches"},
		[]string{"read", "create", "config", "branch", "purge-ns"}))))
	must(ed.CreateBranch(ctx, "rel", client.BranchRequest{Name: "loc", Patches: []any{op("add", "/cleanup", map[string]any{"abandoned": "P1D"})}}))
	must(ed.CreateDoc(ctx, "loc", "x", map[string]any{"n": 1}))
	patchConfig(t, ed, "loc", op("add", "/frozen", true), op("add", "/abandoned", true))

	later := func() time.Time { return time.Now().Add(2 * day) }
	d := must(janitor.New(ed, janitor.Options{Now: later}).Check(ctx, "rel", "loc"))
	wantKeep(t, d, `key "ops" isn't a * key of the branch`)
}

// §F.6 superseded, §F.5 Resuming (v0.63; CONFORMANCE Grant-scope scenario
// 37): a successor's batch counts only if its grant has a root sub and kid
// in the base's current merge.authors, or chains to a current * key of the
// old branch. The rebase tool counts any such batch; the janitor doesn't.
func TestV073SupersededNeedsTrustedBatch(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name  string
		key   func(a *authEnv) clienttest.Key
		sub   string
		purge bool
	}{
		{"an author without a * key", func(a *authEnv) clienttest.Key { return a.editor }, "user:ed", false},
		{"merge.authors", func(a *authEnv) clienttest.Key { return a.editor }, "svc:merge", true},
		{"a * key of the branch", func(a *authEnv) clienttest.Key { return a.tmp }, "user:tmp", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			a := newAuthEnv(t, []string{"r7", "r7-b"},
				map[string]any{"merge": map[string]any{"authors": []any{map[string]any{"sub": "svc:merge", "kid": "editor"}}}})
			a.branch(t, "matches", "r7", map[string]any{"superseded": "P1D"})
			must(merge.Rebase(ctx, a.as(tc.key(a), tc.sub), merge.RebaseOptions{Branch: "r7", New: "r7-b", Switch: true}))
			d := a.check(t, "matches", "r7", 2*day)
			if !tc.purge {
				wantKeep(t, d, "superseded claim not verified: no batch of the branch is by a principal in the base's merge.authors or under a current * key of the branch")
				return
			}
			if d.Action != janitor.ActionPurged || d.Claim != "superseded" {
				t.Fatalf("decision %+v", d)
			}
		})
	}
}

// §F.6 superseded (v0.65): a successor purged after the branch was frozen
// still verifies, from its log, which the purge leaves readable (§8.5). One
// purged before the freeze doesn't.
func TestV073SupersededBySuccessorPurgedLater(t *testing.T) {
	t.Parallel()
	e := newEnv(t, nil)
	e.branch("matches", "r7", map[string]any{"superseded": "P1D"})
	e.edit("r7", "derby", "1-0")
	e.branch("matches", "r8", map[string]any{"superseded": "P1D"})
	must(e.c.CreateDoc(ctx, "r8", "cup", map[string]any{"score": "2-0"}))
	purge := func(ns string) {
		t.Helper()
		e.config(ns, op("add", "/frozen", true))
		must(e.c.PurgeNamespace(ctx, ns, must(e.c.NSHead(ctx, ns)).ID))
	}

	// r7: switched to r7-b, which is purged a minute later.
	must(merge.Rebase(ctx, e.c, merge.RebaseOptions{Branch: "r7", New: "r7-b", Switch: true}))
	e.s.Clock.Advance(time.Minute)
	purge("r7-b")
	// r8: replayed into r8-b and named its successor, which is purged a
	// minute before r8 is frozen.
	must(merge.Rebase(ctx, e.c, merge.RebaseOptions{Branch: "r8", New: "r8-b"}))
	e.config("r8", op("add", "/successor", "r8-b"))
	purge("r8-b")
	e.s.Clock.Advance(time.Minute)
	e.config("r8", op("add", "/frozen", true))

	e.s.Clock.Advance(2 * day)
	ds := e.sweep(false)
	if d := ds["r7"]; d.Action != janitor.ActionPurged || d.Claim != "superseded" {
		t.Fatalf("r7 %+v", d)
	}
	wantKeep(t, ds["r8"], "superseded claim not verified: successor r8-b was purged at ")
	wantKeep(t, ds["r8"], "before the branch was frozen")
}

// §F.6 superseded, §8.5: a sealed successor's purge makes its log 410, so
// the branch can't be verified as superseded and is left for a manual purge.
func TestV073SealedSuccessorPurgedVerifiedByHand(t *testing.T) {
	t.Parallel()
	ks := must(keystore.New(keystore.Generate()))
	s := clienttest.New(t, clienttest.Options{KeyStore: ks})
	c := s.Client(t, client.WithAuthor("alice"), client.WithKeys(client.NewKeys(nil)))
	e := &env{t: t, s: s, c: c}
	must(c.CreateNamespace(ctx, "matches", map[string]any{"read": "public", "merge": devAuthors, "encryption": map[string]any{"level": "sealed"}}))
	must(c.Create(ctx, "matches", "derby", append(client.GenesisPatches(map[string]any{"score": "0-0"}), op("add", "/$nonce", seal.NewNonce()))))
	e.branch("matches", "r7", map[string]any{"superseded": "P1D"})
	h := must(c.Head(ctx, "r7", "derby"))
	must(c.Append(ctx, "r7", "derby", h.ID, []any{op("replace", "/score", "1-0"), op("replace", "/$nonce", seal.NewNonce())}))
	must(merge.Rebase(ctx, c, merge.RebaseOptions{Branch: "r7", New: "r7-b", Switch: true}))
	s.Clock.Advance(time.Minute)
	e.config("r7-b", op("add", "/frozen", true))
	must(c.PurgeNamespace(ctx, "r7-b", must(c.NSHead(ctx, "r7-b")).ID))
	s.Clock.Advance(2 * day)
	wantKeep(t, e.sweep(false)["r7"], "sealed successor purged: verify by hand")
}

// §F.6 closing rule (v0.67), a security fix: in the merged and superseded
// checks, every resource the branch changed up to the counting batch's
// source.at must have an entry in a counting batch from then on, or a head
// in the batch's namespace that equals or descends from the branch's
// revision. A partial merge or replay doesn't get the rest purged.
func TestV073EveryChangeMerged(t *testing.T) {
	t.Parallel()
	e := newEnv(t, nil)
	mergeOnly := func(c *client.Client, branch string, resources ...string) string {
		t.Helper()
		p := must(merge.NewPlan(ctx, c, "matches", branch, merge.Options{Resources: resources}))
		return must(p.Apply(ctx)).NSID
	}
	doc := func(ns, name string) {
		t.Helper()
		must(e.c.CreateDoc(ctx, ns, name, map[string]any{"n": 1}))
	}
	// r7 changes derby and cup; its merge leaves cup out.
	e.branch("matches", "r7", map[string]any{"merged": "P1D"})
	e.edit("r7", "derby", "1-0")
	doc("r7", "cup")
	must(merge.Freeze(ctx, e.c, "r7", mergeOnly(e.c, "r7", "derby")))
	// r8's first merge takes bowl; r8 changes bowl again, and a later
	// merge takes only plate.
	e.branch("matches", "r8", map[string]any{"merged": "P1D"})
	doc("r8", "bowl")
	mergeOnly(e.c, "r8", "bowl")
	must(e.c.Append(ctx, "r8", "bowl", must(e.c.Head(ctx, "r8", "bowl")).ID, []any{op("replace", "/n", 2)}))
	doc("r8", "plate")
	must(merge.Freeze(ctx, e.c, "r8", mergeOnly(e.c, "r8", "plate")))
	// r9: mug reached the base by a fast-forward from bob, who isn't in
	// merge.authors, and the base changed it since; the merge batch that
	// counts has only jug, but the base's mug descends from r9's.
	e.branch("matches", "r9", map[string]any{"merged": "P1D"})
	doc("r9", "mug")
	doc("r9", "jug")
	mergeOnly(e.s.Client(t, client.WithAuthor("bob")), "r9", "mug")
	must(e.c.Append(ctx, "matches", "mug", must(e.c.Head(ctx, "matches", "mug")).ID, []any{op("replace", "/n", 3)}))
	must(merge.Freeze(ctx, e.c, "r9", mergeOnly(e.c, "r9")))
	// r10's replay into its successor leaves pot out.
	e.branch("matches", "r10", map[string]any{"superseded": "P1D"})
	doc("r10", "pan")
	doc("r10", "pot")
	must(merge.Rebase(ctx, e.c, merge.RebaseOptions{Branch: "r10", New: "r10-b", Switch: true, Plan: merge.Options{Resources: []string{"pan"}}}))

	e.s.Clock.Advance(2 * day)
	ds := e.sweep(false)
	wantKeep(t, ds["r7"], "merged claim not verified: cup, changed by the branch in ")
	wantKeep(t, ds["r8"], "merged claim not verified: bowl, changed by the branch in ")
	wantKeep(t, ds["r10"], "superseded claim not verified: pot, changed by the branch in ")
	if d := ds["r9"]; d.Action != janitor.ActionPurged || d.Claim != "merged" {
		t.Fatalf("r9 %+v", d)
	}
}

// §F.3 (v0.63): only batches by a root sub and kid in the base's current
// merge.authors count, so removing an author withdraws its earlier
// batches: a branch it merged is no longer verified as merged.
func TestV073RemovedAuthorWithdrawsMerges(t *testing.T) {
	t.Parallel()
	a := newAuthEnv(t, []string{"r7"},
		map[string]any{"merge": map[string]any{"authors": []any{map[string]any{"sub": "svc:merge", "kid": "editor"}}}})
	a.branch(t, "matches", "r7", map[string]any{"merged": "P1D"})
	m := a.as(a.editor, "svc:merge")
	must(merge.Freeze(ctx, m, "r7", must(must(merge.NewPlan(ctx, m, "matches", "r7", merge.Options{})).Apply(ctx)).NSID))
	later := func() time.Time { return a.s.Now().Add(2 * day) }
	if d := must(janitor.New(a.janitor, janitor.Options{Now: later, DryRun: true}).Check(ctx, "matches", "r7")); d.Action != janitor.ActionWouldPurge {
		t.Fatalf("while listed: %+v", d)
	}
	patchConfig(t, a.admin, "matches", op("replace", "/merge/authors", []any{map[string]any{"sub": "svc:merge", "kid": "ops"}}))
	wantKeep(t, a.check(t, "matches", "r7", 2*day), "merged claim not verified: no batch of the branch is by a principal in the base's merge.authors (")
}
