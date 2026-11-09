package core

import (
	"context"
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/grant"
	"github.com/middle-management/patchlog/internal/grantcheck"
)

// V76-01 (v0.76): origin filtered reads (§B.11.9): a branch stays covered
// only while its root, at its head, still trusts the catalog through every
// key item 1 counts, unchanged (FCORE-1); an uncovered namespace's
// filtered URLs are 401 without a grant that verifies there or a cookie
// (FCORE-3); a filtered at lists a namespace read at its head at its
// head, a branch's root included, while visibility reads the base at its
// baseAt (FSVC-6); and a stored subject set is bound to its key's pub
// (FSVC-7).

// v76fWorld is a v75World whose matches also has key fan, without
// requireAt and with a scope rule testing /resource by type, so its grants
// read matches and its branches in part; root's $access gives fan-club
// reader too. With branch, matches-r7 is cut after seeding.
type v76fWorld struct {
	*v75World
	fanPub  string
	fanPriv ed25519.PrivateKey
}

func newV76fWorld(t *testing.T, branch bool) *v76fWorld {
	t.Helper()
	fanPub, fanPriv := grant.GenerateKey()
	w := &v76fWorld{fanPub: fanPub, fanPriv: fanPriv}
	w.v75World = newV75World(t, v75Opts{matches: func(doc map[string]any) {
		doc["keys"] = append(doc["keys"].([]any), v76fFanEntry(fanPub))
	}})
	w.seed()
	w.put("cat-season", "root", map[string]any{"parents": []any{}, "$access": map[string]any{"group:editors": []any{"reader"},
		"user:li": []any{"reader"}, "group:fan-club": []any{"reader"}}})
	if branch {
		if _, err := w.e.CreateBranch(context.Background(), Request{NS: "matches", Cred: w.admin}, BranchRequest{Name: "matches-r7", IfNoneMatch: true}); err != nil {
			t.Fatal(err)
		}
	}
	return w
}

func v76fFanEntry(pub string) map[string]any {
	return map[string]any{"kid": "fan", "alg": "ed25519", "pub": pub, "can": []any{"read"},
		"rules": []any{map[string]any{"op": "test", "path": "/resource", "schema": map[string]any{"type": "string"}}}}
}

// fan is a partial reader of ns in fan-club, through key fan (not one
// item 1 counts), signed with priv.
func (w *v76fWorld) fan(ns string, priv ed25519.PrivateKey) Credentials {
	return w.cred(priv, map[string]any{"kid": "fan", "sub": "user:fan", "groups": []any{"fan-club"}, "ns": []any{ns}, "can": []any{"read"},
		"exp": w.now().Add(10 * time.Minute).UTC().Format(time.RFC3339)})
}

// v76fRedirect is FilteredCurrent's redirect for cred on ns at gs ("" for
// its own, found through the unfiltered /heads' redirect).
func v76fRedirect(t *testing.T, w *v75World, ns, gs string, cred Credentials) (*FilteredRedirect, int) {
	t.Helper()
	ctx := context.Background()
	if gs == "" {
		_, err := v76fUnfiltered(ctx, w.e, ns, cred)
		if r, ok := err.(*FilteredRedirect); ok {
			gs = r.GS
		} else {
			return nil, v75Status(err)
		}
	}
	err := w.e.FilteredCurrent(ctx, ns, gs, cred)
	if r, ok := err.(*FilteredRedirect); ok {
		return r, 0
	}
	return nil, v75Status(err)
}

// v76fUnfiltered is the redirect a partial reader gets at an unfiltered
// URL of ns (§B.11.9 URLs), recorded as the server records it.
func v76fUnfiltered(ctx context.Context, e *Engine, ns string, cred Credentials) (*actor, error) {
	var a *actor
	err := e.filteredRead(ctx, func(t *tx) error {
		var err error
		a, err = t.nsReaderOrRedirect(t.nsByName(ns), cred)
		return err
	})
	return a, err
}

// v76fHeads are the names FilteredHeads lists for cred at ns/g/gs/at/at,
// and its status (0 for 200; -1 for a redirect).
func v76fHeads(t *testing.T, w *v75World, ns, gs, at string, cred Credentials) ([]string, int) {
	t.Helper()
	page, _, err := w.e.FilteredHeads(context.Background(), ns, gs, at, "", "", cred)
	if _, ok := err.(*FilteredRedirect); ok {
		return nil, -1
	}
	if err != nil {
		return nil, v75Status(err)
	}
	var names []string
	for _, it := range page.Items {
		names = append(names, it["resource"].(string))
	}
	return names, 0
}

func v76fHas(names []string, name string) bool {
	for _, n := range names {
		if n == name {
			return true
		}
	}
	return false
}

// §B.11.9 Branches, Where, §C.4 (conformance 105): a branch stays covered
// only while matches, at its head, trusts cat-season through every key
// item 1 counted at the branch's baseAt, each entry unchanged.
func TestV076OriginBranchUncoveredByKeyRotation(t *testing.T) {
	t.Parallel()
	newPub, _ := grant.GenerateKey()
	for name, c := range map[string]struct {
		ops     []any
		covered bool
	}{
		// Scenario 105: catalog-02 replaces catalog-01, its roles scope
		// without reader.
		"catalog-02 replaces catalog-01": {ops: []any{
			map[string]any{"op": "add", "path": "/keys/-", "value": map[string]any{"kid": "catalog-02", "alg": "ed25519", "pub": newPub,
				"can": []any{"read"}, "requireAt": "cat-season", "roles": map[string]any{"allow": []any{"editor"}}}},
			map[string]any{"op": "remove", "path": "/keys/1"},
		}},
		"catalog-01's scope rules changed": {ops: []any{map[string]any{"op": "replace", "path": "/keys/1/rules",
			"value": []any{map[string]any{"op": "test", "path": "/resource", "schema": map[string]any{"type": "string", "minLength": 1}}}}}},
		"catalog-01's pub rotated":       {ops: []any{map[string]any{"op": "replace", "path": "/keys/1/pub", "value": newPub}}},
		"catalog-01's maxTtl edited":     {ops: []any{map[string]any{"op": "replace", "path": "/keys/1/maxTtl", "value": "PT10M"}}},
		"catalog-01's requireAt dropped": {ops: []any{map[string]any{"op": "remove", "path": "/keys/1/requireAt"}}},
		"cat-season left catalogs":       {ops: []any{map[string]any{"op": "remove", "path": "/catalogs/cat-season"}}},
		// Keys added at the head don't count; nor do roles.
		"an unrelated key added": {ops: []any{map[string]any{"op": "add", "path": "/keys/-", "value": map[string]any{"kid": "extra",
			"alg": "ed25519", "pub": newPub, "can": []any{"read"}}}}, covered: true},
		"a key requireAt cat-season added": {ops: []any{map[string]any{"op": "add", "path": "/keys/-", "value": map[string]any{"kid": "catalog-03",
			"alg": "ed25519", "pub": newPub, "can": []any{"read"}, "requireAt": "cat-season"}}}, covered: true},
		"reader's rules changed": {ops: []any{map[string]any{"op": "add", "path": "/roles/reader/rules",
			"value": []any{map[string]any{"op": "test", "path": "/action", "value": "read"}}}}, covered: true},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			w := newV76fWorld(t, true)
			ctx := context.Background()
			fan := w.fan("matches-r7", w.fanPriv)
			red, st := v76fRedirect(t, w.v75World, "matches-r7", "", fan)
			if red == nil {
				t.Fatalf("before: %d", st)
			}
			gs := red.GS
			if names, st := v76fHeads(t, w.v75World, "matches-r7", gs, red.At, fan); st != 0 || !v76fHas(names, "derby") {
				t.Fatalf("before: %v %d", names, st)
			}
			res, err := w.e.IssueEdgeGrants(ctx, []string{fan.Bearer})
			if err != nil || len(res.Grants) != 1 || res.Grants[0].GS != gs {
				t.Fatalf("exchange before: %+v %v", res, err)
			}
			w.patchConfig("matches", c.ops...)
			red2, st := v76fRedirect(t, w.v75World, "matches-r7", gs, fan)
			names, hst := v76fHeads(t, w.v75World, "matches-r7", gs, red.At, fan)
			_, _, lerr := w.e.FilteredLog(ctx, "matches-r7", gs, red.At, "", 0, fan)
			res, xerr := w.e.IssueEdgeGrants(ctx, []string{fan.Bearer})
			w.inTx(func(t2 *tx) {
				if got := t2.filteredScope(t2.nsByName("matches-r7")) != nil; got != c.covered {
					t.Errorf("covered %v, want %v", got, c.covered)
				}
			})
			if c.covered {
				if red2 == nil {
					t.Fatalf("still covered: FilteredCurrent %d", st)
				}
				if names, st := v76fHeads(t, w.v75World, "matches-r7", gs, red2.At, fan); st != 0 || !v76fHas(names, "derby") {
					t.Fatalf("still covered: heads %v %d", names, st)
				}
				if xerr != nil || len(res.Grants) != 1 || res.Grants[0].GS != gs {
					t.Fatalf("still covered: exchange %+v %v", res, xerr)
				}
				return
			}
			if st != 403 || hst != 403 || v75Status(lerr) != 403 || v76fHas(names, "derby") {
				t.Fatalf("uncovered: FilteredCurrent %d, FilteredHeads %d %v, FilteredLog %v", st, hst, names, lerr)
			}
			if v75Status(xerr) != 403 {
				t.Fatalf("uncovered: exchange %+v %v, want 403", res, xerr)
			}
		})
	}
}

// §B.11.9 gs, §C.4 (conformance 106): a partial reader of matches-r7
// whose grant is signed by a base key that matches then removes: her
// cookie is 403 at a later at, and her exchange then 401.
func TestV076OriginBranchBaseKeyRemoved(t *testing.T) {
	t.Parallel()
	w := newV76fWorld(t, true)
	ctx := context.Background()
	fan := w.fan("matches-r7", w.fanPriv)
	res, err := w.e.IssueEdgeGrants(ctx, []string{fan.Bearer})
	if err != nil || len(res.Grants) != 1 || res.Grants[0].GS == "" {
		t.Fatalf("exchange: %+v %v", res, err)
	}
	gs := res.Grants[0].GS
	cookie := Credentials{Edge: &EdgeGrant{NS: "matches-r7", GS: gs, Prefix: "/ns/matches-r7/g/" + gs, Exp: w.now().Add(10 * time.Minute)}}
	red, st := v76fRedirect(t, w.v75World, "matches-r7", gs, cookie)
	if red == nil {
		t.Fatalf("cookie before: %d", st)
	}
	w.patchConfig("matches", map[string]any{"op": "remove", "path": "/keys/2"})
	if _, st := v76fRedirect(t, w.v75World, "matches-r7", gs, cookie); st != 403 {
		t.Fatalf("cookie at a later at: %d, want 403", st)
	}
	if _, err := w.e.IssueEdgeGrants(ctx, []string{fan.Bearer}); v75Status(err) != 401 {
		t.Fatalf("exchange after the key went: %v, want 401", err)
	}
}

// §B.11.9 URLs, §A.4 Answers: a branch's filtered at lists its root, a
// catalog.trust member read at its head, at its head, while item 1 still
// reads the root's roles as of the branch's baseAt; the at round-trips;
// an at recorded with the root at baseAt instead isn't answered (302).
func TestV076OriginBranchAtLayout(t *testing.T) {
	t.Parallel()
	w := newV75World(t, v75Opts{})
	w.seed()
	ctx := context.Background()
	w.put("matches", "final", map[string]any{"title": "final"})
	w.put("cat-season", "matches.final", map[string]any{"parents": v75Parents("season")})
	if _, err := w.e.CreateBranch(ctx, Request{NS: "matches", Cred: w.admin}, BranchRequest{Name: "matches-r7", IfNoneMatch: true}); err != nil {
		t.Fatal(err)
	}
	var baseAtID string
	w.inTx(func(t2 *tx) { baseAtID = t2.nsLogID(t2.nsByName("matches-r7").baseAt.Int64).String() })
	// matches moves past the branch's baseAt: reader no longer reads final
	// there, at its head.
	w.patchConfig("matches", map[string]any{"op": "add", "path": "/roles/reader/rules",
		"value": []any{map[string]any{"not": map[string]any{"op": "test", "path": "/resource", "value": "final"}}}})
	head := w.head("matches")
	if head == baseAtID {
		t.Fatal("matches didn't move")
	}
	li := w.li(map[string]any{"ns": []any{"matches-r7"}})
	red, st := v76fRedirect(t, w, "matches-r7", "", li)
	if red == nil {
		t.Fatalf("li on matches-r7: %d", st)
	}
	if got := red.CP.nsID("matches"); got != head {
		t.Fatalf("matches listed at %s, want its head %s (baseAt %s)", got, head, baseAtID)
	}
	if got := red.CP.nsID("cat-season"); got != w.head("cat-season") || red.CP.nsID("matches-r7") != w.head("matches-r7") {
		t.Fatalf("at %v", red.CP.ids)
	}
	// Visibility in the branch: matches's trust, keys and roles as of
	// baseAt, so final stays visible.
	names, st := v76fHeads(t, w, "matches-r7", red.GS, red.At, li)
	if st != 0 || !v76fHas(names, "final") || !v76fHas(names, "derby") || v76fHas(names, "opener") {
		t.Fatalf("heads at the current at: %v %d", names, st)
	}
	// A catalog write: a new at; the recorded one still answers.
	w.put("cat-season", "matches.shared", map[string]any{"parents": v75Parents("root")})
	red2, _ := v76fRedirect(t, w, "matches-r7", red.GS, li)
	if red2 == nil || red2.At == red.At {
		t.Fatalf("after a catalog write: %+v", red2)
	}
	if names, st := v76fHeads(t, w, "matches-r7", red.GS, red.At, li); st != 0 || !v76fHas(names, "final") {
		t.Fatalf("heads at the recorded at: %v %d", names, st)
	}
	// An at recorded before v0.76, matches at baseAt, still computes the
	// same answer, as visibility reads matches at baseAt either way: it
	// is answered (§B.11.9 URLs, "wherever the origin can compute that
	// exact answer again").
	old := &fcp{ids: map[string]string{}}
	for k, v := range red.CP.ids {
		old.ids[k] = v
	}
	old.ids["matches"] = baseAtID
	old.at = grantcheck.CombinedAt(old.ids)
	if err := w.e.recordFilteredAt(ctx, old); err != nil {
		t.Fatal(err)
	}
	if names, st := v76fHeads(t, w, "matches-r7", red.GS, old.at, li); st != 0 || !v76fHas(names, "final") {
		t.Fatalf("an at recorded before v0.76: %v %d", names, st)
	}
	// A base read only as a base stays at its baseAt: a branch of the
	// branch lists matches-r7 so.
	if _, err := w.e.CreateBranch(ctx, Request{NS: "matches-r7", Cred: w.admin}, BranchRequest{Name: "matches-r7a", IfNoneMatch: true}); err != nil {
		t.Fatal(err)
	}
	w.put("matches-r7", "shared", map[string]any{"title": "moved"})
	var moved *fcp
	w.inTx(func(t2 *tx) {
		b, r7 := t2.nsByName("matches-r7a"), t2.nsByName("matches-r7")
		fs := t2.filteredScope(b)
		if fs == nil {
			t.Fatal("matches-r7a not covered")
		}
		cp := t2.filteredCurrent(fs)
		if cp.seqs["matches-r7"] != b.baseAt.Int64 || cp.seqs["matches-r7"] == r7.headSeq.Int64 || cp.nsID("matches") != head {
			t.Fatalf("matches-r7a's at: %v", cp.ids)
		}
		if got, ok := t2.filteredAt(fs, cp.at); !ok || got.readSeq("matches") != fs.chain[1].at || got.readSeq("matches-r7") != b.baseAt.Int64 {
			t.Fatalf("matches-r7a's at doesn't resolve: %v", ok)
		}
		// One listing matches-r7, read only as a base, elsewhere isn't
		// answered.
		ids := map[string]string{}
		for k, v := range cp.ids {
			ids[k] = v
		}
		ids["matches-r7"] = t2.nsLogID(r7.headSeq.Int64).String()
		moved = &fcp{ids: ids, at: grantcheck.CombinedAt(ids)}
	})
	if err := w.e.recordFilteredAt(ctx, moved); err != nil {
		t.Fatal(err)
	}
	w.inTx(func(t2 *tx) {
		if _, ok := t2.filteredAt(t2.filteredScope(t2.nsByName("matches-r7a")), moved.at); ok {
			t.Fatal("an at listing a base read only as a base past its baseAt resolved")
		}
	})
}

// §B.11.9 gs, §C.4: a stored subject set is bound to its key's pub: a
// cookie is 403 once matches replaces that kid's pub, keeping its scope
// and roles, until the reader exchanges again; an empty stored pub is 403
// too. In a branch, the base key's pub decides.
func TestV076OriginGSBoundToPub(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	newPub, newPriv := grant.GenerateKey()
	for _, c := range []struct {
		name, ns string
		kid      int // index of the key in matches's keys
	}{{"matches, catalog-01", "matches", 1}, {"matches-r7, base key fan", "matches-r7", 2}} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			w := newV76fWorld(t, c.ns != "matches")
			grantOf := func(priv ed25519.PrivateKey) Credentials {
				if c.kid == 1 {
					return w.catGrant("user:li", []any{"editors", "interns"})
				}
				return w.fan(c.ns, priv)
			}
			cred := grantOf(w.fanPriv)
			res, err := w.e.IssueEdgeGrants(ctx, []string{cred.Bearer})
			if err != nil || len(res.Grants) != 1 || res.Grants[0].GS == "" {
				t.Fatalf("exchange: %+v %v", res, err)
			}
			gs := res.Grants[0].GS
			cookie := Credentials{Edge: &EdgeGrant{NS: c.ns, GS: gs, Prefix: "/ns/" + c.ns + "/g/" + gs, Exp: w.now().Add(10 * time.Minute)}}
			wantPub := w.catPub
			if c.kid == 2 {
				wantPub = w.fanPub
			}
			w.inTx(func(t2 *tx) {
				if r := t2.loadGS(c.ns, gs); r == nil || r.pub != wantPub {
					t.Fatalf("stored row %+v, want pub %s", r, wantPub)
				}
			})
			red, st := v76fRedirect(t, w.v75World, c.ns, gs, cookie)
			if red == nil {
				t.Fatalf("cookie before: %d", st)
			}
			if names, st := v76fHeads(t, w.v75World, c.ns, gs, red.At, cookie); st != 0 || !v76fHas(names, "derby") {
				t.Fatalf("cookie before: %v %d", names, st)
			}
			// An empty stored pub, as a row from before the migration has.
			if err := w.e.update(ctx, func(t2 *tx) error {
				_, err := t2.Exec(`UPDATE filtered_gs SET pub = '' WHERE ns = ? AND gs = ?`, c.ns, gs)
				return err
			}); err != nil {
				t.Fatal(err)
			}
			if _, st := v76fHeads(t, w.v75World, c.ns, gs, red.At, cookie); st != 403 {
				t.Fatalf("an empty stored pub: %d, want 403", st)
			}
			if _, err := w.e.IssueEdgeGrants(ctx, []string{cred.Bearer}); err != nil {
				t.Fatal(err)
			}
			if _, st := v76fHeads(t, w.v75World, c.ns, gs, red.At, cookie); st != 0 {
				t.Fatalf("exchanged again: %d", st)
			}
			// The kid's pub is replaced, its scope and roles kept.
			w.patchConfig("matches", map[string]any{"op": "replace", "path": "/keys/" + string(rune('0'+c.kid)) + "/pub", "value": newPub})
			if c.kid == 1 {
				w.catPub, w.catPriv = newPub, newPriv
			}
			red2, st := v76fRedirect(t, w.v75World, c.ns, gs, cookie)
			if st != 403 {
				t.Fatalf("cookie after the pub changed: %+v %d, want 403", red2, st)
			}
			if _, err := w.e.IssueEdgeGrants(ctx, []string{cred.Bearer}); v75Status(err) != 401 {
				t.Fatalf("the old grant's exchange: %v, want 401", err)
			}
			fresh := grantOf(newPriv)
			res, err = w.e.IssueEdgeGrants(ctx, []string{fresh.Bearer})
			if err != nil || len(res.Grants) != 1 || res.Grants[0].GS != gs {
				t.Fatalf("exchange with the new key: %+v %v", res, err)
			}
			red3, st := v76fRedirect(t, w.v75World, c.ns, gs, cookie)
			if red3 == nil {
				t.Fatalf("cookie after exchanging again: %d", st)
			}
			if names, st := v76fHeads(t, w.v75World, c.ns, gs, red3.At, cookie); st != 0 || !v76fHas(names, "derby") {
				t.Fatalf("cookie after exchanging again: %v %d", names, st)
			}
		})
	}
}

// §B.11.9 Purged namespaces, §B.11.5: an uncovered namespace's filtered
// URLs are 401 for a request with neither a grant that verifies there nor
// a cookie, a public namespace's included, and 403 otherwise.
func TestV076OriginUncoveredFiltered401(t *testing.T) {
	t.Parallel()
	w := newV75World(t, v75Opts{})
	w.mkNS("pub", map[string]any{"read": "public", "keys": []any{w.kEntry()}})
	w.mkNS("priv", map[string]any{"read": "grant", "keys": []any{w.kEntry()}})
	ctx := context.Background()
	gs := grantcheck.SubjectSetID([]string{"group:editors"})
	at := grantcheck.CombinedAt(map[string]string{"pub": w.head("pub")})
	k := func(ns string, can ...any) Credentials {
		return w.cred(w.kPriv, map[string]any{"kid": "k", "sub": "user:r", "ns": []any{ns}, "can": can})
	}
	badSig := k("pub", "read")
	badSig.Bearer = badSig.Bearer[:len(badSig.Bearer)-4] + "AAAA"
	exp := w.now().Add(10 * time.Minute)
	for name, c := range map[string]struct {
		ns   string
		cred Credentials
		want int
	}{
		"public, no credentials":                  {"pub", Credentials{}, 401},
		"public, a grant for another namespace":   {"pub", k("matches", "read"), 401},
		"public, a grant that doesn't verify":     {"pub", badSig, 401},
		"public, a grant that verifies there":     {"pub", k("pub", "read"), 403},
		"public, a verified cookie":               {"pub", Credentials{Edge: &EdgeGrant{NS: "pub", Prefix: "/ns/pub", Exp: exp}}, 403},
		"private, no credentials":                 {"priv", Credentials{}, 401},
		"private, a grant that reads there":       {"priv", k("priv", "read"), 403},
		"private, a grant for another namespace":  {"priv", k("matches", "read"), 403},
		"private, a grant that doesn't read here": {"priv", k("priv", "create"), 403},
	} {
		st := v75Status(w.e.FilteredCurrent(ctx, c.ns, gs, c.cred))
		_, _, herr := w.e.FilteredHeads(ctx, c.ns, gs, at, "", "", c.cred)
		_, _, lerr := w.e.FilteredLog(ctx, c.ns, gs, at, "", 0, c.cred)
		if st != c.want || v75Status(herr) != c.want || v75Status(lerr) != c.want {
			t.Errorf("%s: FilteredCurrent %d, FilteredHeads %v, FilteredLog %v, want %d", name, st, herr, lerr, c.want)
		}
		if c.want == 401 {
			if e, _ := herr.(*Error); e == nil || e.Body["code"] != "unauthenticated" {
				t.Errorf("%s: %v, want unauthenticated", name, herr)
			}
		}
	}
}
