package core

import (
	"context"
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/grant"
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
