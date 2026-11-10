package core

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/grant"
	"github.com/middle-management/patchlog/internal/grantcheck"
)

// V76-01 (v0.76): origin filtered reads (§B.11.9): an uncovered
// namespace's filtered URLs are 401 without a grant that verifies there or
// a cookie (FCORE-3), a branch among them since v0.78; and a stored
// subject set is bound to its key's pub (FSVC-7).

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
	err := w.e.FilteredCurrent(ctx, ns, gs, "/heads", cred)
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

// §B.11.9 Where (v0.78: "Filtered reads cover no branch"; conformance
// TDA 63, 105, 106): a partial reader of matches-r7 gets no redirect, its
// filtered URLs are 403 and its exchange 403 with no g prefix, whatever
// matches trusts; once the base key that signed its grant is gone, the
// grant no longer verifies and the exchange is 401. Before v0.78 the
// branch was covered while matches still trusted cat-season through every
// key counted at baseAt.
func TestV076OriginBranchUncovered(t *testing.T) {
	t.Parallel()
	w := newV76fWorld(t, true)
	ctx := context.Background()
	fan := w.fan("matches-r7", w.fanPriv)
	li := w.li(map[string]any{"ns": []any{"matches-r7"}})
	gs := grantcheck.SubjectSetID([]string{"group:fan-club"})
	at := grantcheck.CombinedAt(map[string]string{"matches-r7": w.head("matches-r7")})
	for name, cred := range map[string]Credentials{"fan": fan, "li": li} {
		if _, err := v76fUnfiltered(ctx, w.e, "matches-r7", cred); v75Status(err) != 403 {
			t.Errorf("%s: unfiltered URL %v, want 403 and no redirect", name, err)
		}
		if _, st := v76fRedirect(t, w.v75World, "matches-r7", gs, cred); st != 403 {
			t.Errorf("%s: FilteredCurrent %d, want 403", name, st)
		}
		if _, st := v76fHeads(t, w.v75World, "matches-r7", gs, at, cred); st != 403 {
			t.Errorf("%s: FilteredHeads %d, want 403", name, st)
		}
		if _, _, err := w.e.FilteredLog(ctx, "matches-r7", gs, at, "", 0, cred); v75Status(err) != 403 {
			t.Errorf("%s: FilteredLog %v, want 403", name, err)
		}
		if res, err := w.e.IssueEdgeGrants(ctx, []string{cred.Bearer}); v75Status(err) != 403 {
			t.Errorf("%s: exchange %+v %v, want 403", name, res, err)
		}
	}
	if _, st := v76fHeads(t, w.v75World, "matches-r7", gs, at, Credentials{}); st != 401 {
		t.Errorf("no credentials: %d, want 401", st)
	}
	cookie := Credentials{Edge: &EdgeGrant{NS: "matches-r7", GS: gs, Prefix: "/ns/matches-r7/g/" + gs, Exp: w.now().Add(10 * time.Minute)}}
	if _, st := v76fRedirect(t, w.v75World, "matches-r7", gs, cookie); st != 403 {
		t.Errorf("a g cookie: %d, want 403", st)
	}
	w.patchConfig("matches", map[string]any{"op": "remove", "path": "/keys/2"})
	if _, err := w.e.IssueEdgeGrants(ctx, []string{fan.Bearer}); v75Status(err) != 401 {
		t.Fatalf("exchange after the key went: %v, want 401", err)
	}
}

// §B.11.9 gs, §C.4 (conformance 106, ported from the branch case before
// v0.78): a partial reader of matches whose grant is signed by key fan,
// which matches then removes: her cookie is 403 at a later at, and her
// exchange then 401.
func TestV076OriginGSKeyRemoved(t *testing.T) {
	t.Parallel()
	w := newV76fWorld(t, false)
	ctx := context.Background()
	fan := w.fan("matches", w.fanPriv)
	res, err := w.e.IssueEdgeGrants(ctx, []string{fan.Bearer})
	if err != nil || len(res.Grants) != 1 || res.Grants[0].GS == "" {
		t.Fatalf("exchange: %+v %v", res, err)
	}
	gs := res.Grants[0].GS
	cookie := Credentials{Edge: &EdgeGrant{NS: "matches", GS: gs, Prefix: "/ns/matches/g/" + gs, Exp: w.now().Add(10 * time.Minute)}}
	red, st := v76fRedirect(t, w.v75World, "matches", gs, cookie)
	if red == nil {
		t.Fatalf("cookie before: %d", st)
	}
	if names, st := v76fHeads(t, w.v75World, "matches", gs, red.At, cookie); st != 0 || !v76fHas(names, "derby") {
		t.Fatalf("cookie before: %v %d", names, st)
	}
	w.patchConfig("matches", map[string]any{"op": "remove", "path": "/keys/2"})
	if _, st := v76fRedirect(t, w.v75World, "matches", gs, cookie); st != 403 {
		t.Fatalf("cookie at a later at: %d, want 403", st)
	}
	if _, err := w.e.IssueEdgeGrants(ctx, []string{fan.Bearer}); v75Status(err) != 401 {
		t.Fatalf("exchange after the key went: %v, want 401", err)
	}
}

// §B.11.9 gs, §C.4: a stored subject set is bound to its key's pub: a
// cookie is 403 once matches replaces that kid's pub, keeping its scope
// and roles, until the reader exchanges again; an empty stored pub is 403
// too.
func TestV076OriginGSBoundToPub(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	newPub, newPriv := grant.GenerateKey()
	// Branches aren't covered (v0.78), so the base key's case is gone.
	for _, c := range []struct {
		name, ns string
		kid      int // index of the key in matches's keys
	}{{"matches, catalog-01", "matches", 1}} {
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
			// A grant of the new key exchanges for a gs of its own, bound
			// to the new pub (catvis.KeySubject); the old gs stays 403.
			fresh := grantOf(newPriv)
			res, err = w.e.IssueEdgeGrants(ctx, []string{fresh.Bearer})
			if err != nil || len(res.Grants) != 1 || res.Grants[0].GS == "" || res.Grants[0].GS == gs {
				t.Fatalf("exchange with the new key: %+v %v (old gs %s)", res, err, gs)
			}
			if _, st := v76fRedirect(t, w.v75World, c.ns, gs, cookie); st != 403 {
				t.Fatalf("the old cookie after exchanging again: %d, want 403", st)
			}
			gs2 := res.Grants[0].GS
			cookie2 := Credentials{Edge: &EdgeGrant{NS: c.ns, GS: gs2, Prefix: "/ns/" + c.ns + "/g/" + gs2, Exp: w.now().Add(10 * time.Minute)}}
			red3, st := v76fRedirect(t, w.v75World, c.ns, gs2, cookie2)
			if red3 == nil {
				t.Fatalf("cookie after exchanging again: %d", st)
			}
			if names, st := v76fHeads(t, w.v75World, c.ns, gs2, red3.At, cookie2); st != 0 || !v76fHas(names, "derby") {
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
		st := v75Status(w.e.FilteredCurrent(ctx, c.ns, gs, "/heads", c.cred))
		lst := v75Status(w.e.FilteredCurrent(ctx, c.ns, gs, "/log", c.cred))
		_, _, herr := w.e.FilteredHeads(ctx, c.ns, gs, at, "", "", c.cred)
		_, _, lerr := w.e.FilteredLog(ctx, c.ns, gs, at, "", 0, c.cred)
		if st != c.want || lst != c.want || v75Status(herr) != c.want || v75Status(lerr) != c.want {
			t.Errorf("%s: FilteredCurrent %d %d, FilteredHeads %v, FilteredLog %v, want %d", name, st, lst, herr, lerr, c.want)
		}
		if c.want == 401 {
			if e, _ := herr.(*Error); e == nil || e.Body["code"] != "unauthenticated" {
				t.Errorf("%s: %v, want unauthenticated", name, herr)
			}
		}
	}
}

// §B.11.9 Purged namespaces, §8.5: a purged namespace this section doesn't
// cover answers its filtered URLs as §8.5 answers their unfiltered forms
// once the read check passes: /heads, at an at or without, is 410, as are
// long-poll and events from the purge-ns entry; the forms §8.5 serves as
// before keep the uncovered answer, 401 without credentials. A private
// purged namespace is still 401 before any 410.
func TestV076OriginPurgedUncoveredFiltered(t *testing.T) {
	t.Parallel()
	w := newV75World(t, v75Opts{})
	ctx := context.Background()
	for _, ns := range []string{"pub", "priv"} {
		read := "grant"
		if ns == "pub" {
			read = "public"
		}
		w.mkNS(ns, map[string]any{"read": read, "keys": []any{w.kEntry()}})
		w.admin = w.cred(w.kPriv, map[string]any{"kid": "k", "sub": "user:r", "ns": []any{ns}, "can": []any{"config", "read"}})
		w.patchConfig(ns, map[string]any{"op": "add", "path": "/frozen", "value": true})
		op := w.cred(w.opPriv, map[string]any{"kid": "operator", "sub": "op:root", "ns": []any{ns}, "can": []any{"purge-ns"}})
		if _, err := w.e.PurgeNamespace(ctx, Request{NS: ns, Cred: op}, w.head(ns), true); err != nil {
			t.Fatal(err)
		}
	}
	gs := grantcheck.SubjectSetID([]string{"group:editors"})
	reader := func(ns string) Credentials {
		return w.cred(w.kPriv, map[string]any{"kid": "k", "sub": "user:r", "ns": []any{ns}, "can": []any{"read"}})
	}
	for _, c := range []struct {
		name, ns   string
		cred       Credentials
		heads, log int // /heads forms; log ranges and live from elsewhere
	}{
		{"public, no credentials", "pub", Credentials{}, 410, 401},
		{"public, a grant that verifies there", "pub", reader("pub"), 410, 403},
		{"private, no credentials", "priv", Credentials{}, 401, 401},
		{"private, a grant that reads there", "priv", reader("priv"), 410, 403},
	} {
		w.admin = w.cred(w.kPriv, map[string]any{"kid": "k", "sub": "user:r", "ns": []any{c.ns}, "can": []any{"read"}})
		purge := w.head(c.ns)
		_, uerr := w.e.NamespaceHeads(ctx, c.ns, purge, "", c.cred)
		if v75Status(uerr) != c.heads {
			t.Fatalf("%s: unfiltered /heads %v, want %d", c.name, uerr, c.heads)
		}
		at := grantcheck.CombinedAt(map[string]string{c.ns: purge})
		_, _, herr := w.e.FilteredHeads(ctx, c.ns, gs, at, "", "", c.cred)
		hcur := w.e.FilteredCurrent(ctx, c.ns, gs, "/heads", c.cred)
		_, _, pollPurge := w.e.FilteredLiveLog(ctx, c.ns, gs, purge, 10, c.cred)
		if v75Status(herr) != c.heads || v75Status(hcur) != c.heads || v75Status(pollPurge) != c.heads {
			t.Errorf("%s: FilteredHeads %v, FilteredCurrent /heads %v, live from the purge-ns entry %v, want %d", c.name, herr, hcur, pollPurge, c.heads)
		}
		if c.heads == 410 {
			if e, _ := herr.(*Error); e == nil || e.Body["code"] != "purged" || e.Body["head"] != purge {
				t.Errorf("%s: %v, want purged with head %s", c.name, herr, purge)
			}
		}
		_, _, lerr := w.e.FilteredLog(ctx, c.ns, gs, at, "", 10, c.cred)
		lcur := w.e.FilteredCurrent(ctx, c.ns, gs, "/log", c.cred)
		_, _, poll := w.e.FilteredLiveLog(ctx, c.ns, gs, "", 10, c.cred)
		if v75Status(lerr) != c.log || v75Status(lcur) != c.log || v75Status(poll) != c.log {
			t.Errorf("%s: FilteredLog %v, FilteredCurrent /log %v, live %v, want %d", c.name, lerr, lcur, poll, c.log)
		}
	}
}

// §B.11.9 gs, §C.4: readers whose grants come from two keys with the same
// scope rules never share a gs, so neither's filtered_gs row judges the
// other's cookies: once fan's pub is replaced, a cookie from fan's grant
// is 403 whatever is exchanged through fan2, before or after, and fan2's
// cookie reads on. Before catvis.KeySubject both got one gs, whose row
// kept the kid and pub of the last exchange.
func TestV076OriginGSPerKey(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	for _, rotateFirst := range []bool{false, true} {
		t.Run(fmt.Sprintf("rotate first %v", rotateFirst), func(t *testing.T) {
			t.Parallel()
			w := newV76fWorld(t, false)
			pub2, priv2 := grant.GenerateKey()
			e2 := v76fFanEntry(pub2)
			e2["kid"] = "fan2"
			w.patchConfig("matches", map[string]any{"op": "add", "path": "/keys/-", "value": e2})
			a := w.fan("matches", w.fanPriv)
			b := w.cred(priv2, map[string]any{"kid": "fan2", "sub": "user:other", "groups": []any{"fan-club"}, "ns": []any{"matches"}, "can": []any{"read"},
				"exp": w.now().Add(10 * time.Minute).UTC().Format(time.RFC3339)})
			exchange := func(c Credentials) (string, Credentials) {
				t.Helper()
				res, err := w.e.IssueEdgeGrants(ctx, []string{c.Bearer})
				if err != nil || len(res.Grants) != 1 || res.Grants[0].GS == "" {
					t.Fatalf("exchange: %+v %v", res, err)
				}
				gs := res.Grants[0].GS
				return gs, Credentials{Edge: &EdgeGrant{NS: "matches", GS: gs, Prefix: "/ns/matches/g/" + gs, Exp: w.now().Add(10 * time.Minute)}}
			}
			rotate := func() {
				np, _ := grant.GenerateKey()
				w.patchConfig("matches", map[string]any{"op": "replace", "path": "/keys/2/pub", "value": np})
			}
			gsA, cookieA := exchange(a)
			if rotateFirst {
				rotate()
				if _, st := v76fRedirect(t, w.v75World, "matches", gsA, cookieA); st != 403 {
					t.Fatalf("fan's cookie after the rotation: %d, want 403", st)
				}
			}
			gsB, cookieB := exchange(b)
			if gsA == gsB {
				t.Fatalf("grants of fan and fan2 share gs %s", gsA)
			}
			w.inTx(func(t2 *tx) {
				if r := t2.loadGS("matches", gsA); r == nil || r.kid != "fan" || r.pub != w.fanPub {
					t.Fatalf("fan's row %+v", r)
				}
				if r := t2.loadGS("matches", gsB); r == nil || r.kid != "fan2" || r.pub != pub2 {
					t.Fatalf("fan2's row %+v", r)
				}
			})
			if !rotateFirst {
				rotate()
			}
			if red, st := v76fRedirect(t, w.v75World, "matches", gsA, cookieA); red != nil || st != 403 {
				names := []string(nil)
				if red != nil {
					names, _ = v76fHeads(t, w.v75World, "matches", gsA, red.At, cookieA)
				}
				t.Fatalf("fan's cookie after fan's pub was replaced: %d %v, want 403", st, names)
			}
			red, st := v76fRedirect(t, w.v75World, "matches", gsB, cookieB)
			if red == nil {
				t.Fatalf("fan2's cookie: %d", st)
			}
			if names, st := v76fHeads(t, w.v75World, "matches", gsB, red.At, cookieB); st != 0 || !v76fHas(names, "derby") {
				t.Fatalf("fan2's cookie: %v %d", names, st)
			}
		})
	}
}
