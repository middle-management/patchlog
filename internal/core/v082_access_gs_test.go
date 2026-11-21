package core

import (
	"context"
	"testing"
	"time"
)

// V82-02 (v0.82), ACC-14: a view cookie ends when the key its key: string
// names, or a key or role its rules came from, is gone or changes in any
// member (SERVICES §7.9 view).

// v82accessCookie exchanges cred and returns the cookie of its /view/ prefix
// in matches, with its view. The cookie expires as the server's would
// (§C.5.2): 15 minutes on, or with the grant if that is sooner.
func v82accessCookie(t *testing.T, w *v75World, cred Credentials) (Credentials, string) {
	t.Helper()
	res, err := w.e.IssueEdgeGrants(context.Background(), []string{cred.Bearer})
	if err != nil || len(res.Grants) != 1 || res.Grants[0].View == "" {
		t.Fatalf("exchange: %+v %v", res, err)
	}
	g := res.Grants[0]
	exp := res.Now.Add(maxEdgeTTL)
	if !g.Exp.IsZero() && g.Exp.Before(exp) {
		exp = g.Exp
	}
	return Credentials{Edge: &EdgeGrant{NS: g.NS, View: g.View, Prefix: "/ns/" + g.NS + "/view/" + g.View, Exp: exp}}, g.View
}

// v82accessLater moves w's clock on by d: a cookie from an exchange after
// it expires later than those before, which is how the origin tells it
// from them once the record's entry was replaced (recordFilteredView).
func v82accessLater(w *v75World, d time.Duration) { w.clock.Add(d.Milliseconds()) }

// v82accessCookieReads is the status of cookie's read of matches' filtered
// /heads for view at the current checkpoint: 0 where it is served.
func v82accessCookieReads(t *testing.T, w *v75World, vid string, cookie Credentials) int {
	t.Helper()
	red, st := v76fRedirect(t, w, "matches", vid, cookie)
	if red == nil {
		return st
	}
	_, st = v76fHeads(t, w, "matches", vid, red.At, cookie)
	return st
}

func v82accessOp(op, path string, value any) map[string]any {
	return map[string]any{"op": op, "path": path, "value": value}
}

// §7.9 view (v0.82): "A view cookie is 403 at an at where those rules
// differ, or the key its key: string names, or a key or role they came
// from, is gone or changes in any member, until the reader exchanges
// again." Each change below leaves the scope digest, the key's pub and
// its read alone, so before v0.82 the cookie was served on; an unrelated
// key's or role's change still ends nothing.
func TestV082AccessGSEntryAnyMember(t *testing.T) {
	t.Parallel()
	ends := map[string]map[string]any{
		"the key's sub":      v82accessOp("add", "/keys/1/sub", "user:.*"),
		"the key's groups":   v82accessOp("add", "/keys/1/groups", map[string]any{"deny": []any{"banned"}}),
		"the key's roles":    v82accessOp("add", "/keys/1/roles", map[string]any{"allow": []any{"reader"}}),
		"the key's attrs":    v82accessOp("add", "/keys/1/attrs", true),
		"the key's maxTtl":   v82accessOp("replace", "/keys/1/maxTtl", "PT14M"),
		"the key's rate":     v82accessOp("add", "/keys/1/rate", map[string]any{"rate": 50.0, "burst": 50.0}),
		"the key's can":      v82accessOp("replace", "/keys/1/can", []any{"read", "append"}),
		"the role's can":     v82accessOp("replace", "/roles/reader/can", []any{"read", "append"}),
		"the role's x-label": v82accessOp("add", "/roles/reader/x-label", "Readers"),
		// v0.87: any role that lists read, one the grant doesn't hold
		// included.
		"another role listing read": v82accessOp("add", "/roles/other", map[string]any{"can": []any{"read", "append"}}),
	}
	keeps := map[string]map[string]any{
		"another key's member":      v82accessOp("add", "/keys/0/maxTtl", "PT2H"),
		"another role without read": v82accessOp("add", "/roles/other", map[string]any{"can": []any{"append"}}),
		"a member of its own":       v82accessOp("add", "/x-note", "PT55S"),
	}
	for name, patch := range ends {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			w := newV75World(t, v75Opts{})
			w.seed()
			cookie, vid := v82accessCookie(t, w, w.li())
			if st := v82accessCookieReads(t, w, vid, cookie); st != 0 {
				t.Fatalf("the cookie before the change: %d", st)
			}
			var before string
			w.inTx(func(t2 *tx) { before = t2.loadView("matches", vid).entry })
			if before == "" {
				t.Fatal("the exchange recorded no entry digest")
			}
			w.patchConfig("matches", patch)
			if st := v82accessCookieReads(t, w, vid, cookie); st != 403 {
				t.Fatalf("the cookie after the change: %d, want 403", st)
			}
			// Long-poll judges it at the current checkpoint.
			if _, _, err := w.e.FilteredLiveLog(context.Background(), "matches", vid, "", 100, cookie); v75Status(err) != 403 {
				t.Fatalf("long-poll under the cookie after the change: %v, want 403", err)
			}
			// Until the reader exchanges again: the same view (none of
			// these members is in it), a new record.
			v82accessLater(w, time.Second)
			cookie2, gs2 := v82accessCookie(t, w, w.li())
			if gs2 != vid {
				t.Fatalf("vid after the change %s, was %s", gs2, vid)
			}
			if st := v82accessCookieReads(t, w, vid, cookie2); st != 0 {
				t.Fatalf("the cookie after exchanging again: %d", st)
			}
			w.inTx(func(t2 *tx) {
				if after := t2.loadView("matches", vid).entry; after == "" || after == before {
					t.Fatalf("entry digest after the change %q, before %q", after, before)
				}
			})
			if _, _, err := w.e.FilteredLiveLog(context.Background(), "matches", vid, "", 100, cookie2); err != nil {
				t.Fatalf("long-poll after exchanging again: %v", err)
			}
			// The cookie the change ended stays ended.
			if st := v82accessCookieReads(t, w, vid, cookie); st != 403 {
				t.Fatalf("the earlier cookie after exchanging again: %d, want 403", st)
			}
		})
	}
	for name, patch := range keeps {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			w := newV75World(t, v75Opts{})
			w.seed()
			cookie, vid := v82accessCookie(t, w, w.li())
			w.patchConfig("matches", patch)
			if st := v82accessCookieReads(t, w, vid, cookie); st != 0 {
				t.Fatalf("the cookie after an unrelated change: %d", st)
			}
		})
	}
}

// §7.9 view: the changes that ended a cookie before v0.82 still do, and
// are 403 too: a role gaining a rule (its scope digest differs, and her
// next exchange gives another view), the key or the role removed.
func TestV082AccessGSEntryEarlierEndings(t *testing.T) {
	t.Parallel()
	for name, patch := range map[string]map[string]any{
		"the role gains a rule": v82accessOp("add", "/roles/reader/rules", []any{map[string]any{"op": "test", "path": "/resource", "schema": map[string]any{"pattern": "^d"}}}),
		"the key is removed":    {"op": "remove", "path": "/keys/1"},
		"the role is removed":   {"op": "remove", "path": "/roles/reader"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			w := newV75World(t, v75Opts{})
			w.seed()
			cookie, vid := v82accessCookie(t, w, w.li())
			if st := v82accessCookieReads(t, w, vid, cookie); st != 0 {
				t.Fatalf("the cookie before the change: %d", st)
			}
			w.patchConfig("matches", patch)
			if st := v82accessCookieReads(t, w, vid, cookie); st != 403 {
				t.Fatalf("the cookie after the change: %d, want 403", st)
			}
		})
	}
}

// §7.9 view (v0.87): a cookie a change ended is 403 at every URL, an at
// from before the change included; one from an exchange after the change
// isn't ended, and reads at every at, the earlier one included, each
// revision judged by its own rules. The cookie from before keeps its own
// record (v0.86, filtered_view_exps): no exchange revives it. (Before
// v0.87 a cookie was judged at the URL's at, so the ended one read on at
// the earlier at, and the new one was 403 there.)
func TestV082AccessGSEntryPerAt(t *testing.T) {
	t.Parallel()
	w := newV75World(t, v75Opts{})
	w.seed()
	cookie, vid := v82accessCookie(t, w, w.li())
	old, st := v76fRedirect(t, w, "matches", vid, cookie)
	if old == nil {
		t.Fatalf("before: %d", st)
	}
	w.patchConfig("matches", v82accessOp("add", "/keys/1/rate", map[string]any{"rate": 50.0, "burst": 50.0}))
	if _, st := v76fHeads(t, w, "matches", vid, old.At, cookie); st != 403 {
		t.Fatalf("the earlier at before a new exchange: %d, want 403", st)
	}
	v82accessLater(w, time.Second)
	cookie2, _ := v82accessCookie(t, w, w.li())
	if st := v82accessCookieReads(t, w, vid, cookie2); st != 0 {
		t.Fatalf("the new cookie at the current checkpoint: %d", st)
	}
	if _, st := v76fHeads(t, w, "matches", vid, old.At, cookie2); st != 0 {
		t.Fatalf("the earlier at under the new cookie: %d, want it served", st)
	}
	if _, st := v76fHeads(t, w, "matches", vid, old.At, cookie); st != 403 {
		t.Fatalf("the earlier at under the earlier cookie, after the new exchange: %d, want 403", st)
	}
	if st := v82accessCookieReads(t, w, vid, cookie); st != 403 {
		t.Fatalf("the current at under the earlier cookie: %d, want 403", st)
	}
}

// Stored data (stored.md, core migration 017): a record from before the
// upgrade has entry ”, which never holds. Its cookie is 403 until the
// reader exchanges again; a view the origin keeps nothing for stays 401
// (§7.9 view). Since v0.86 the entry is in the cookie's own record
// (filtered_view_exps).
func TestV082AccessGSStoredWithoutEntry(t *testing.T) {
	t.Parallel()
	w := newV75World(t, v75Opts{})
	w.seed()
	ctx := context.Background()
	cookie, vid := v82accessCookie(t, w, w.li())
	if err := w.e.update(ctx, func(t2 *tx) error {
		_, err := t2.Exec(`UPDATE filtered_view_exps SET entry = '' WHERE ns = ? AND view = ?`, "matches", vid)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if st := v82accessCookieReads(t, w, vid, cookie); st != 403 {
		t.Fatalf("a row without an entry digest: %d, want 403", st)
	}
	if _, _, err := w.e.FilteredLiveLog(ctx, "matches", vid, "", 100, cookie); v75Status(err) != 403 {
		t.Fatalf("long-poll under a row without an entry digest: %v, want 403", err)
	}
	// The grant itself still reads: only the cookie's record is short.
	if names, _ := v081Heads(t, w, w.li()); len(names) == 0 {
		t.Fatal("li's grant reads nothing")
	}
	v82accessLater(w, time.Second)
	cookie2, _ := v82accessCookie(t, w, w.li())
	if st := v82accessCookieReads(t, w, vid, cookie2); st != 0 {
		t.Fatalf("after exchanging again: %d", st)
	}
	// A record without an entry digest is shared by no exchange: the
	// cookie from before stays 403.
	if st := v82accessCookieReads(t, w, vid, cookie); st != 403 {
		t.Fatalf("the cookie of the row without an entry digest, after another exchange: %d, want 403", st)
	}
	if err := w.e.update(ctx, func(t2 *tx) error {
		_, err := t2.Exec(`DELETE FROM filtered_views WHERE ns = ? AND view = ?`, "matches", vid)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if st := v82accessCookieReads(t, w, vid, cookie2); st != 401 {
		t.Fatalf("a vid with no row: %d, want 401", st)
	}
}

// The window between a narrowing and the next exchange, for readers who
// share a view: bo and cy, both in editors through reader-01, have one view
// and so one filtered_views row (§7.9 view: "The origin keeps, per namespace
// and view ..."), and a cookie names its prefix and expiry alone (§C.5.3).
// The key's attrs scope is narrowed to cy's alone (a sub scope would give
// each her own view, §B.11.5):
//
//   - bo's cookie is 403 at once, and bo can't exchange again (the key's
//     scope refuses the grant);
//   - nothing is served under the old record in between;
//   - once cy exchanges, the row is the new document's, and bo's cookie
//     stays 403 until it expires, /heads and long-poll alike: bo hasn't
//     exchanged again ("until the reader exchanges again"), and a cookie
//     never reads where its grant couldn't. The origin tells the cookies
//     apart by their expiry: each second's cookies have their own record
//     (filtered_view_exps), and an exchange whose cookie must differ from
//     the one a second holds takes an earlier second (recordFilteredView;
//     §C.5.2, v0.86);
//   - so cy's cookie from the same second as the last one before the
//     change, or from the grant she held before, reads (before v0.86,
//     told apart by "expires no later", those were refused with bo's);
//   - a change made and undone revives nothing either.
func TestV082AccessGSEntrySharedRow(t *testing.T) {
	t.Parallel()
	w := newV75World(t, v75Opts{})
	w.seed()
	ctx := context.Background()
	reader := func(sub string) Credentials {
		return w.catGrant(sub, []any{"editors"}, map[string]any{"attrs": map[string]any{"desk": sub}})
	}
	boGrant := reader("user:bo")
	boCookie, vid := v82accessCookie(t, w, boGrant)
	cyGrant := reader("user:cy")
	cyOld, cyView := v82accessCookie(t, w, cyGrant)
	if cyView != vid {
		t.Fatalf("bo and cy have different vid: %s, %s", vid, cyView)
	}
	reads := func(what string, cookie Credentials, want int) {
		t.Helper()
		if st := v82accessCookieReads(t, w, vid, cookie); st != want {
			t.Errorf("%s, /heads at the current checkpoint: status %d (0 = served), want %d", what, st, want)
		}
		if _, _, err := w.e.FilteredLiveLog(ctx, "matches", vid, "", 10, cookie); v75Status(err) != want {
			t.Errorf("%s, long-poll: %v, want %d (0 = served)", what, err, want)
		}
	}
	reads("bo's cookie before the change", boCookie, 0)
	w.patchConfig("matches", v82accessOp("add", "/keys/1/attrs", map[string]any{"properties": map[string]any{"desk": map[string]any{"const": "user:cy"}}}))
	reads("bo's cookie after the key's attrs were narrowed", boCookie, 403)
	// bo's grant itself reads nothing any more, and exchanges for nothing.
	if _, err := w.e.NamespaceLog(ctx, "matches", "", "", 10, boGrant); v75Status(err) != 403 {
		t.Fatalf("bo's grant after the change: %v, want 403", err)
	}
	if res, err := w.e.IssueEdgeGrants(ctx, []string{reader("user:bo").Bearer}); err == nil && len(res.Grants) != 0 {
		t.Fatalf("bo exchanged again under a key that refuses bo: %+v", res)
	}
	reads("bo's cookie after bo's refused exchange", boCookie, 403)

	// cy exchanges within the second of the last exchange before the
	// change, and then the grant she held before, which ends with the
	// cookies from before: her cookies expire a second before those they
	// must be told apart from, and read; bo's stays ended.
	sameSecond, _ := v82accessCookie(t, w, reader("user:cy"))
	if !sameSecond.Edge.Exp.Before(boCookie.Edge.Exp) {
		t.Errorf("cy's cookie from the same second expires %v, bo's ended one %v: want it earlier", sameSecond.Edge.Exp, boCookie.Edge.Exp)
	}
	reads("cy's cookie from the same second", sameSecond, 0)
	reads("bo's cookie after cy's same-second exchange", boCookie, 403)
	v82accessLater(w, time.Second)
	sameGrant, _ := v82accessCookie(t, w, cyGrant)
	reads("cy's cookie from the grant she held before", sameGrant, 0)
	reads("bo's cookie after cy's exchange of her earlier grant", boCookie, 403)

	// cy, not bo, exchanges a grant from after the change.
	cyCookie, cyView := v82accessCookie(t, w, reader("user:cy"))
	if cyView != vid {
		t.Fatalf("cy's vid after the change %s, was %s", cyView, vid)
	}
	reads("cy's cookie after exchanging again", cyCookie, 0)
	reads("bo's old cookie after cy's exchange", boCookie, 403)
	reads("cy's own cookie from before the change", cyOld, 403)

	// The change is undone: the record is the narrowed document's, so
	// every cookie is 403; after cy's next exchange the entry digest is
	// the first one again, and bo's cookie from under it stays ended.
	w.patchConfig("matches", map[string]any{"op": "remove", "path": "/keys/1/attrs"})
	reads("bo's old cookie after the change was undone", boCookie, 403)
	reads("cy's cookie after the change was undone", cyCookie, 403)
	v82accessLater(w, time.Second)
	cyCookie2, _ := v82accessCookie(t, w, reader("user:cy"))
	// The cookies' own records: bo's from before the change and cy's
	// from after the undo carry the same entry digest, under different
	// documents, and cy's from the narrowed document another.
	slotOf := func(c Credentials) (s viewSlot) {
		w.inTx(func(t2 *tx) {
			var ok bool
			if s, ok = t2.loadViewSlot("matches", vid, c.Edge.Exp.Unix()); !ok {
				t.Errorf("no record for the cookie expiring %v", c.Edge.Exp)
			}
		})
		return s
	}
	first := slotOf(boCookie)
	if now := slotOf(cyCookie2); now.entry != first.entry || now.conf <= first.conf || slotOf(cyCookie).entry == first.entry {
		t.Errorf("records: before the change %+v, under the narrowed document %+v, after the undo %+v", first, slotOf(cyCookie), now)
	}
	reads("cy's cookie after the undoing and her exchange", cyCookie2, 0)
	reads("bo's old cookie after the undoing and cy's exchange", boCookie, 403)
	reads("cy's cookie from the narrowed document", cyCookie, 403)

	// An exchange under the same entry replaces nothing: the earlier
	// cookie of that entry reads on. bo exchanges again, and reads.
	v82accessLater(w, time.Second)
	boCookie2, _ := v82accessCookie(t, w, reader("user:bo"))
	reads("bo's cookie after bo exchanged again", boCookie2, 0)
	reads("cy's cookie after bo's exchange under the same entry", cyCookie2, 0)
	if got := slotOf(boCookie); got != first {
		t.Errorf("the record of bo's ended cookie after later exchanges: %+v, was %+v", got, first)
	}
	// bo's old cookie is 403 to its last second.
	w.clock.Store(boCookie.Edge.Exp.Add(-time.Second).UnixMilli())
	reads("bo's old cookie in its last second", boCookie, 403)
}

// A cookie without an expiry, which the server never mints, is refused
// (v0.86: a cookie is judged from the record of its own expiry, and it
// has none; before, it read until a record was replaced), and a cookie
// for /ns/{ns}, which covers a view's URLs too, is held to the same expiry
// as one for the view would be.
func TestV082AccessGSEntryAfterOtherCookies(t *testing.T) {
	t.Parallel()
	w := newV75World(t, v75Opts{})
	w.seed()
	cookie, vid := v82accessCookie(t, w, w.li())
	wide := func(exp time.Time) Credentials {
		return Credentials{Edge: &EdgeGrant{NS: "matches", Prefix: "/ns/matches", Exp: exp}}
	}
	noExp := Credentials{Edge: &EdgeGrant{NS: "matches", View: vid, Prefix: "/ns/matches/view/" + vid}}
	wideOld := wide(cookie.Edge.Exp)
	if st := v82accessCookieReads(t, w, vid, wideOld); st != 0 {
		t.Fatalf("a cookie for /ns/matches, before any change: %d", st)
	}
	if st := v82accessCookieReads(t, w, vid, noExp); st != 403 {
		t.Fatalf("a cookie without an expiry, before any change: %d, want 403", st)
	}
	w.patchConfig("matches", v82accessOp("add", "/keys/1/rate", map[string]any{"rate": 50.0, "burst": 50.0}))
	v82accessLater(w, time.Second)
	cookie2, _ := v82accessCookie(t, w, w.li())
	if st := v82accessCookieReads(t, w, vid, cookie2); st != 0 {
		t.Fatalf("the new cookie: %d", st)
	}
	if st := v82accessCookieReads(t, w, vid, noExp); st != 403 {
		t.Errorf("a cookie without an expiry, after the record was replaced: %d, want 403", st)
	}
	// An unrestricted reader's /ns/{ns} cookie reads there as at its own
	// URLs, not as the view's (§7.9 Partial reader).
	if st := v82accessCookieReads(t, w, vid, wideOld); st != 0 {
		t.Errorf("a cookie for /ns/matches, from before, after the record was replaced: %d, want 0", st)
	}
	if st := v82accessCookieReads(t, w, vid, wide(cookie2.Edge.Exp)); st != 0 {
		t.Errorf("a cookie for /ns/matches that expires with the new one: %d", st)
	}
}

// EntryDigest's definition (design §5), pinned on a fixed input so that
// the index's own code (edge_gs_keys.entry) can be compared with it:
// text(trunc160(sha256(canonical({ "key": K, "roles": R })))).
func TestV082AccessEntryDigestVector(t *testing.T) {
	t.Parallel()
	key := map[string]any{"kid": "reader-01", "alg": "ed25519", "pub": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		"can": []any{"read"}, "maxTtl": "PT15M",
		"rules": []any{map[string]any{"op": "test", "path": "/resource", "schema": map[string]any{"type": "string"}}}}
	roles := map[string]any{"reader": map[string]any{"can": []any{"read"}}}
	for _, c := range []struct {
		what  string
		roles map[string]any
		want  string
	}{
		{"one role", roles, "1tm77qzwtfacpjdi6gn2z4qpyvngm6vlb"},
		{"no roles", map[string]any{}, "1irlyte76oluqesl6gq2yhlv5d6dezqa6"},
		{"nil roles, as {}", nil, "1irlyte76oluqesl6gq2yhlv5d6dezqa6"},
	} {
		if got := entryDigest(key, c.roles); got != c.want {
			t.Errorf("%s: %s, want %s", c.what, got, c.want)
		}
	}
}
