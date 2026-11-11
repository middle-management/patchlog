package core

import (
	"context"
	"testing"
	"time"
)

// V82-02 (v0.82), ACC-14: a gs cookie ends when the key its key: string
// names, or a key or role its rules came from, is gone or changes in any
// member (SERVICES §B.11.9 gs).

// v82accessCookie exchanges cred and returns the cookie of its /g/ prefix
// in matches, with its gs.
func v82accessCookie(t *testing.T, w *v75World, cred Credentials) (Credentials, string) {
	t.Helper()
	res, err := w.e.IssueEdgeGrants(context.Background(), []string{cred.Bearer})
	if err != nil || len(res.Grants) != 1 || res.Grants[0].GS == "" {
		t.Fatalf("exchange: %+v %v", res, err)
	}
	g := res.Grants[0]
	return Credentials{Edge: &EdgeGrant{NS: g.NS, GS: g.GS, Prefix: "/ns/" + g.NS + "/g/" + g.GS, Exp: w.now().Add(10 * time.Minute)}}, g.GS
}

// v82accessCookieReads is the status of cookie's read of matches' filtered
// /heads for gs at the current checkpoint: 0 where it is served.
func v82accessCookieReads(t *testing.T, w *v75World, gs string, cookie Credentials) int {
	t.Helper()
	red, st := v76fRedirect(t, w, "matches", gs, cookie)
	if red == nil {
		return st
	}
	_, st = v76fHeads(t, w, "matches", gs, red.At, cookie)
	return st
}

func v82accessOp(op, path string, value any) map[string]any {
	return map[string]any{"op": op, "path": path, "value": value}
}

// §B.11.9 gs (v0.82): "A gs cookie is 403 at an at where those rules
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
		"the key's maxLag":   v82accessOp("add", "/keys/1/maxLag", "PT50S"),
		"the key's can":      v82accessOp("replace", "/keys/1/can", []any{"read", "append"}),
		"the role's can":     v82accessOp("replace", "/roles/reader/can", []any{"read", "append"}),
		"the role's x-label": v82accessOp("add", "/roles/reader/x-label", "Readers"),
	}
	keeps := map[string]map[string]any{
		"another key's member": v82accessOp("add", "/keys/0/maxTtl", "PT2H"),
		"another role":         v82accessOp("add", "/roles/other", map[string]any{"can": []any{"read", "append"}}),
		"a limit":              v82accessOp("add", "/maxLag", "PT55S"),
	}
	for name, patch := range ends {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			w := newV75World(t, v75Opts{})
			w.seed()
			cookie, gs := v82accessCookie(t, w, w.li())
			if st := v82accessCookieReads(t, w, gs, cookie); st != 0 {
				t.Fatalf("the cookie before the change: %d", st)
			}
			var before string
			w.inTx(func(t2 *tx) { before = t2.loadGS("matches", gs).entry })
			if before == "" {
				t.Fatal("the exchange recorded no entry digest")
			}
			w.patchConfig("matches", patch)
			if st := v82accessCookieReads(t, w, gs, cookie); st != 403 {
				t.Fatalf("the cookie after the change: %d, want 403", st)
			}
			// Long-poll judges it at the current checkpoint.
			if _, _, err := w.e.FilteredLiveLog(context.Background(), "matches", gs, "", 100, cookie); v75Status(err) != 403 {
				t.Fatalf("long-poll under the cookie after the change: %v, want 403", err)
			}
			// Until the reader exchanges again: the same gs (none of
			// these members is in it), a new record.
			cookie2, gs2 := v82accessCookie(t, w, w.li())
			if gs2 != gs {
				t.Fatalf("gs after the change %s, was %s", gs2, gs)
			}
			if st := v82accessCookieReads(t, w, gs, cookie2); st != 0 {
				t.Fatalf("the cookie after exchanging again: %d", st)
			}
			w.inTx(func(t2 *tx) {
				if after := t2.loadGS("matches", gs).entry; after == "" || after == before {
					t.Fatalf("entry digest after the change %q, before %q", after, before)
				}
			})
			if _, _, err := w.e.FilteredLiveLog(context.Background(), "matches", gs, "", 100, cookie2); err != nil {
				t.Fatalf("long-poll after exchanging again: %v", err)
			}
		})
	}
	for name, patch := range keeps {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			w := newV75World(t, v75Opts{})
			w.seed()
			cookie, gs := v82accessCookie(t, w, w.li())
			w.patchConfig("matches", patch)
			if st := v82accessCookieReads(t, w, gs, cookie); st != 0 {
				t.Fatalf("the cookie after an unrelated change: %d", st)
			}
		})
	}
}

// §B.11.9 gs: the answers at an at from before the change are the ones
// its document gave, so the old cookie still reads there, as a changed
// rule leaves it (immutable answers, §B.5); once the reader has exchanged
// again, her record is the new document's and the earlier at is 403 for
// it.
func TestV082AccessGSEntryPerAt(t *testing.T) {
	t.Parallel()
	w := newV75World(t, v75Opts{})
	w.seed()
	cookie, gs := v82accessCookie(t, w, w.li())
	old, st := v76fRedirect(t, w, "matches", gs, cookie)
	if old == nil {
		t.Fatalf("before: %d", st)
	}
	w.patchConfig("matches", v82accessOp("add", "/keys/1/maxLag", "PT50S"))
	if _, st := v76fHeads(t, w, "matches", gs, old.At, cookie); st != 0 {
		t.Fatalf("the earlier at before a new exchange: %d", st)
	}
	cookie2, _ := v82accessCookie(t, w, w.li())
	if _, st := v76fHeads(t, w, "matches", gs, old.At, cookie2); st != 403 {
		t.Fatalf("the earlier at under the new record: %d, want 403", st)
	}
}

// Stored data (stored.md, core migration 017): a filtered_gs row from
// before the upgrade has entry ”, which never holds. Its cookie is 403
// until the reader exchanges again; a gs the origin keeps nothing for
// stays 401 (§B.11.9 gs).
func TestV082AccessGSStoredWithoutEntry(t *testing.T) {
	t.Parallel()
	w := newV75World(t, v75Opts{})
	w.seed()
	ctx := context.Background()
	cookie, gs := v82accessCookie(t, w, w.li())
	if err := w.e.update(ctx, func(t2 *tx) error {
		_, err := t2.Exec(`UPDATE filtered_gs SET entry = '' WHERE ns = ? AND gs = ?`, "matches", gs)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if st := v82accessCookieReads(t, w, gs, cookie); st != 403 {
		t.Fatalf("a row without an entry digest: %d, want 403", st)
	}
	if _, _, err := w.e.FilteredLiveLog(ctx, "matches", gs, "", 100, cookie); v75Status(err) != 403 {
		t.Fatalf("long-poll under a row without an entry digest: %v, want 403", err)
	}
	// The grant itself still reads: only the cookie's record is short.
	if names, _ := v081Heads(t, w, w.li()); len(names) == 0 {
		t.Fatal("li's grant reads nothing")
	}
	cookie2, _ := v82accessCookie(t, w, w.li())
	if st := v82accessCookieReads(t, w, gs, cookie2); st != 0 {
		t.Fatalf("after exchanging again: %d", st)
	}
	if err := w.e.update(ctx, func(t2 *tx) error {
		_, err := t2.Exec(`DELETE FROM filtered_gs WHERE ns = ? AND gs = ?`, "matches", gs)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if st := v82accessCookieReads(t, w, gs, cookie2); st != 401 {
		t.Fatalf("a gs with no row: %d, want 401", st)
	}
}

// The window between a narrowing and the next exchange, for readers who
// share a gs: bo and cy, both in editors through catalog-01, have one gs
// and so one filtered_gs row (§B.11.9 gs: "The origin keeps, per namespace
// and gs ..."). The key's attrs scope is narrowed to cy's alone (a sub
// scope would give each her own gs, §B.11.5):
//
//   - bo's cookie is 403 at once, and bo can't exchange again (the key's
//     scope refuses the grant);
//   - nothing is served under the old record in between;
//   - once cy exchanges, the row is the new document's, and a cookie for
//     that gs is served again, bo's old one included until it expires
//     (15 minutes at most, §C.5.2): a cookie names its prefix alone
//     (§C.5.3), so the origin can't tell whose it is. It shows only what
//     that gs sees, which is what cy's shows.
func TestV082AccessGSEntrySharedRow(t *testing.T) {
	t.Parallel()
	w := newV75World(t, v75Opts{})
	w.seed()
	ctx := context.Background()
	reader := func(sub string) Credentials {
		return w.catGrant(sub, []any{"editors"}, map[string]any{"attrs": map[string]any{"desk": sub}})
	}
	boCookie, gs := v82accessCookie(t, w, reader("user:bo"))
	if _, cyGS := v82accessCookie(t, w, reader("user:cy")); cyGS != gs {
		t.Fatalf("bo and cy have different gs: %s, %s", gs, cyGS)
	}
	w.patchConfig("matches", v82accessOp("add", "/keys/1/attrs", map[string]any{"properties": map[string]any{"desk": map[string]any{"const": "user:cy"}}}))
	if st := v82accessCookieReads(t, w, gs, boCookie); st != 403 {
		t.Fatalf("bo's cookie after the key's attrs were narrowed: %d, want 403", st)
	}
	if res, err := w.e.IssueEdgeGrants(ctx, []string{reader("user:bo").Bearer}); err == nil && len(res.Grants) != 0 {
		t.Fatalf("bo exchanged again under a key that refuses bo: %+v", res)
	}
	if st := v82accessCookieReads(t, w, gs, boCookie); st != 403 {
		t.Fatalf("bo's cookie after bo's refused exchange: %d, want 403", st)
	}
	cyCookie, cyGS := v82accessCookie(t, w, reader("user:cy"))
	if cyGS != gs {
		t.Fatalf("cy's gs after the change %s, was %s", cyGS, gs)
	}
	if st := v82accessCookieReads(t, w, gs, cyCookie); st != 0 {
		t.Fatalf("cy's cookie: %d", st)
	}
	// Pinned, not wanted: see the comment above and the report's feedback.
	if st := v82accessCookieReads(t, w, gs, boCookie); st != 0 {
		t.Fatalf("a cookie for the shared gs after cy's exchange: %d (the origin now tells cookies of one gs apart: update this test)", st)
	}
}

// EntryDigest's definition (design §5), pinned on a fixed input so that
// the index's own code (edge_gs_keys.entry) can be compared with it:
// text(trunc160(sha256(canonical({ "key": K, "roles": R })))).
func TestV082AccessEntryDigestVector(t *testing.T) {
	t.Parallel()
	key := map[string]any{"kid": "catalog-01", "alg": "ed25519", "pub": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		"can": []any{"read"}, "requireAt": "cat-season", "maxTtl": "PT15M",
		"rules": []any{map[string]any{"op": "test", "path": "/resource", "schema": map[string]any{"type": "string"}}}}
	roles := map[string]any{"reader": map[string]any{"can": []any{"read"}}}
	for _, c := range []struct {
		what  string
		roles map[string]any
		want  string
	}{
		{"one role", roles, "1tgoxfk3zovxbwszogjaifs34qebbmbx7"},
		{"no roles", map[string]any{}, "1rdlzgylsx4ico373fnjq5hsd3ekeghxy"},
		{"nil roles, as {}", nil, "1rdlzgylsx4ico373fnjq5hsd3ekeghxy"},
	} {
		if got := entryDigest(key, c.roles); got != c.want {
			t.Errorf("%s: %s, want %s", c.what, got, c.want)
		}
	}
}
