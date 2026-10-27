package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/archive"
	"github.com/middle-management/patchlog/internal/schema"
	"github.com/middle-management/patchlog/internal/seal"
)

// W3X (P29 x P34 x P26; §8.6, §D.4, Addendum E Levels): a namespace raised
// from none to e2e keeps its pre-raise history in the clear. Restoring it
// must check each archived entry by the level its revision was written at,
// not the namespace's current one: a plain archive written by a prune
// before the raise, and the sealed bundle an E3 prune writes after it, of
// a history that is plaintext before the raise and sealed ops after it,
// both come back whole and clear the horizon.
func TestW3XRaisedE2EArchiveRestores(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	dir := t.TempDir()
	e := newEnv(t, withArchive(t, dir), withoutRetentionLoop, withKeyStore(newKeyStore(t)))
	e.mkNS("rz", map[string]any{"read": "public"})
	revs := e.chain("rz", "d", 4)
	// p is pruned before the raise: a plain archive.
	prevs := e.chain("rz", "p", 4)
	e.clock.Advance(10 * time.Minute)
	expect(t, e.prune("rz", "p", map[string]any{"horizon": prevs[2]}, "admin"), 200)
	expect(t, e.patchNS("rz", ops(op("add", "/encryption", map[string]any{"level": "e2e", "epoch": 1.0})), ""), 201)
	preps, err := archive.Restore(ctx, e.e, archive.RestoreOptions{NS: "rz", Name: "p"})
	if err != nil {
		t.Fatal(err)
	}
	if len(preps) != 1 || preps[0].Restored != 2 || preps[0].Skipped != 0 || !preps[0].Cleared {
		t.Errorf("restore of a plain archive written before the raise to e2e: %+v, want 2 restored and the horizon cleared", preps)
	}
	if r := e.get("/r/rz/p/rev/" + prevs[0]); r.Code == 410 {
		t.Errorf("p's first revision after the restore: %d %s", r.Code, r.Body)
	}
	// d gets two sealed revisions after the raise, then an E3 prune to the
	// last archives four plaintext patch sets and one sealed op.
	k := seal.NewKey()
	for i := 4; i < 6; i++ {
		r := e.writeAs("rz", "d", revs[i-1], sealed(t, k, "rz#1", "rz", "d", revs[i-1], ops(op("replace", "/n", float64(i)))), "alice")
		expect(t, r, 201)
		revs = append(revs, etagOf(r))
	}
	e.clock.Advance(10 * time.Minute)
	snap, err := seal.SealSnapshot(k, "rz#1", "rz", "d", revs[5], map[string]any{"n": 5.0})
	if err != nil {
		t.Fatal(err)
	}
	expect(t, e.prune("rz", "d", map[string]any{"horizon": revs[5], "snapshot": snap}, "admin"), 200)
	expect(t, e.get("/r/rz/d/rev/"+revs[0]), 410)
	reps, err := archive.Restore(ctx, e.e, archive.RestoreOptions{NS: "rz", Name: "d"})
	if err != nil {
		t.Fatal(err)
	}
	if len(reps) != 1 || len(reps[0].Failed) != 0 || reps[0].Restored != 5 || reps[0].Skipped != 0 || !reps[0].Cleared {
		t.Fatalf("restore of a pre- and post-raise history archived by an E3 prune: %+v, want 5 restored and the horizon cleared", reps)
	}
	for _, id := range []string{revs[0], revs[4]} {
		if r := e.get("/r/rz/d/rev/" + id); r.Code == 410 {
			t.Errorf("d's revision %s after the restore: %d %s", id, r.Code, r.Body)
		}
	}
}

// W3X (P27 x remote branches; CIS-17, §6.1, §G.3, F-S1): a schema A writes
// now compiles under today's rules there (idn-email asserted), and B's
// remote branch validates its own writes with its mirror of that revision
// (§G.3), so the mirror keeps A's marker: the same revision path judges a
// document alike on both. A serves the marker with a schema revision
// (schema.RulesHeader), and B serves its mirror with the same one.
func TestW3XRemoteMirrorKeepsRulesMarker(t *testing.T) {
	t.Parallel()
	a, b, _ := pair(t, nil, nil)
	a.mkNS("schemas", map[string]any{"read": "public"})
	s := a.create("schemas", "mail", map[string]any{"$schema": dialect, "type": "object",
		"properties": map[string]any{"e": map[string]any{"type": "string", "format": "idn-email"}}})
	if r := a.get("/r/schemas/mail/rev/" + s); r.H.Get(schema.RulesHeader) != "v0.73" {
		t.Fatalf("A's schema revision written now: %s %q, want v0.73", schema.RulesHeader, r.H.Get(schema.RulesHeader))
	}
	a.mkNS("main", map[string]any{"read": "public"})
	x := a.create("main", "x", map[string]any{"$schema": "/r/schemas/mail/rev/" + s, "e": "a@b.example"})
	if r := a.get("/r/main/x/rev/" + x); r.H.Get(schema.RulesHeader) != "" {
		t.Errorf("a typed document, which isn't a schema: %s %q", schema.RulesHeader, r.H.Get(schema.RulesHeader))
	}
	bad := map[string]any{"$schema": "/r/schemas/mail/rev/" + s, "e": "not an email"}
	expect(t, a.write("PATCH", "main", "y", "", addRoot(bad)), 422)
	expect(t, b.mkRemote("rel", remoteGenesis("main", a.nsHead("main"), nil)), 201)
	if r := b.write("PATCH", "rel", "y", "", addRoot(bad)); r.Code != 422 {
		t.Fatalf("B's remote branch took a document A refuses under the same schema revision %s: %d %s", s, r.Code, r.Body)
	}
	expect(t, b.write("PATCH", "rel", "y", "", addRoot(map[string]any{"$schema": "/r/schemas/mail/rev/" + s, "e": "c@d.example"})), 201)
	if r := b.get("/r/schemas/mail/rev/" + s); r.Code != 200 || r.H.Get(schema.RulesHeader) != "v0.73" {
		t.Errorf("B's mirror of the revision: %d %s %q, want v0.73", r.Code, schema.RulesHeader, r.H.Get(schema.RulesHeader))
	}
}

// W3X: a base that serves a schema revision as Legacy, or sends no
// marker, as a server from before markers compiles every schema as
// Legacy, is mirrored as Legacy: B then validates under the revision as
// such a base does (idn-email not asserted), and serves the mirror as
// legacy.
func TestW3XRemoteMirrorLegacyMarker(t *testing.T) {
	t.Parallel()
	for _, served := range []string{"legacy", ""} {
		t.Run("served="+served, func(t *testing.T) {
			t.Parallel()
			a, b, rt := pair(t, nil, nil)
			u, err := url.Parse(a.srv.URL)
			if err != nil {
				t.Fatal(err)
			}
			// What B reads from A passes through a proxy that serves every
			// schema revision with the marker served.
			p := httputil.NewSingleHostReverseProxy(u)
			p.ModifyResponse = func(r *http.Response) error {
				if r.Header.Get(schema.RulesHeader) != "" {
					if served == "" {
						r.Header.Del(schema.RulesHeader)
					} else {
						r.Header.Set(schema.RulesHeader, served)
					}
				}
				return nil
			}
			proxy := httptest.NewServer(p)
			t.Cleanup(proxy.Close)
			rt.set(proxy.URL, "")
			a.mkNS("schemas", map[string]any{"read": "public"})
			s := a.create("schemas", "mail", map[string]any{"$schema": dialect, "type": "object",
				"properties": map[string]any{"e": map[string]any{"type": "string", "format": "idn-email"}}})
			a.mkNS("main", map[string]any{"read": "public"})
			a.create("main", "x", map[string]any{"$schema": "/r/schemas/mail/rev/" + s, "e": "a@b.example"})
			expect(t, b.mkRemote("rel", remoteGenesis("main", a.nsHead("main"), nil)), 201)
			r := b.write("PATCH", "rel", "y", "", addRoot(map[string]any{"$schema": "/r/schemas/mail/rev/" + s, "e": "not an email"}))
			if r.Code != 201 {
				t.Errorf("B under a revision its base serves as %q: %d %s, want 201 (idn-email not asserted, as under Legacy)", served, r.Code, r.Body)
			}
			if r := b.get("/r/schemas/mail/rev/" + s); r.H.Get(schema.RulesHeader) != "legacy" {
				t.Errorf("B's mirror: %s %q, want legacy", schema.RulesHeader, r.H.Get(schema.RulesHeader))
			}
		})
	}
}

// W3X (P27 x P29; §6.1 "Purged or unknown references", Read permission;
// Addendum E Levels): a schema revision written before its namespace was
// raised from none to e2e is stored in the clear and stays readable to the
// server, so documents elsewhere that pin it keep validating; only a
// revision written while the namespace is e2e is schema_unavailable.
func TestW3XRaisedSchemaNamespaceStillResolves(t *testing.T) {
	t.Parallel()
	e := newEnv(t, withKeyStore(newKeyStore(t)))
	e.mkNS("sch", map[string]any{"read": "public"})
	s := e.create("sch", "m", matchSchema())
	e.mkNS("docs", map[string]any{"read": "public"})
	d := e.create("docs", "d", map[string]any{"$schema": "/r/sch/m/rev/" + s, "score": "1-0"})
	expect(t, e.patchNS("sch", ops(op("add", "/encryption", map[string]any{"level": "e2e", "epoch": 1.0})), ""), 201)
	if w := e.write("PATCH", "docs", "d", d, ops(op("replace", "/score", "2-0"))); w.Code != 201 {
		t.Fatalf("a document typed by a pre-raise schema revision after its namespace became e2e: %d %s", w.Code, w.Body)
	}
	// Still validated against it.
	expectCode(t, e.write("PATCH", "docs", "x", "", addRoot(map[string]any{"$schema": "/r/sch/m/rev/" + s, "score": 3.0})), 422, "invalid")
	// A revision written at e2e, which the server can't read, doesn't
	// resolve.
	k := seal.NewKey()
	r := e.writeAs("sch", "m", s, sealed(t, k, "sch#1", "sch", "m", s, ops(op("replace", "/title", "sealed"))), "alice")
	expect(t, r, 201)
	after := etagOf(r)
	w := e.write("PATCH", "docs", "y", "", addRoot(map[string]any{"$schema": "/r/sch/m/rev/" + after, "score": "1-0"}))
	expectCode(t, w, 422, "schema_unavailable")
}
