package server

import (
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"testing"

	"github.com/middle-management/patchlog/internal/schema"
)

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
// Legacy, is mirrored as Legacy, and B serves the mirror as legacy. Since
// v0.74 the marker selects nothing: B validates under the revision as
// every schema compiles now, idn-email asserted (§6.1).
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
			if r.Code != 422 || r.Str("code") != "invalid" {
				t.Errorf("B under a revision its base serves as %q: %d %s, want 422 invalid (idn-email asserted whatever the marker)", served, r.Code, r.Body)
			}
			if r := b.get("/r/schemas/mail/rev/" + s); r.H.Get(schema.RulesHeader) != "legacy" {
				t.Errorf("B's mirror: %s %q, want legacy", schema.RulesHeader, r.H.Get(schema.RulesHeader))
			}
		})
	}
}
