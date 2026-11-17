package grantcheck_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/grant"
	"github.com/middle-management/patchlog/internal/grantcheck"
	"github.com/middle-management/patchlog/internal/keystore"
)

// Grant scope 77 (§C.4 requireAt, v0.85): "The grant fails the scope
// (403) ... where requireAt names a purged namespace, which a service
// learns from its log or 410 (§8.5)". A key of sec names an unsealed
// catalog, whose document and log are still served once it is purged, and
// another a sealed one, whose every URL is 410 then: a grant at either's
// head verifies while it lives, and is refused 403 with the one text of a
// rejected at once it is purged, by a checker that held its state before
// and by one that starts after, at the head it read under and at the
// purge-ns entry. Before v0.85 the unsealed one's grant still verified
// and the sealed one's was a chain the checker can't read (502).
func TestV085RequireAtPurgedNamespace(t *testing.T) {
	ctx := context.Background()
	ks, err := keystore.New(keystore.Generate())
	if err != nil {
		t.Fatal(err)
	}
	s := clienttest.New(t, clienttest.Options{Auth: true, KeyStore: ks})
	admin := clienttest.NewKey("admin")
	keys := map[string]clienttest.Key{}
	docs := map[string]map[string]any{
		"old-plain":  {"read": "grant", "keys": []any{admin.Entry("*")}},
		"old-sealed": {"read": "grant", "keys": []any{admin.Entry("*")}, "encryption": map[string]any{"level": "sealed"}},
	}
	sec := []any{admin.Entry("*")}
	for ns := range docs {
		k := clienttest.NewKey("at-" + ns)
		e := k.Entry("read")
		e["requireAt"] = ns
		keys[ns], sec = k, append(sec, e)
	}
	docs["sec"] = map[string]any{"read": "grant", "keys": sec}
	nss := []string{"sec", "old-plain", "old-sealed"}
	for ns, cfg := range docs {
		must(s.Client(t, client.WithBearer(s.OperatorGrant(t, ns))).CreateNamespace(ctx, ns, cfg))
	}
	adminC := s.Client(t, client.WithBearer(admin.Grant(t, s.Now(), "user:root", nss, []string{"read", "create", "append", "config", "purge-ns"})), client.WithKeys(client.NewKeys(nil)))
	checker := func() *grantcheck.Checker {
		g := admin.Grant(t, s.Now(), "svc:index", nss, []string{"read"})
		return grantcheck.New(s.Client(t, client.WithBearer(g), client.WithKeys(client.NewKeys(nil))), grantcheck.WithClock(s.Now), grantcheck.WithTTL(0))
	}
	grantAt := func(ns, at string) string {
		return keys[ns].Grant(t, s.Now(), "user:li", []string{"sec"}, []string{"read"}, map[string]any{"at": map[string]any{"ns": ns, "id": at}, "nbf": s.Now().Format(time.RFC3339)})
	}
	for _, ns := range []string{"old-plain", "old-sealed"} {
		held := checker()
		before := must(adminC.NSHead(ctx, ns)).ID
		live := grantAt(ns, before)
		if _, err := held.Verify(ctx, "sec", live); err != nil {
			t.Fatalf("%s live: %v", ns, err)
		}
		h := must(adminC.NSHead(ctx, ns))
		must(adminC.PatchConfig(ctx, ns, h.Config, []any{map[string]any{"op": "add", "path": "/frozen", "value": true}}))
		frozen := must(adminC.NSHead(ctx, ns)).ID
		if _, err := held.Verify(ctx, "sec", grantAt(ns, frozen)); err != nil {
			t.Fatalf("%s frozen, not purged: %v", ns, err)
		}
		purge := must(adminC.PurgeNamespace(ctx, ns, frozen))
		for cn, ch := range map[string]*grantcheck.Checker{"a checker from before": held, "a new checker": checker()} {
			for an, tok := range map[string]string{"the grant that verified": live, "at the frozen head": grantAt(ns, frozen), "at the purge-ns entry": grantAt(ns, purge)} {
				_, err := ch.Verify(ctx, "sec", tok)
				var ae *grant.AuthError
				if !errors.As(err, &ae) || ae.Status != 403 || ae.Msg != grant.RequireAtRefusal {
					t.Errorf("%s purged, %s, %s: %v, want 403 %q", ns, cn, an, err, grant.RequireAtRefusal)
				}
			}
		}
	}
}
