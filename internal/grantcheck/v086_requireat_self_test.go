package grantcheck_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/grant"
	"github.com/middle-management/patchlog/internal/grantcheck"
	"github.com/middle-management/patchlog/internal/keystore"
)

// Access scenario 83 (§C.4 requireAt, §8.5; v0.86): the scope's 403 is
// for a requireAt naming "a purged namespace other than the one the grant
// is checked in". A key of matches with requireAt: "matches", its own
// name, is judged as one with requireAt: true once matches is purged: a
// checker gives both the same answer, at the head they read under and at
// the purge-ns entry, whether it held matches's state before or starts
// after, and never the requireAt refusal. In an unsealed namespace, whose
// document and log stay served, the grant still verifies; a sealed one's
// every URL is 410, which is the answer for both. Before v0.86 the key
// naming its own namespace was refused 403.
func TestV086RequireAtOwnNamespacePurged(t *testing.T) {
	ctx := context.Background()
	ks, err := keystore.New(keystore.Generate())
	if err != nil {
		t.Fatal(err)
	}
	s := clienttest.New(t, clienttest.Options{Auth: true, KeyStore: ks})
	admin := clienttest.NewKey("admin")
	type nsKeys struct{ self, named clienttest.Key }
	keys := map[string]nsKeys{}
	nss := []string{"plain", "sealed"}
	for _, ns := range nss {
		k := nsKeys{clienttest.NewKey("self-" + ns), clienttest.NewKey("named-" + ns)}
		se, ne := k.self.Entry("read"), k.named.Entry("read")
		se["requireAt"], ne["requireAt"] = true, ns
		doc := map[string]any{"read": "grant", "keys": []any{admin.Entry("*"), se, ne}}
		if ns == "sealed" {
			doc["encryption"] = map[string]any{"level": "sealed"}
		}
		keys[ns] = k
		must(s.Client(t, client.WithBearer(s.OperatorGrant(t, ns))).CreateNamespace(ctx, ns, doc))
	}
	adminC := s.Client(t, client.WithBearer(admin.Grant(t, s.Now(), "user:root", nss, []string{"read", "create", "append", "config", "purge-ns"})), client.WithKeys(client.NewKeys(nil)))
	checker := func() *grantcheck.Checker {
		g := admin.Grant(t, s.Now(), "svc:index", nss, []string{"read"})
		return grantcheck.New(s.Client(t, client.WithBearer(g), client.WithKeys(client.NewKeys(nil))), grantcheck.WithClock(s.Now), grantcheck.WithTTL(0))
	}
	grantAt := func(k clienttest.Key, ns, at string) string {
		return k.Grant(t, s.Now(), "user:li", []string{ns}, []string{"read"}, map[string]any{"at": map[string]any{"ns": ns, "id": at}, "nbf": s.Now().Format(time.RFC3339)})
	}
	for _, ns := range nss {
		held := checker()
		before := must(adminC.NSHead(ctx, ns)).ID
		liveSelf, liveNamed := grantAt(keys[ns].self, ns, before), grantAt(keys[ns].named, ns, before)
		for _, tok := range []string{liveSelf, liveNamed} {
			if _, err := held.Verify(ctx, ns, tok); err != nil {
				t.Fatalf("%s live: %v", ns, err)
			}
		}
		h := must(adminC.NSHead(ctx, ns))
		must(adminC.PatchConfig(ctx, ns, h.Config, []any{map[string]any{"op": "add", "path": "/frozen", "value": true}}))
		frozen := must(adminC.NSHead(ctx, ns)).ID
		purge := must(adminC.PurgeNamespace(ctx, ns, frozen))
		// answer is what a checker says of a grant, as a caller sees it.
		answer := func(ch *grantcheck.Checker, tok string) string {
			_, err := ch.Verify(ctx, ns, tok)
			var ae *grant.AuthError
			switch {
			case err == nil:
				return "verified"
			case errors.As(err, &ae):
				return fmt.Sprintf("%d %s", ae.Status, ae.Msg)
			case client.IsPurged(err):
				return "410 purged"
			}
			return "error: " + err.Error()
		}
		for cn, ch := range map[string]*grantcheck.Checker{"a checker from before": held, "a new checker": checker()} {
			for an, at := range map[string]string{"the grant that verified": "", "at the purge-ns entry": purge} {
				self, named := liveSelf, liveNamed
				if at != "" {
					self, named = grantAt(keys[ns].self, ns, at), grantAt(keys[ns].named, ns, at)
				}
				as, an2 := answer(ch, self), answer(ch, named)
				t.Logf("%s purged, %s, %s: requireAt true: %s; its own name: %s", ns, cn, an, as, an2)
				if as != an2 {
					t.Errorf("%s purged, %s, %s: requireAt: true is %q and requireAt: %q is %q, want the same", ns, cn, an, as, ns, an2)
				}
				if an2 == "403 "+grant.RequireAtRefusal {
					t.Errorf("%s purged, %s, %s: its own name is the scope's 403", ns, cn, an)
				}
				if ns == "plain" && an2 != "verified" {
					t.Errorf("%s purged, %s, %s: %s, want the grant verified: an unsealed namespace's document and log are kept (§8.5)", ns, cn, an, an2)
				}
			}
		}
	}
}
