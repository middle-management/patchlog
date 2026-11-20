package grantcheck_test

import (
	"context"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/grantcheck"
	"github.com/middle-management/patchlog/internal/keystore"
)

// A load of a namespace's state that began before an Observe of it (a
// follower applying a config entry, say) and ends after it is not stored:
// it may hold the document the Observe said is gone, fresh for the TTL.
// Here the checker's read of sec's document is held while sec is made
// private and the checker told so; the next check reads again, and gets
// the private document.
func TestV0261ObserveOvertakesLoad(t *testing.T) {
	ctx := context.Background()
	ks, err := keystore.New(keystore.Generate())
	if err != nil {
		t.Fatal(err)
	}
	var gate atomic.Value
	gate.Store("")
	hit, release := make(chan struct{}), make(chan struct{})
	s := clienttest.New(t, clienttest.Options{Auth: true, KeyStore: ks, Wrap: func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if p := gate.Load().(string); p != "" && r.Method == "GET" && r.URL.Path == p && gate.CompareAndSwap(p, "") {
				close(hit)
				<-release
			}
			h.ServeHTTP(w, r)
		})
	}})
	admin := clienttest.NewKey("admin")
	must(s.Client(t, client.WithBearer(s.OperatorGrant(t, "sec"))).CreateNamespace(ctx, "sec", map[string]any{"read": "public", "keys": []any{admin.Entry("*")}}))
	w := s.Client(t, client.WithBearer(admin.Grant(t, s.Now(), "user:root", []string{"sec"}, []string{"read", "config"})), client.WithKeys(client.NewKeys(nil)))
	ch := grantcheck.New(s.Client(t, client.WithBearer(admin.Grant(t, s.Now(), "svc:x", []string{"sec"}, []string{"read"})), client.WithKeys(client.NewKeys(nil))),
		grantcheck.WithClock(s.Now), grantcheck.WithTTL(time.Hour))
	h0 := must(w.NSHead(ctx, "sec"))
	gate.Store("/ns/sec/rev/" + h0.ID)
	done := make(chan *grantcheck.Config, 1)
	go func() { done <- must(ch.Config(ctx, "sec")) }()
	<-hit
	must(w.PatchConfig(ctx, "sec", h0.Config, []any{map[string]any{"op": "replace", "path": "/read", "value": "grant"}}))
	ch.Observe("sec", must(w.NSHead(ctx, "sec")).ID)
	close(release)
	if c := <-done; c.Read != "public" {
		t.Fatalf("the load held: read %q, want the document it began at", c.Read)
	}
	if c := must(ch.Config(ctx, "sec")); c.Read != "grant" {
		t.Errorf("after the Observe, within the TTL: read %q, want grant (a load the Observe overtook was kept)", c.Read)
	}
}
