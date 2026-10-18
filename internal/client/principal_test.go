package client_test

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
)

// v0.55 §7.4: NSPrincipal is the server's verdict on the client's grant in
// a namespace, and what a writer needs from its document, to a grant
// limited to some resources too.
func TestNSPrincipal(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{Auth: true})
	k := clienttest.NewKey("k")
	admin := s.Client(t, client.WithBearer(s.OperatorGrant(t, "p")))
	must(admin.CreateNamespace(ctx, "p", map[string]any{"read": "public", "keys": []any{k.Entry("*")}, "nonce": "required",
		"limits": map[string]any{"opsPerSet": 50, "retryWindow": "PT5M", "ratePerPrincipal": map[string]any{"rate": 5, "burst": 9}}}))
	li := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:li", []string{"p"}, []string{"append"},
		map[string]any{"rules": []any{map[string]any{"op": "test", "path": "/resource", "value": "a"}}})))
	p := must(li.NSPrincipal(ctx, "p"))
	if p.Sub != "user:li" || p.Kid != "k" || !reflect.DeepEqual(p.Can, []string{"append"}) || len(p.Roles) != 0 ||
		!p.HasVerb("append") || p.HasVerb("read") || p.Config == "" || p.Principal["grant"] == "" {
		t.Fatalf("principal %+v", p)
	}
	w := p.Writer
	if !w.NonceRequired || w.SignaturesRequired || w.Frozen || w.Level != "" || w.Successor != "" {
		t.Fatalf("writer %+v", w)
	}
	if n, ok := w.Size("opsPerSet"); !ok || n != 50 {
		t.Fatalf("opsPerSet %d %v", n, ok)
	}
	if d, ok := w.Duration("retryWindow"); !ok || d != 5*time.Minute {
		t.Fatalf("retryWindow %v %v", d, ok)
	}
	if d, ok := w.Duration("remoteRegistration"); !ok || d != 30*24*time.Hour {
		t.Fatalf("remoteRegistration %v %v", d, ok)
	}
	if r, b, ok := w.Rate("ratePerPrincipal"); !ok || r != 5 || b != 9 {
		t.Fatalf("ratePerPrincipal %v %v %v", r, b, ok)
	}
	// The grant is the question, in a public namespace too.
	if _, err := s.Client(t).NSPrincipal(ctx, "p"); !client.IsAuth(err) {
		t.Fatalf("without a grant: %v", err)
	}
	// With authentication disabled there is no principal.
	d := clienttest.New(t, clienttest.Options{})
	dc := d.Client(t, client.WithAuthor("alice"))
	must(dc.CreateNamespace(ctx, "d", map[string]any{}))
	p = must(dc.NSPrincipal(ctx, "d"))
	if p.Principal != nil || p.Sub != "" || p.Kid != "" || !p.HasVerb("purge-ns") {
		t.Fatalf("auth disabled %+v", p)
	}
}
