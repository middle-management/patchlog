package client_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/ids"
)

// v075ID is a well-formed id for s.
func v075ID(s string) string { return ids.Hash(nil, []byte(s)).String() }

// v075Fake serves h and returns a client of it.
func v075Fake(t *testing.T, h http.HandlerFunc) *client.Client {
	t.Helper()
	hs := httptest.NewServer(h)
	t.Cleanup(hs.Close)
	c, err := client.New(hs.URL)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func v075JSON(w http.ResponseWriter, hdr map[string]string, v any) {
	w.Header().Set("Content-Type", "application/json")
	for k, x := range hdr {
		w.Header().Set(k, x)
	}
	json.NewEncoder(w).Encode(v)
}

// /principal's roles are objects { name, can, rules } from v0.75 servers
// (§7.4): Roles keeps the names and RoleDefs the definitions; from older
// servers, names only (MUST-2, SVC-8).
func TestV075NSPrincipalRoles(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	var roles atomic.Value
	c := v075Fake(t, func(w http.ResponseWriter, r *http.Request) {
		v075JSON(w, map[string]string{"X-Config-Revision": v075ID("cfg")}, map[string]any{"principal": map[string]any{"id": "user:r"},
			"kid": "k", "operator": false, "can": []any{"read"}, "roles": roles.Load(), "writer": map[string]any{}})
	})
	rule := map[string]any{"op": "test", "path": "/resource", "schema": map[string]any{"type": "string"}}
	roles.Store([]any{map[string]any{"name": "reader", "can": []any{"read"}, "rules": []any{}},
		map[string]any{"name": "translator", "can": []any{"read", "append"}, "rules": []any{rule}}})
	p := must(c.NSPrincipal(ctx, "n"))
	if !reflect.DeepEqual(p.Roles, []string{"reader", "translator"}) || len(p.RoleDefs) != 2 {
		t.Fatalf("roles %v defs %+v", p.Roles, p.RoleDefs)
	}
	if d := p.RoleDefs[0]; d.Name != "reader" || !reflect.DeepEqual(d.Can, []string{"read"}) || d.Rules == nil || len(d.Rules) != 0 {
		t.Fatalf("reader %+v", d)
	}
	if d := p.RoleDefs[1]; d.Name != "translator" || !reflect.DeepEqual(d.Can, []string{"read", "append"}) || len(d.Rules) != 1 {
		t.Fatalf("translator %+v", d)
	}
	// A server before v0.75 sends names.
	roles.Store([]any{"reader"})
	p = must(c.NSPrincipal(ctx, "n"))
	if !reflect.DeepEqual(p.Roles, []string{"reader"}) || len(p.RoleDefs) != 1 || p.RoleDefs[0].Name != "reader" || p.RoleDefs[0].Can != nil {
		t.Fatalf("old roles %v defs %+v", p.Roles, p.RoleDefs)
	}

	// Against this server, end to end (§7.4).
	s := clienttest.New(t, clienttest.Options{Auth: true})
	k := clienttest.NewKey("k")
	admin := s.Client(t, client.WithBearer(s.OperatorGrant(t, "p")))
	must(admin.CreateNamespace(ctx, "p", map[string]any{"read": "grant", "keys": []any{k.Entry("*")},
		"roles": map[string]any{"translator": map[string]any{"can": []any{"read", "append"}, "rules": []any{rule}}}}))
	tr := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:t", []string{"p"}, nil, map[string]any{"roles": []any{"translator", "ghost"}})))
	p = must(tr.NSPrincipal(ctx, "p"))
	if !reflect.DeepEqual(p.Roles, []string{"translator"}) || len(p.RoleDefs) != 1 ||
		!reflect.DeepEqual(p.RoleDefs[0].Can, []string{"read", "append"}) || len(p.RoleDefs[0].Rules) != 1 {
		t.Fatalf("server roles %v defs %+v", p.Roles, p.RoleDefs)
	}
}

// /heads takes ?prefix=, a resource name (§7.4, §12.4): HeadsPrefix sends
// it and reads every page; an invalid prefix is refused before any
// request, and a row outside it is an error (MUST-8, SVC-9).
func TestV075HeadsPrefix(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	nsID := v075ID("h")
	var asked atomic.Int32
	var stray atomic.Bool
	c := v075Fake(t, func(w http.ResponseWriter, r *http.Request) {
		asked.Add(1)
		q := r.URL.Query()
		if r.URL.Path != "/ns/n/rev/"+nsID+"/heads" || q.Get("prefix") != "pub-" {
			http.Error(w, "want prefix=pub-: "+r.URL.String(), 400)
			return
		}
		row := func(n string) any { return map[string]any{"resource": n, "kind": "head", "target": v075ID(n)} }
		switch q.Get("after") {
		case "":
			v075JSON(w, nil, map[string]any{"heads": []any{row("pub-a")}, "next": "pub-a"})
		case "pub-a":
			rows := []any{row("pub-b")}
			if stray.Load() {
				rows = append(rows, row("x"))
			}
			v075JSON(w, nil, map[string]any{"heads": rows})
		}
	})
	got := must(c.HeadsPrefix(ctx, "n", nsID, "pub-"))
	if len(got) != 2 || got[0].Resource != "pub-a" || got[1].Resource != "pub-b" {
		t.Fatalf("heads %+v", got)
	}
	n := asked.Load()
	for _, bad := range []string{".x", "a/b", "-a", "A", strings.Repeat("a", 129)} {
		if _, _, err := c.HeadsPrefixPage(ctx, "n", nsID, bad, ""); err == nil {
			t.Fatalf("prefix %q accepted", bad)
		}
	}
	if asked.Load() != n {
		t.Fatal("an invalid prefix was sent")
	}
	stray.Store(true)
	if _, err := c.HeadsPrefix(ctx, "n", nsID, "pub-"); err == nil || !strings.Contains(err.Error(), "outside prefix") {
		t.Fatalf("stray row: %v", err)
	}
}

