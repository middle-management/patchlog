package client_test

import (
	"context"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
)

// v0.84 §7.4 GET /ns (HTTP-69; scenario 75): Namespaces reads a page of
// the deployment's namespaces under an operator grant naming "*", and
// AllNamespaces every page.
func TestV084Namespaces(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{Auth: true, LogPageSize: 2})
	star := clienttest.NewKey("star")
	all := []string{"read", "append", "create", "delete", "config", "branch", "purge", "purge-ns"}
	for _, ns := range []string{"matches", "a_b", "a-b", "a0", "old"} {
		c := s.Client(t, client.WithBearer(s.OperatorGrant(t, ns)))
		must(c.CreateNamespace(ctx, ns, map[string]any{"keys": []any{star.Entry("*")}}))
	}
	admin := s.Client(t, client.WithBearer(star.Grant(t, s.Now(), "user:admin", []string{"matches", "old"}, all)))
	must(admin.CreateBranch(ctx, "matches", client.BranchRequest{Name: "matches-next"}))
	h := must(admin.NSHead(ctx, "old"))
	must(admin.PatchConfig(ctx, "old", h.Config, ops(op("add", "/frozen", true))))
	must(admin.PurgeNamespace(ctx, "old", must(admin.NSHead(ctx, "old")).ID))

	// Scenario 75: a namespace's grant is 403, one naming "*" that no
	// operator key signed 401.
	if _, _, err := admin.Namespaces(ctx, "", ""); !hasStatus(err, 403) {
		t.Fatalf("a namespace grant: %v", err)
	}
	wild := s.Client(t, client.WithBearer(star.Grant(t, s.Now(), "user:admin", []string{"*"}, all)))
	if _, _, err := wild.Namespaces(ctx, "", ""); !hasStatus(err, 401) {
		t.Fatalf(`a namespace key's grant naming "*": %v`, err)
	}
	if _, _, err := s.Client(t).Namespaces(ctx, "", ""); !hasStatus(err, 401) {
		t.Fatalf("no grant: %v", err)
	}

	op := s.Client(t, client.WithBearer(clienttest.Mint(t, s.OperatorKey, map[string]any{"kid": "operator", "sub": "op:root", "ns": []any{"*"}, "can": []any{"config"},
		"exp": s.Now().Add(time.Hour).Format(time.RFC3339)})))
	names := func(xs []client.Namespace) []string {
		out := []string{}
		for _, x := range xs {
			out = append(out, x.Name)
		}
		return out
	}
	// A page, and its next.
	page, next, err := op.Namespaces(ctx, "", "")
	if err != nil || !reflect.DeepEqual(names(page), []string{"a-b", "a0"}) || next != "a0" {
		t.Fatalf("first page %v next %q: %v", names(page), next, err)
	}
	page, next, err = op.Namespaces(ctx, "a", "a")
	if err != nil || !reflect.DeepEqual(names(page), []string{"a-b", "a0"}) || next != "a0" {
		t.Fatalf("page after a %v next %q: %v", names(page), next, err)
	}
	page, next, err = op.Namespaces(ctx, "a0", "a")
	if err != nil || !reflect.DeepEqual(names(page), []string{"a_b"}) || next != "" {
		t.Fatalf("last page of a %v next %q: %v", names(page), next, err)
	}
	// Every page, in byte order.
	rows, err := op.AllNamespaces(ctx, "")
	if err != nil || !reflect.DeepEqual(names(rows), []string{"a-b", "a0", "a_b", "matches", "matches-next", "old"}) {
		t.Fatalf("all %v: %v", names(rows), err)
	}
	created := s.Now().UTC().Format("2006-01-02T15:04:05.000Z")
	for _, r := range rows {
		if r.Created != created && !r.Purged || r.Raw["name"] != r.Name {
			t.Fatalf("row %+v", r)
		}
		switch r.Name {
		case "old":
			// Only what a purged namespace keeps (§5, §7.4, v0.91).
			if !r.Purged || !r.Frozen || r.Base != nil || r.Created != "" || len(r.Raw) != 3 {
				t.Fatalf("purged row %+v", r)
			}
		case "matches-next":
			if r.Purged || r.Frozen || r.Base["ns"] != "matches" || r.Base["at"] == "" {
				t.Fatalf("branch row %+v", r)
			}
		default:
			if r.Purged || r.Frozen || r.Base != nil {
				t.Fatalf("row %+v", r)
			}
		}
	}
	if rows, err := op.AllNamespaces(ctx, "matches"); err != nil || !reflect.DeepEqual(names(rows), []string{"matches", "matches-next"}) {
		t.Fatalf("prefix matches %v: %v", names(rows), err)
	}
	if rows, err := op.AllNamespaces(ctx, "zz"); err != nil || len(rows) != 0 {
		t.Fatalf("prefix zz %v: %v", names(rows), err)
	}
	// A prefix that is no namespace name is refused before any request.
	for _, p := range []string{"A", "a.b", "-a", strings.Repeat("a", 65)} {
		if _, _, err := op.Namespaces(ctx, "", p); err == nil || !strings.Contains(err.Error(), "prefix") {
			t.Fatalf("prefix %q: %v", p, err)
		}
		if _, err := op.AllNamespaces(ctx, p); err == nil {
			t.Fatalf("prefix %q accepted", p)
		}
	}
}

// §7.4: while authentication is disabled the listing answers everyone,
// and a row outside the page asked for, or a next that doesn't advance,
// is an error, not a loop.
func TestV084NamespacesDevAndBadPages(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	answer := ""
	s := clienttest.New(t, clienttest.Options{Wrap: func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if answer != "" && r.URL.Path == "/ns" {
				w.Header().Set("Content-Type", "application/json")
				w.Write([]byte(answer))
				return
			}
			h.ServeHTTP(w, r)
		})
	}})
	c := s.Client(t, client.WithAuthor("alice"))
	must(c.CreateNamespace(ctx, "docs", map[string]any{}))
	rows, err := c.AllNamespaces(ctx, "")
	if err != nil || len(rows) != 1 || rows[0].Name != "docs" || rows[0].Created == "" {
		t.Fatalf("rows %+v: %v", rows, err)
	}
	for _, bad := range []string{
		`{"heads":[]}`,
		`{"namespaces":[{"name":"docs","created":"x","frozen":false,"purged":false}],"next":""}` + "\x00prefix",
		`{"namespaces":[{"name":"~docs"}]}`,
	} {
		ans, prefix, _ := strings.Cut(bad, "\x00")
		answer = ans
		if prefix != "" {
			prefix = "x"
		}
		if _, _, err := c.Namespaces(ctx, "", prefix); err == nil {
			t.Errorf("accepted %s", ans)
		}
	}
	answer = `{"namespaces":[{"name":"b"}]}`
	if _, _, err := c.Namespaces(ctx, "b", ""); err == nil {
		t.Error("accepted a row not after after")
	}
	answer = `{"namespaces":[{"name":"b"}],"next":"b"}`
	if _, err := c.AllNamespaces(ctx, ""); err == nil {
		t.Error("a listing that repeats its page ended without an error")
	}
	answer = `{"namespaces":[],"next":"a"}`
	if _, err := c.AllNamespaces(ctx, "b"); err == nil || !strings.Contains(err.Error(), "next") {
		t.Errorf("a next that doesn't advance: %v", err)
	}
}

func hasStatus(err error, status int) bool {
	ae, ok := client.AsAPIError(err)
	return ok && ae.Status == status
}
