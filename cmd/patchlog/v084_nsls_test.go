package main

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
)

// patchlog ns ls (§7.4 GET /ns, v0.84; HTTP-69): the deployment's
// namespaces, every page, as name, state, created and base.
func TestNSLs(t *testing.T) {
	t.Parallel()
	f := &resFixture{t: t, s: clienttest.New(t, clienttest.Options{LogPageSize: 2}), ctx: context.Background()}
	for _, ns := range []string{"m", "a_b", "a-b", "a0", "old", "icy"} {
		f.must("ns", "create", ns, `{"read":"public"}`)
	}
	f.must("branch", "create", "m", "m-b")
	f.must("ns", "config", "icy", `[{"op":"add","path":"/frozen","value":true}]`)
	f.must("ns", "config", "old", `[{"op":"add","path":"/frozen","value":true}]`)
	f.must("ns", "purge", "old", "--yes")

	out, _ := f.must("ns", "ls")
	lines := strings.Split(strings.TrimSpace(out), "\n")
	var names []string
	rows := map[string][]string{}
	for _, l := range lines {
		c := strings.Fields(l)
		if len(c) != 4 {
			t.Fatalf("ns ls line %q", l)
		}
		names = append(names, c[0])
		rows[c[0]] = c[1:]
	}
	// Byte order, across pages of two.
	if want := []string{"a-b", "a0", "a_b", "icy", "m", "m-b", "old"}; !slices.Equal(names, want) {
		t.Fatalf("ns ls: %v, want %v", names, want)
	}
	created := f.s.Now().UTC().Format("2006-01-02T15:04:05.000Z")
	for n, want := range map[string]string{"a0": "live", "icy": "frozen", "old": "purged", "m-b": "live"} {
		// A purged namespace's row has no created (§5, §7.4, v0.91).
		if r := rows[n]; r[0] != want || r[1] != created && !(n == "old" && r[1] == "-") {
			t.Errorf("%s: %v", n, r)
		}
	}
	if rows["m"][2] != "-" || !strings.HasPrefix(rows["m-b"][2], "m@") || len(rows["m-b"][2]) < 20 {
		t.Errorf("base columns: m %v, m-b %v", rows["m"], rows["m-b"])
	}

	out, _ = f.must("ns", "ls", "--prefix", "a")
	if got := strings.Fields(strings.ReplaceAll(out, "\n", " \n ")); strings.Count(out, "\n") != 3 || got[0] != "a-b" {
		t.Fatalf("ns ls --prefix a: %q", out)
	}
	if out, _ = f.must("ns", "ls", "--prefix", "zz"); strings.TrimSpace(out) != "" {
		t.Fatalf("ns ls of no match: %q", out)
	}
	msg, _ := f.fail("ns", "ls", "--prefix", "A_")
	wantIn(t, "ns ls with a prefix that is no name", msg, "prefix")

	out, _ = f.must("ns", "ls", "--json", "--prefix", "m")
	var js []map[string]any
	if err := json.Unmarshal([]byte(out), &js); err != nil || len(js) != 2 {
		t.Fatalf("ns ls --json: %v %s", err, out)
	}
	if js[0]["name"] != "m" || js[0]["frozen"] != false || js[0]["purged"] != false || js[0]["created"] != created || js[0]["base"] != nil {
		t.Fatalf("ns ls --json row %v", js[0])
	}
	if b, _ := js[1]["base"].(map[string]any); js[1]["name"] != "m-b" || b["ns"] != "m" || b["at"] == nil {
		t.Fatalf("ns ls --json branch row %v", js[1])
	}
	if out, _ = f.must("ns", "ls", "--json", "--prefix", "zz"); strings.TrimSpace(out) != "[]" {
		t.Fatalf("ns ls --json of no match: %q", out)
	}
}

// With authentication on, ns ls needs an operator grant naming "*" with
// config (§7.4, §C.4; scenario 75).
func TestNSLsOperatorGrant(t *testing.T) {
	t.Parallel()
	s := clienttest.New(t, clienttest.Options{Auth: true})
	ctx := context.Background()
	k := clienttest.NewKey("k1")
	if _, err := s.Client(t, client.WithBearer(s.OperatorGrant(t, "m"))).CreateNamespace(ctx, "m", map[string]any{"keys": []any{k.Entry("*")}}); err != nil {
		t.Fatal(err)
	}
	_, _, err := clientRun(t, ctx, s.URL, "ns", "ls")
	if err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("ns ls without a grant: %v", err)
	}
	// A grant to create m names m, not "*": 403.
	_, _, err = clientRun(t, ctx, s.URL, "ns", "ls", "--bearer", s.OperatorGrant(t, "m"))
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("ns ls with a namespace's operator grant: %v", err)
	}
	_, _, err = clientRun(t, ctx, s.URL, "ns", "ls", "--bearer", k.Grant(t, s.Now(), "user:eve", []string{"*"}, []string{"config"}))
	if err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf(`ns ls with a namespace key's grant naming "*": %v`, err)
	}
	g := clienttest.Mint(t, s.OperatorKey, map[string]any{"kid": "operator", "sub": "op:root", "ns": []any{"*"}, "can": []any{"config"},
		"exp": s.Now().Add(time.Hour).Format(time.RFC3339)})
	out, errw, err := clientRun(t, ctx, s.URL, "ns", "ls", "--bearer", g)
	if err != nil || !strings.HasPrefix(out, "m ") || strings.Count(out, "\n") != 1 {
		t.Fatalf("ns ls: %q %v %s", out, err, errw)
	}
}
