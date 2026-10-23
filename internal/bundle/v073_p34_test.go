package bundle_test

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/bundle"
	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/grant"
	"github.com/middle-management/patchlog/internal/jsonv"
)

// P34, MF-44 (§G.4.1, §7.1): with "authors": true, history lines carry the
// entry's authorship members, via included: a revision written under a
// narrowed grant names its delegatees, one under the root grant none.
// Without authors no line carries via, and a bundle whose line does is
// rejected. via isn't hashed (ids recompute), and an import takes such a
// bundle.
func TestV073HistoryLinesCarryVia(t *testing.T) {
	t.Parallel()
	s := clienttest.New(t, clienttest.Options{Auth: true})
	admin := clienttest.NewKey("admin")
	oper := s.Client(t, client.WithBearer(s.OperatorGrant(t, "pub")))
	must(oper.CreateNamespace(ctx, "pub", map[string]any{"read": "public", "keys": []any{admin.Entry("*")}}))
	rootBearer := admin.Grant(t, s.Now(), "user:alice", []string{"pub"}, []string{"read", "create", "append"})
	root := must(grant.Decode(rootBearer, 0))
	nar := must(root.Narrow(map[string]any{"via": "svc:translator"}))
	w := must(s.Client(t, client.WithBearer(nar.Encode())).Create(ctx, "pub", "d", client.GenesisPatches(map[string]any{"n": 1})))
	w2 := must(s.Client(t, client.WithBearer(rootBearer)).Append(ctx, "pub", "d", w.ID, ops(op("replace", "/n", 2))))

	export := func(authors bool) []byte {
		bearer := admin.Grant(t, s.Now(), "user:root", []string{"pub"}, []string{"read", "export"})
		var buf bytes.Buffer
		if _, _, err := bundle.Export(ctx, s.Client(t, client.WithBearer(bearer)), &buf, bundle.ExportOptions{Select: []string{"pub"}, Authors: authors, Bearer: bearer}); err != nil {
			t.Fatal(err)
		}
		return buf.Bytes()
	}
	vias := func(b []byte) map[string]any {
		out := map[string]any{}
		for _, m := range lineMaps(t, b)[1:] {
			if id, ok := m["id"].(string); ok {
				if v, has := m["via"]; has {
					out[id] = v
				}
			}
		}
		return out
	}
	with := export(true)
	v := vias(with)
	if via, _ := v[w.ID].([]any); len(via) != 1 || via[0] != "svc:translator" {
		t.Fatalf("the delegated revision's line: via %v", v[w.ID])
	}
	if _, has := v[w2.ID]; has {
		t.Fatalf("the root grant's revision's line carries via %v", v[w2.ID])
	}
	// The reader parses it, and ids recompute over the patches alone.
	rd := must(bundle.NewReader(bytes.NewReader(with)))
	for {
		l, err := rd.Next()
		if err == io.EOF {
			break
		}
		noErr(t, err)
		if l.ID == w.ID && (len(l.Via) != 1 || l.Via[0] != "svc:translator" || len(l.LogEntry().Via) != 1) {
			t.Fatalf("parsed line: via %v", l.Via)
		}
	}
	if len(vias(export(false))) != 0 {
		t.Fatal("a bundle without authors carries via")
	}
	importB(t, newDeployment(t, stagingOrigin), with, bundle.ImportOptions{})

	// Lines carrying via where they may not, or in another shape.
	plain := export(false)
	ls := lines(plain)
	withVia := func(l []byte, via any) []byte {
		m := jsonv.MustParse(l).(map[string]any)
		m["via"] = via
		return jsonv.Canonical(m)
	}
	authorsHeader := func(h []byte) []byte {
		m := jsonv.MustParse(h).(map[string]any)
		m["authors"] = true
		return jsonv.Canonical(m)
	}
	first := 1
	for i, l := range ls[1:] {
		if bytes.Contains(l, []byte(`"id":"`+w.ID+`"`)) {
			first = i + 1
		}
	}
	mk := func(header []byte, via any) []byte {
		out := append([][]byte{header}, ls[1:]...)
		out[first] = withVia(ls[first], via)
		return join(out)
	}
	for name, c := range map[string]struct {
		b    []byte
		want string
	}{
		"without authors": {mk(ls[0], []any{"svc:x"}), `carries "via" in a bundle without authors`},
		"empty":           {mk(authorsHeader(ls[0]), []any{}), "via must be a non-empty array"},
		"a string":        {mk(authorsHeader(ls[0]), "svc:x"), "via must be a non-empty array"},
		"empty delegatee": {mk(authorsHeader(ls[0]), []any{""}), "each a non-empty string"},
		"not a string":    {mk(authorsHeader(ls[0]), []any{1.0}), "each a non-empty string"},
	} {
		_, err := bundle.Verify(bytes.NewReader(c.b))
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", name, err, c.want)
		}
	}
	// With authors, a via on a line verifies: it isn't hashed.
	if _, err := bundle.Verify(bytes.NewReader(mk(authorsHeader(ls[0]), []any{"svc:x", "svc:y"}))); err != nil {
		t.Fatalf("via with authors: %v", err)
	}
	// The writer drops via without authors, as the other members.
	var buf bytes.Buffer
	hdr := must(bundle.NewReader(bytes.NewReader(plain))).Header()
	bw := must(bundle.NewWriter(&buf, *hdr))
	rd = must(bundle.NewReader(bytes.NewReader(with)))
	for {
		l, err := rd.Next()
		if err != nil {
			break
		}
		if !l.IsGrant() {
			noErr(t, bw.Line(*l))
		}
	}
	must(bw.Close())
	if !bytes.Equal(buf.Bytes(), plain) {
		t.Fatalf("rewritten without authors:\n%s\nwant\n%s", buf.Bytes(), plain)
	}
}
