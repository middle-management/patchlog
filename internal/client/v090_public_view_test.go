package client_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/jsonv"
)

// v0.90 "Filtering a namespace" (§7.9 Where, §7 step 1, §E.2.3,
// scenarios 95–97): a consumer filters a public namespace by narrowing
// its grant with read rules. The unfiltered URLs ignore the grant and
// never redirect, so the client finds its view (ViewOf: /edge-grants, or
// /keys where sealed) and reads the filtered log and /heads there
// (ViewLog, ViewHeads). Head entries carry their revision's schema, by
// which the shared log can be filtered on the client too (SchemaHeads).
//
//	a1  team a, typed                     visible
//	b1  team b, typed                     hidden
//	x   genesis team b, then team a       x1 hidden, x2 visible
func TestV090PublicView(t *testing.T) {
	t.Parallel()
	for _, sealed := range []bool{false, true} {
		name := "plain"
		if sealed {
			name = "sealed"
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			v090PublicView(t, sealed)
		})
	}
}

func v090PublicView(t *testing.T, sealed bool) {
	ctx := context.Background()
	opts := clienttest.Options{Auth: true, EdgeGrants: true}
	doc := map[string]any{"read": "public"}
	wrap := func(p []any) []any { return p }
	if sealed {
		opts.KeyStore = keyStore(t)
		doc["encryption"] = map[string]any{"level": "sealed"}
		wrap = nonced
	}
	s := clienttest.New(t, opts)
	k := clienttest.NewKey("k")
	doc["keys"] = []any{k.Entry("*")}
	must(s.Client(t, client.WithBearer(s.OperatorGrant(t, "pub"))).CreateNamespace(ctx, "pub", doc))
	adminGrant := k.Grant(t, s.Now(), "user:a", []string{"pub"}, []string{"read", "create", "append"})
	admin := s.Client(t, client.WithBearer(adminGrant), client.WithKeys(client.NewKeys(nil)))

	sc := must(admin.Create(ctx, "pub", "sch", wrap(client.GenesisPatches(map[string]any{"$schema": "https://json-schema.org/draft/2020-12/schema", "type": "object"})))).ID
	ref := "/r/pub/sch/rev/" + sc
	data := []byte("the blob of a1")
	bid := must(admin.UploadBlob(ctx, "pub", "a1", "text/plain", "", data))
	bref := map[string]any{"$blob": bid, "type": "text/plain", "size": float64(len(data))}
	a1 := must(admin.Create(ctx, "pub", "a1", wrap(client.GenesisPatches(map[string]any{"$schema": ref, "team": "a", "mark": "A1", "file": bref})))).ID
	b1 := must(admin.Create(ctx, "pub", "b1", wrap(client.GenesisPatches(map[string]any{"$schema": ref, "team": "b", "mark": "HIDDEN-B1"})))).ID
	x1 := must(admin.Create(ctx, "pub", "x", wrap(client.GenesisPatches(map[string]any{"team": "b", "mark": "HIDDEN-X1"})))).ID
	x2 := must(admin.Append(ctx, "pub", "x", x1, wrap(ops(op("replace", "/team", "a"), op("replace", "/mark", "X2"))))).ID

	readerGrant := k.Grant(t, s.Now(), "user:r", []string{"pub"}, []string{"read"},
		map[string]any{"rules": []any{map[string]any{"op": "test", "path": "/doc/team", "value": "a"}}})
	reader := s.Client(t, client.WithBearer(readerGrant), client.WithKeys(client.NewKeys(nil)))

	if !sealed {
		// The unfiltered log ignores the grant: no redirect, every entry.
		es, fa, err := reader.FilteredLog(ctx, "pub", "")
		if err != nil || fa.Filtered() || !slices.ContainsFunc(es, func(e client.NSEntry) bool { return e.Resource == "b1" }) {
			t.Fatalf("the unfiltered log to the reader: %v %+v", err, fa)
		}
		// The schema of each head entry, by which the whole log filters.
		typed := client.SchemaHeads(es, ref)
		if len(typed) != 2 || typed[0].Resource != "a1" || typed[1].Resource != "b1" {
			t.Fatalf("SchemaHeads of the whole log: %+v", typed)
		}
	}

	view := must(reader.ViewOf(ctx, "pub"))
	if view == "" {
		t.Fatal("ViewOf: no view for a partial reader")
	}
	if sealed {
		// The view's K_view alone, where v0.89 refused one (§E.2.3).
		ka := must(reader.FetchKeysAnswer(ctx, "pub", nil, nil))
		if len(ka.Keys) != 1 || ka.Keys[0].View != view || ka.Keys[0].Resource != "" {
			t.Fatalf("the partial reader's keys: %+v", ka.Keys)
		}
	}
	es, fa, err := reader.ViewLog(ctx, "pub", "")
	if err != nil || fa.View != view {
		t.Fatalf("ViewLog: %v %+v (view %s)", err, fa, view)
	}
	var shown []string
	for _, e := range es {
		if e.Kind == "head" {
			shown = append(shown, e.Resource+"@"+e.Target+":"+e.Schema)
		}
		if strings.Contains(string(jsonv.Canonical(jsonv.FromGo(e.Raw))), "HIDDEN") {
			t.Fatalf("the filtered log shows a hidden document: %v", e.Raw)
		}
	}
	if want := []string{"a1@" + a1 + ":" + ref, "x@" + x2 + ":"}; !slices.Equal(shown, want) {
		t.Fatalf("visible heads in the view's range %v, want %v", shown, want)
	}
	heads, hfa, err := reader.ViewHeads(ctx, "pub", "")
	if err != nil || hfa.View != view || len(heads) != 2 || heads[0].Resource != "a1" || heads[1].Resource != "x" || heads[1].Target != x2 {
		t.Fatalf("ViewHeads: %+v %+v %v", heads, hfa, err)
	}

	// Visible documents open, at their own URLs, which ignore the grant,
	// with what the view's answers carried where sealed.
	for id, name := range map[string]string{a1: "a1", x2: "x"} {
		if _, err := reader.Doc(ctx, "pub", name, id); err != nil {
			t.Fatalf("Doc %s@%s: %v", name, id, err)
		}
	}
	// A resource's log at its own URL ignores the grant: the same bytes
	// as to an anonymous request, never filtered or sealed for the view.
	rawGet := func(path, bearer string) string {
		t.Helper()
		req, _ := http.NewRequest("GET", s.URL+path, nil)
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		b, _ := io.ReadAll(res.Body)
		return fmt.Sprint(res.StatusCode, " ", res.Header.Get("Content-Type"), " ", string(b))
	}
	for _, p := range []string{"/r/pub/x/rev/" + x2 + "/log", "/ns/pub/rev/" + fa.End + "/heads"} {
		if got, anon := rawGet(p, readerGrant), rawGet(p, ""); got != anon || !strings.HasPrefix(got, "200") {
			t.Fatalf("%s to the reader:\n%s\nanonymously:\n%s", p, got, anon)
		}
	}
	if sealed {
		// Hidden ones are served there, sealed, but open under nothing
		// the reader holds.
		for id, name := range map[string]string{b1: "b1", x1: "x"} {
			if _, err := reader.Doc(ctx, "pub", name, id); err == nil {
				t.Fatalf("hidden %s@%s opened", name, id)
			}
		}
	}

	if sealed {
		// The view key opens nothing for a copy (§E.2.3, TERM-6): a blob
		// copy out of the public sealed namespace with the partial
		// reader's grant as the source grant is refused, as before v0.90
		// when it got no key at all; an unrestricted source grant copies.
		must(s.Client(t, client.WithBearer(s.OperatorGrant(t, "p"))).CreateNamespace(ctx, "p",
			map[string]any{"read": "grant", "keys": []any{k.Entry("*")}}))
		pw := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:w", []string{"p"}, []string{"read", "create"})))
		if err := pw.CopyBlob(ctx, "p", "c", bid, "pub", "a1", readerGrant); err == nil {
			t.Fatal("a blob copied out of a public sealed namespace with a partial reader's grant")
		}
		if err := pw.CopyBlob(ctx, "p", "c", bid, "pub", "a1", adminGrant); err != nil {
			t.Fatalf("a blob copied with an unrestricted grant: %v", err)
		}
	}

	// An unrestricted reader has no view; a request without a grant
	// gets none either.
	if v, err := admin.ViewOf(ctx, "pub"); err != nil || v != "" {
		t.Fatalf("the unrestricted reader's ViewOf: %q %v", v, err)
	}
	if _, err := s.Client(t).ViewOf(ctx, "pub"); err == nil {
		t.Fatal("ViewOf without a grant")
	}
}
