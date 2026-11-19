package index_test

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
)

// §6.6 Validation work (v0.86), LIM-7, conformance scenario 90, SERVICES
// §A.4: an index hit filtered per item by a grant's rule whose schema
// test runs out of validationSteps for one item is left out, the rest
// listed: never the item shown, under a not either, and never the whole
// result failed. The service is told the deployment's validationSteps
// (Options.ValidationSteps), which no namespace document carries.
func TestV086IndexItemBudget(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{Auth: true, LongPoll: 150 * time.Millisecond})
	admin, issuer := clienttest.NewKey("admin"), clienttest.NewKey("issuer")
	op := s.Client(t, client.WithBearer(s.OperatorGrant(t, "sec")))
	must(op.CreateNamespace(ctx, "sec", map[string]any{"read": "grant", "keys": []any{admin.Entry("*"), issuer.Entry("read")}}))
	writer := s.Client(t, client.WithBearer(admin.Grant(t, s.Now(), "user:root", []string{"sec"}, []string{"read", "create", "append"})))
	sch := must(writer.CreateDoc(ctx, "sec", "schema", map[string]any{"$schema": d2020, "type": "object",
		"properties": map[string]any{"title": map[string]any{"type": "string", "x-index": "text"}}}))
	for _, n := range []string{"a", "b", "c"} {
		must(writer.CreateDoc(ctx, "sec", n, map[string]any{"$schema": "/r/sec/schema/rev/" + sch.ID, "title": "secret " + n}))
	}
	indexer := s.Client(t, client.WithBearer(admin.Grant(t, s.Now(), "svc:indexer", []string{"sec"}, []string{"read"})))
	x := startSvcWith(t, indexer, svcOpts{db: filepath.Join(t.TempDir(), "i.db"), ns: []string{"sec"}, untyped: true, now: s.Now},
		func(o *indexOpts) { o.ValidationSteps = 2000 })
	x.caughtUp("sec")

	// More than 2^30 steps on any value.
	defs := map[string]any{"a30": true}
	for i := 0; i < 30; i++ {
		next := map[string]any{"$ref": fmt.Sprintf("#/$defs/a%d", i+1)}
		defs[fmt.Sprintf("a%d", i)] = map[string]any{"allOf": []any{next, next}}
	}
	slow := map[string]any{"op": "test", "path": "/resource", "schema": map[string]any{"$ref": "#/$defs/a0", "$defs": defs}}
	onB := func(then any) []any {
		return []any{map[string]any{"if": []any{map[string]any{"op": "test", "path": "/resource", "value": "b"}}, "then": []any{then}}}
	}
	for name, rs := range map[string][]any{"a test": onB(slow), "under a not": onB(map[string]any{"not": slow})} {
		g := issuer.Grant(t, s.Now(), "user:li", []string{"sec"}, []string{"read"}, map[string]any{"rules": rs})
		if got := strings.Join(resources(x.search("/sec?q=secret", g)), ","); got != "a,c" {
			t.Errorf("%s: the reader's hits are %q, want a,c", name, got)
		}
	}
}
