package client_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/archive"
	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/seal"
)

// §E.2.3, §11.2, §C.5: a writer limited to some resources reads neither the
// namespace document nor its log, and /keys tells it what sealing needs:
// 404 not_offered where the namespace isn't sealed, else the level, and the
// current epoch and pad. At E3 it then writes, prunes, undoes and redoes
// through an E2E view, under the epoch current then and padded as the
// namespace says, without reading the keyring. Undo reports as impossible
// a gesture whose oldest entry lies at or before the oldest entry it can read after a pruning horizon,
// the gesture's first entry read being that one or none following it.
func TestUndoLimitedKeys(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	arch, err := archive.NewDir(archive.URL(t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	s := clienttest.New(t, clienttest.Options{Auth: true, KeyStore: keyStore(t), Archiver: arch})
	k := clienttest.NewKey("k")
	jwk, priv, _ := seal.GenerateRecipient()
	liPub := priv.PublicKey()
	only := map[string]any{"enc": jwk, "rules": []any{map[string]any{"op": "test", "path": "/resource", "schema": map[string]any{"enum": []any{"a", "b"}}}}}
	rights := []string{"read", "create", "append", "prune"}
	limited := func(ns string) *client.Client {
		li := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:li", []string{ns}, rights, only)), client.WithKeys(client.NewKeys(priv)))
		if _, err := li.NSHead(ctx, ns); err == nil {
			t.Fatalf("%s: li reads the namespace", ns)
		}
		return li
	}
	mkNS := func(ns string, enc map[string]any) {
		doc := map[string]any{"read": "grant", "keys": []any{k.Entry("*")}}
		if enc != nil {
			doc["encryption"] = enc
		}
		must(s.Client(t, client.WithBearer(s.OperatorGrant(t, ns))).CreateNamespace(ctx, ns, doc))
	}

	// Plain: nothing to seal; the undo learns the level there.
	mkNS("kp", nil)
	li := limited("kp")
	if _, err := li.FetchKeysAnswer(ctx, "kp", nil, nil); !client.IsNotOffered(err) {
		t.Fatalf("plain keys: %v", err)
	}
	w := must(li.Create(ctx, "kp", "a", nonced(client.GenesisPatches(map[string]any{"n": 0}))))
	g := client.NewGesture()
	must(li.Append(ctx, "kp", "a", w.ID, nonced(ops(op("replace", "/n", 1))), client.WithGesture(g)))
	if plan := must(li.PlanUndo(ctx, "kp", g, client.UndoScanLog(), client.UndoResources("a"))); plan.Level != "" || len(plan.Batch.Items) != 1 {
		t.Fatalf("plain plan %+v", plan)
	}

	// Sealed: the level, epoch and pad, and per-resource keys.
	mkNS("ks", map[string]any{"level": "sealed", "pad": true})
	li = limited("ks")
	ans := must(li.FetchKeysAnswer(ctx, "ks", nil, []string{"a"}))
	if ans.Level != "sealed" || ans.Epoch != 1 || !ans.Pad || len(ans.Keys) != 1 || ans.Keys[0].Resource != "a" {
		t.Fatalf("sealed keys %+v", ans)
	}
	w = must(li.Create(ctx, "ks", "a", nonced(client.GenesisPatches(map[string]any{"n": 0}))))
	g = client.NewGesture()
	must(li.Append(ctx, "ks", "a", w.ID, nonced(ops(op("replace", "/n", 1))), client.WithGesture(g)))
	if plan := must(li.PlanUndo(ctx, "ks", g, client.UndoResources("a"))); plan.Level != "sealed" || len(plan.Batch.Items) != 1 {
		t.Fatalf("sealed plan %+v", plan)
	}

	// E3, padded: the relay gives li its own keyring entries, though it
	// can't read the keyring.
	mkNS("ke", map[string]any{"level": "e2e", "pad": true})
	adminJWK, adminPriv, _ := seal.GenerateRecipient()
	ac := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:admin", []string{"ke"}, []string{"read", "create", "append", "config"}, map[string]any{"enc": adminJWK})))
	ax := ac.E2E(adminPriv)
	must(ax.InitKeyring(ctx, "ke", liPub))
	li = limited("ke")
	ans = must(li.FetchKeysAnswer(ctx, "ke", []int{}, nil))
	if ans.Level != "e2e" || ans.Epoch != 1 || !ans.Pad || len(ans.Keys) != 0 {
		t.Fatalf("e2e keys %+v", ans)
	}
	lx := li.E2E(priv).WithSenders(adminPriv.PublicKey())
	w = must(lx.CreateDocSealed(ctx, "ke", "a", map[string]any{"n": 0, "m": 0}))
	if !patchSetPadded(t, ac, ax, "ke", "a", w.ID) {
		t.Fatal("li's write isn't padded")
	}
	g = client.NewGesture()
	w = must(lx.AppendSealed(ctx, "ke", "a", w.ID, ops(op("replace", "/n", 1)), client.WithGesture(g)))
	must(ax.AppendSealed(ctx, "ke", "a", w.ID, ops(op("replace", "/m", 1))))
	if e := must(ax.RotateEpoch(ctx, "ke", liPub)); e != 2 {
		t.Fatalf("epoch %d", e)
	}
	e2e := []client.UndoOption{client.UndoResources("a"), client.UndoE2E(lx)}
	if _, err := li.Undo(ctx, "ke", g, client.UndoResources("a")); err == nil || !strings.Contains(err.Error(), "UndoE2E") {
		t.Fatalf("an e2e undo without the view: %v", err)
	}
	u := must(li.Undo(ctx, "ke", g, e2e...))
	if u.Plan.Level != "e2e" || u.Plan.Source != "resources" || u.Plan.Author != "user:li" {
		t.Fatalf("e2e plan %+v", u.Plan)
	}
	h, d := must2(ax.LoadE2E(ctx, "ke", "a"))
	if len(d.Flagged) != 0 {
		t.Fatalf("flagged %+v", d.Flagged)
	}
	sameDoc(t, "e2e undone", d.Value, map[string]any{"n": 0, "m": 1})
	if kid := sealedKid(t, ac, "ke", "a", h.ID); kid != "ke#2" {
		t.Fatalf("the undo is sealed under %s", kid)
	}
	if !patchSetPadded(t, ac, ax, "ke", "a", h.ID) {
		t.Fatal("the undo isn't padded")
	}
	must(li.Redo(ctx, "ke", g, e2e...))
	_, d = must2(ax.LoadE2E(ctx, "ke", "a"))
	sameDoc(t, "e2e redone", d.Value, map[string]any{"n": 1, "m": 1})

	// The impossible cases, after li prunes b at the first entry of g3:
	// g4 lies wholly below the horizon, g3 continues below it, and g5,
	// after another entry, is undone.
	w = must(lx.CreateDocSealed(ctx, "ke", "b", map[string]any{"p": 0, "q": 0, "r": 0}))
	g3, g4, g5 := client.NewGesture(), client.NewGesture(), client.NewGesture()
	w = must(lx.AppendSealed(ctx, "ke", "b", w.ID, ops(op("replace", "/r", 1)), client.WithGesture(g4)))
	w = must(lx.AppendSealed(ctx, "ke", "b", w.ID, ops(op("replace", "/p", 1)), client.WithGesture(g3)))
	horizon := w.ID
	w = must(lx.AppendSealed(ctx, "ke", "b", w.ID, ops(op("replace", "/q", 1)), client.WithGesture(g3)))
	must(lx.AppendSealed(ctx, "ke", "b", w.ID, ops(op("replace", "/r", 2)), client.WithGesture(g5)))
	s.Clock.Advance(10 * time.Minute)
	if pr := must(lx.PruneE2E(ctx, "ke", "b", horizon)); pr.Horizon != horizon {
		t.Fatalf("prune %+v", pr)
	}
	inB := []client.UndoOption{client.UndoResources("b"), client.UndoE2E(lx)}
	for what, opts := range map[string][]client.UndoOption{
		"g3":            inB,
		"g4":            inB,
		"g4 by li":      append([]client.UndoOption{client.UndoAuthor("user:li")}, inB...),
		"g3 with a doc": {client.UndoResources("a", "b"), client.UndoE2E(lx)},
	} {
		gesture := g3
		if what[:2] == "g4" {
			gesture = g4
		}
		_, err := li.Undo(ctx, "ke", gesture, opts...)
		var ie *client.ImpossibleError
		if !errors.As(err, &ie) || ie.Reason != "pruned" || ie.Resource != "b" {
			t.Fatalf("%s: %v", what, err)
		}
	}
	_, d = must2(ax.LoadE2E(ctx, "ke", "b"))
	sameDoc(t, "after the refusals", d.Value, map[string]any{"p": 1, "q": 1, "r": 2})
	must(li.Undo(ctx, "ke", g5, inB...))
	_, d = must2(ax.LoadE2E(ctx, "ke", "b"))
	sameDoc(t, "g5 undone", d.Value, map[string]any{"p": 1, "q": 1, "r": 1})
}

// sealedKid is the kid the sealed patch set of revision id of ns/name is
// sealed under (§E.3.1).
func sealedKid(t *testing.T, c *client.Client, ns, name, id string) string {
	t.Helper()
	for _, le := range must(c.Log(context.Background(), ns, name, id, "")) {
		if le.ID != id {
			continue
		}
		jwe, ok := seal.SealedJWE(le.Patches)
		if !ok {
			t.Fatalf("%s is not sealed", id)
		}
		return must(seal.ParseHeader(jwe)).Kid
	}
	t.Fatalf("%s not in the log", id)
	return ""
}

// §E.2.3, §E.3: what a limited writer does with a /keys answer it can't
// use. One without a level, as a deployment before v0.51 gives, leaves the
// level to be learned from the resource log, so an e2e undo is refused and
// a sealed one still plans as sealed, and an e2e write says /keys doesn't
// tell. Errors other than a refusal, such as a 500, are returned as they
// are. The epoch it names is raised to the newest one relayed to the
// grant, since at E3 the server is outside the trust boundary.
func TestUndoLimitedKeysAnswers(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	var mode atomic.Value
	mode.Store("")
	s := clienttest.New(t, clienttest.Options{Auth: true, KeyStore: keyStore(t), Wrap: func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			m := mode.Load().(string)
			if m == "" || r.Method != "POST" || !strings.HasSuffix(r.URL.Path, "/keys") {
				h.ServeHTTP(w, r)
				return
			}
			if m == "500" {
				http.Error(w, `{"code":"internal"}`, 500)
				return
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, r)
			var body map[string]any
			if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &body) != nil {
				w.WriteHeader(rec.Code)
				w.Write(rec.Body.Bytes())
				return
			}
			switch m {
			case "old":
				delete(body, "epoch")
				delete(body, "level")
				delete(body, "pad")
			case "stale":
				body["epoch"] = 1
			}
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "no-store")
			json.NewEncoder(w).Encode(body)
		})
	}})
	k := clienttest.NewKey("k")
	jwk, priv, _ := seal.GenerateRecipient()
	only := map[string]any{"enc": jwk, "rules": []any{map[string]any{"op": "test", "path": "/resource", "value": "a"}}}
	mkNS := func(ns string, enc map[string]any) *client.Client {
		must(s.Client(t, client.WithBearer(s.OperatorGrant(t, ns))).CreateNamespace(ctx, ns, map[string]any{"read": "grant", "keys": []any{k.Entry("*")}, "encryption": enc}))
		return s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:li", []string{ns}, []string{"read", "create", "append"}, only)), client.WithKeys(client.NewKeys(priv)))
	}

	li := mkNS("as", map[string]any{"level": "sealed"})
	w := must(li.Create(ctx, "as", "a", nonced(client.GenesisPatches(map[string]any{"n": 0}))))
	g := client.NewGesture()
	must(li.Append(ctx, "as", "a", w.ID, nonced(ops(op("replace", "/n", 1))), client.WithGesture(g)))
	mode.Store("old")
	if plan := must(li.PlanUndo(ctx, "as", g, client.UndoResources("a"))); plan.Level != "sealed" {
		t.Fatalf("sealed plan from an older /keys %+v", plan)
	}

	mode.Store("")
	li = mkNS("ae", map[string]any{"level": "e2e"})
	adminJWK, adminPriv, _ := seal.GenerateRecipient()
	ac := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:admin", []string{"ae"}, []string{"read", "create", "append", "config"}, map[string]any{"enc": adminJWK})))
	ax := ac.E2E(adminPriv)
	must(ax.InitKeyring(ctx, "ae", priv.PublicKey()))
	lx := li.E2E(priv).WithSenders(adminPriv.PublicKey())
	w = must(lx.CreateDocSealed(ctx, "ae", "a", map[string]any{"n": 0}))
	g = client.NewGesture()
	w = must(lx.AppendSealed(ctx, "ae", "a", w.ID, ops(op("replace", "/n", 1)), client.WithGesture(g)))
	e2e := []client.UndoOption{client.UndoResources("a"), client.UndoE2E(lx)}

	mode.Store("old")
	if _, err := li.Undo(ctx, "ae", g, e2e...); !errors.Is(err, client.ErrUndoE2ELimited) {
		t.Fatalf("e2e undo with an older /keys: %v", err)
	}
	if _, err := lx.AppendSealed(ctx, "ae", "a", w.ID, ops(op("replace", "/n", 2))); err == nil || strings.Contains(err.Error(), "not e2e") {
		t.Fatalf("e2e write with an older /keys: %v", err)
	}

	mode.Store("500")
	var ae *client.APIError
	if _, err := li.PlanUndo(ctx, "ae", g, e2e...); !errors.As(err, &ae) || ae.Status != 500 || errors.Is(err, client.ErrUndoE2ELimited) {
		t.Fatalf("undo with a failing /keys: %v", err)
	}

	mode.Store("")
	if e := must(ax.RotateEpoch(ctx, "ae", priv.PublicKey())); e != 2 {
		t.Fatalf("epoch %d", e)
	}
	mode.Store("stale")
	w = must(lx.AppendSealed(ctx, "ae", "a", w.ID, ops(op("replace", "/n", 2))))
	if kid := sealedKid(t, ac, "ae", "a", w.ID); kid != "ae#2" {
		t.Fatalf("sealed under %s with a stale epoch from /keys", kid)
	}
}
