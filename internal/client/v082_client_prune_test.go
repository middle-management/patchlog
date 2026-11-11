package client_test

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/seal"
)

// v82Chain is g, p and the tombstone T on p in st, with p's document
// folded from its log, as PruneE2E reads it.
func v82Chain(st *e3Stub) (g, p map[string]any, P, T string) {
	g = st.rev(st.kr, "", []any{map[string]any{"op": "add", "path": "", "value": map[string]any{"n": 1.0}}})
	p = st.rev(st.kr, g["id"].(string), []any{map[string]any{"op": "replace", "path": "/n", "value": 2.0}})
	P = p["id"].(string)
	T = st.tombstone(P)["id"].(string)
	st.routes["/r/e/d/rev/"+P] = st.notOffered("", "")
	st.routes["/r/e/d/rev/"+P+"/log"] = st.json(200, []any{g, p})
	return g, p, P, T
}

// E2E-4 (§E.3.1 Snapshots, §7.1): a pruning client takes a tombstone
// horizon's parent from the last of the tombstone's own 410, checks it
// against the tombstone's id and binds the snapshot's pl.id to it. Here
// nothing else names the parent: the head is a later live revision and
// the log of T isn't served.
func TestV082PruneE2EParentFromTombstone410(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	st := newE3Stub(t)
	_, _, P, T := v82Chain(st)
	r := st.rev(st.kr, T, []any{map[string]any{"op": "add", "path": "", "value": map[string]any{"n": 3.0}}})
	st.routes["/r/e/d"] = func(w http.ResponseWriter) {
		w.Header().Set("ETag", `"`+r["id"].(string)+`"`)
		w.WriteHeader(302)
	}
	st.routes["/r/e/d/rev/"+T] = st.json(410, map[string]any{"code": "gone", "tombstone": T, "last": P})
	x := st.view()
	if _, err := x.PruneE2E(ctx, "e", "d", T); err != nil {
		t.Fatal(err)
	}
	hd := must(seal.ParseHeader(st.pruned["snapshot"].(string)))
	if st.pruned["horizon"] != T || hd.PL["id"] != P || len(hd.PL) != 3 {
		t.Fatalf("prune %v, snapshot header %s; want horizon %s and pl.id %s", st.pruned["horizon"], hd.Raw, T, P)
	}
	if doc := must(seal.OpenSnapshot(st.pruned["snapshot"].(string), st.kr, "e#1", "e", "d", P)); doc.(map[string]any)["n"] != 2.0 {
		t.Fatalf("snapshot %v", doc)
	}
	if st.wasAsked("/r/e/d/rev/" + T + "/log") {
		t.Fatalf("the parent was looked for in the log: %v", st.asked)
	}
}

// E2E-4: a server naming a last that isn't the tombstone's parent, or
// another tombstone, is refused before anything is sealed or sent, even
// where the head would name the right parent.
func TestV082PruneE2EWrongLastRefused(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	for what, body := range map[string]func(g, P, T string) map[string]any{
		"another revision as last": func(g, P, T string) map[string]any {
			return map[string]any{"code": "gone", "tombstone": T, "last": g}
		},
		"last that isn't an id": func(g, P, T string) map[string]any {
			return map[string]any{"code": "gone", "tombstone": T, "last": "x"}
		},
		"another tombstone": func(g, P, T string) map[string]any {
			return map[string]any{"code": "gone", "tombstone": must(client.ExpectedTombstone(g)), "last": g}
		},
		"last without tombstone": func(g, P, T string) map[string]any {
			return map[string]any{"code": "gone", "last": P}
		},
	} {
		st := newE3Stub(t)
		g, _, P, T := v82Chain(st)
		st.routes["/r/e/d"] = st.json(410, map[string]any{"code": "gone", "tombstone": T, "last": P})
		st.routes["/r/e/d/rev/"+g["id"].(string)] = st.notOffered("", "")
		st.routes["/r/e/d/rev/"+g["id"].(string)+"/log"] = st.json(200, []any{g})
		st.routes["/r/e/d/rev/"+T] = st.json(410, body(g["id"].(string), P, T))
		x := st.view()
		if _, err := x.PruneE2E(ctx, "e", "d", T); !errors.Is(err, seal.ErrMismatch) {
			t.Fatalf("%s: %v, want seal.ErrMismatch", what, err)
		}
		if st.pruned != nil {
			t.Fatalf("%s: a prune was sent: %v", what, st.pruned)
		}
	}
}

// E2E-4: a 410 without last, as a server before v0.82 or a cache answers,
// leaves the earlier sources: the head's last, or the log.
func TestV082PruneE2E410WithoutLastFallsBack(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	st := newE3Stub(t)
	g, p, P, T := v82Chain(st)
	r := st.rev(st.kr, T, []any{map[string]any{"op": "add", "path": "", "value": map[string]any{"n": 3.0}}})
	st.routes["/r/e/d"] = func(w http.ResponseWriter) {
		w.Header().Set("ETag", `"`+r["id"].(string)+`"`)
		w.WriteHeader(302)
	}
	st.routes["/r/e/d/rev/"+T] = st.json(410, map[string]any{"code": "gone"})
	st.routes["/r/e/d/rev/"+T+"/log"] = st.json(200, []any{g, p, st.tombstone(P)})
	x := st.view()
	if _, err := x.PruneE2E(ctx, "e", "d", T); err != nil {
		t.Fatal(err)
	}
	if hd := must(seal.ParseHeader(st.pruned["snapshot"].(string))); hd.PL["id"] != P || st.pruned["horizon"] != T {
		t.Fatalf("snapshot header %s, horizon %v", hd.Raw, st.pruned["horizon"])
	}
	if !st.wasAsked("/r/e/d/rev/" + T + "/log") {
		t.Fatal("the log wasn't read")
	}
}

// E2E-4: a re-prune at the current tombstone horizon, which the log no
// longer lists, learns the parent from the tombstone's 410 as well.
func TestV082PruneE2ECurrentTombstoneHorizon(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	st := newE3Stub(t)
	_, _, P, T := v82Chain(st)
	r := st.rev(st.kr, T, []any{map[string]any{"op": "add", "path": "", "value": map[string]any{"n": 3.0}}})
	st.routes["/r/e/d"] = func(w http.ResponseWriter) {
		w.Header().Set("ETag", `"`+r["id"].(string)+`"`)
		w.WriteHeader(302)
	}
	// As a server whose horizon is T answers: P serves the snapshot, the
	// log from T is empty.
	st.routes["/r/e/d/rev/"+P] = st.jose(st.snapshot(P, map[string]any{"n": 2.0}))
	st.routes["/r/e/d/rev/"+T] = st.json(410, map[string]any{"code": "gone", "tombstone": T, "last": P})
	x := st.view()
	if _, err := x.PruneE2E(ctx, "e", "d", T); err != nil {
		t.Fatal(err)
	}
	if hd := must(seal.ParseHeader(st.pruned["snapshot"].(string))); hd.PL["id"] != P || st.pruned["horizon"] != T {
		t.Fatalf("snapshot header %s, horizon %v", hd.Raw, st.pruned["horizon"])
	}
}

// E2E-3 (§7.1): APIError.Tombstone and Last read a tombstone's 410; a
// pruned or purged 410, and another status, name no tombstone.
func TestV082APIErrorTombstone(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	st := newE3Stub(t)
	_, _, P, T := v82Chain(st)
	st.routes["/r/p/d/rev/"+T] = st.json(410, map[string]any{"code": "gone", "tombstone": T, "last": P})
	st.routes["/r/p/d/rev/"+P] = st.json(410, map[string]any{"code": "pruned", "horizon": T})
	st.routes["/r/p/x/rev/"+T] = st.json(410, map[string]any{"code": "gone"})
	st.routes["/r/p/y/rev/"+T] = st.json(404, map[string]any{"code": "not_found", "tombstone": T})
	c, err := client.New(st.server().URL)
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Doc(ctx, "p", "d", T)
	ae, ok := client.AsAPIError(err)
	if !ok || !client.IsGone(err) || client.IsPruned(err) || ae.Tombstone() != T || ae.Last() != P {
		t.Fatalf("a tombstone's /rev: %v", err)
	}
	_, err = c.Doc(ctx, "p", "d", P)
	if ae, _ := client.AsAPIError(err); !client.IsPruned(err) || client.IsGone(err) || ae.Tombstone() != "" {
		t.Fatalf("a pruned /rev: %v", err)
	}
	_, err = c.Doc(ctx, "p", "x", T)
	if ae, _ := client.AsAPIError(err); !client.IsGone(err) || ae.Tombstone() != "" || ae.Last() != "" {
		t.Fatalf("a purged resource's /rev: %v", err)
	}
	_, err = c.Doc(ctx, "p", "y", T)
	if ae, _ := client.AsAPIError(err); !client.IsNotFound(err) || ae.Tombstone() != "" {
		t.Fatalf("a 404: %v", err)
	}
}
