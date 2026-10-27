package core

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/grant"
	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/pgtest"
)

// Spec v0.73, package P19: log entries, heads, /principal, grants and
// cache tags (§7.1, §7.4, §8.3, §9).

// Two writes appended together by group commit (appendNSMany), one under a
// delegated grant and one not: each namespace entry records its own via
// (§7.4, RH-8), the canonical array of the grant's delegatees, or none.
func TestPGGroupCommitViaPerWrite(t *testing.T) {
	opPub, opPriv := grant.GenerateKey()
	ops, err := grant.ParseKeys(jsonv.FromGo([]any{map[string]any{"kid": "operator", "alg": "ed25519", "pub": opPub, "can": []any{"*"}}}))
	if err != nil {
		t.Fatal(err)
	}
	lim := DefaultLimits()
	fast := Rate{1e9, 1e9}
	lim.RatePerResource, lim.RatePerPrincipal, lim.RatePerNamespace = fast, fast, fast
	e, err := Open(Options{Path: pgtest.NewDB(t), BlobStore: fileBlobs(t), OperatorKeys: ops, RetentionInterval: -1, Remote: RemoteOptions{FollowInterval: -1},
		Limits: lim, TailInterval: tailEvery, Purger: discardPurger{}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close() })
	e.noSolo = true
	e.opt.GroupCommitWait = 5 * time.Second
	exp := time.Now().Add(time.Hour).Format(time.RFC3339)
	pub, priv := grant.GenerateKey()
	can := []any{"read", "create", "append"}
	opG, err := grant.Mint(map[string]any{"kid": "operator", "sub": "op:root", "ns": []any{"n"}, "can": []any{"config"}, "exp": exp}, opPriv)
	if err != nil {
		t.Fatal(err)
	}
	doc := map[string]any{"read": "public", "keys": []any{map[string]any{"kid": "k", "alg": "ed25519", "pub": pub, "can": can}}}
	if _, err := e.WriteConfig(context.Background(), Request{NS: "n", Cred: Credentials{Bearer: opG.Encode()}}, ConfigChange{IfNoneMatch: true, Patches: []any{map[string]any{"op": "add", "path": "", "value": doc}}}); err != nil {
		t.Fatal(err)
	}
	root, err := grant.Mint(map[string]any{"kid": "k", "sub": "svc:w", "ns": []any{"n"}, "can": can, "exp": exp}, priv)
	if err != nil {
		t.Fatal(err)
	}
	nar, err := root.Narrow(map[string]any{"via": "svc:relay"})
	if err != nil {
		t.Fatal(err)
	}
	grants := []string{nar.Encode(), root.Encode()}
	sizes := groupSizes(e)
	holdChecked(t, e, 2, nil)
	res, errs := concurrently(2, func(i int) (*WriteResult, error) {
		it := Item{Resource: fmt.Sprint("c", i), IfNoneMatch: true, Steps: []Step{{Patches: []any{map[string]any{"op": "add", "path": "", "value": map[string]any{"n": float64(i)}}}}}}
		return e.WriteResource(context.Background(), Request{NS: "n", Cred: Credentials{Bearer: grants[i]}}, it)
	})
	for i, err := range errs {
		if err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}
	if got := sizes(); len(got) != 1 || got[0] != 2 {
		t.Fatalf("group attempts %v, want one of 2", got)
	}
	for i, r := range res {
		var via sql.NullString
		id, _ := ids.Parse(r.NSID)
		if err := e.db.QueryRow(`SELECT via FROM ns_log WHERE id = $1`, id[:]).Scan(&via); err != nil {
			t.Fatal(err)
		}
		if want := []string{`["svc:relay"]`, ""}[i]; via.String != want || via.Valid != (want != "") {
			t.Errorf("write %d recorded via %v, want %q", i, via, want)
		}
	}
	lg, err := e.NamespaceLog(context.Background(), "n", "", "", 0, Credentials{})
	if err != nil {
		t.Fatal(err)
	}
	var vias []any
	for _, m := range lg.Entries[1:] {
		vias = append(vias, m["via"])
	}
	if string(jsonv.Canonical(vias)) != `[["svc:relay"],null]` && string(jsonv.Canonical(vias)) != `[null,["svc:relay"]]` {
		t.Errorf("served vias %s", jsonv.Canonical(vias))
	}
}
