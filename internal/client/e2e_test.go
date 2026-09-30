package client_test

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/archive"
	"github.com/middle-management/patchlog/internal/bundle"
	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/merge"
	"github.com/middle-management/patchlog/internal/seal"
)

func sameJSON(t *testing.T, got, want any) {
	t.Helper()
	g, w := jsonv.Canonical(jsonv.FromGo(got)), jsonv.Canonical(jsonv.FromGo(want))
	if !bytes.Equal(g, w) {
		t.Fatalf("got %s, want %s", g, w)
	}
}

// A key-holding client seals writes, folds and verifies reads, validates
// against $schema and flags what doesn't, prunes with a sealed snapshot,
// and administers the keyring (Addendum E.3).
func TestE2EClient(t *testing.T) {
	ctx := context.Background()
	arch, err := archive.NewDir(archive.URL(t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	s := clienttest.New(t, clienttest.Options{Auth: true, KeyStore: keyStore(t), Archiver: arch})
	admin, writer := clienttest.NewKey("admin"), clienttest.NewKey("writer")
	opc := s.Client(t, client.WithBearer(s.OperatorGrant(t, "e")))
	must(opc.CreateNamespace(ctx, "e", map[string]any{"keys": []any{admin.Entry("*"), writer.Entry("read", "create", "append", "restore", "delete", "prune", "branch")},
		"encryption": map[string]any{"level": "e2e"}}))
	must(s.Client(t, client.WithBearer(s.OperatorGrant(t, "schemas"))).CreateNamespace(ctx, "schemas", map[string]any{"read": "public", "keys": []any{admin.Entry("*")}}))

	all := []string{"read", "create", "append", "restore", "delete", "config", "branch", "purge", "prune", "export"}
	adminJWK, adminPriv, _ := seal.GenerateRecipient()
	writerJWK, writerPriv, _ := seal.GenerateRecipient()
	readerJWK, readerPriv, _ := seal.GenerateRecipient()
	now := s.Now()
	adminC := s.Client(t, client.WithBearer(admin.Grant(t, now, "user:admin", []string{"e", "eb", "schemas"}, all, map[string]any{"enc": adminJWK})))
	ad := adminC.E2E(adminPriv)
	wc := s.Client(t, client.WithBearer(writer.Grant(t, now, "user:writer", []string{"e", "eb"}, []string{"read", "create", "append", "restore", "delete", "prune"}, map[string]any{"enc": writerJWK})))
	w := wc.E2E(writerPriv)
	rc := s.Client(t, client.WithBearer(writer.Grant(t, now, "user:reader", []string{"e"}, []string{"read"}, map[string]any{"enc": readerJWK})))
	rd := rc.E2E(readerPriv)

	// A schema in a public namespace, referenced from sealed documents.
	sch := must(adminC.CreateDoc(ctx, "schemas", "item", map[string]any{"$schema": "https://json-schema.org/draft/2020-12/schema",
		"type": "object", "properties": map[string]any{"n": map[string]any{"type": "number"}}}))
	ref := "/r/schemas/item/rev/" + sch.ID

	// The keyring: the admin, the writer and the reader.
	must(ad.InitKeyring(ctx, "e", writerPriv.PublicKey(), readerPriv.PublicKey()))

	// Writes: create, append, delete, restore ([] and sealed).
	marker := "zqx-e2e-marker"
	c0 := must(w.CreateDocSealed(ctx, "e", "d", map[string]any{"$schema": ref, "title": marker, "n": 0}))
	c1 := must(w.AppendSealed(ctx, "e", "d", c0.ID, ops(op("replace", "/n", 1))))
	if _, err := w.AppendSealed(ctx, "e", "d", c1.ID, ops(op("replace", "/n", "one"))); err == nil || !strings.Contains(err.Error(), "$schema") {
		t.Fatalf("client-side validation: %v", err)
	}
	del := must(wc.Delete(ctx, "e", "d", c1.ID))
	r1 := must(w.RestoreSealed(ctx, "e", "d", del.ID, nil))
	del2 := must(wc.Delete(ctx, "e", "d", r1.ID))
	r2 := must(w.RestoreSealed(ctx, "e", "d", del2.ID, ops(op("add", "/restored", true))))
	want := map[string]any{"$schema": ref, "title": marker, "n": 1, "restored": true}
	for _, x := range []*client.E2E{w, rd, ad} {
		h, d := must2(x.LoadE2E(ctx, "e", "d"))
		if h.ID != r2.ID || d.ValidID != r2.ID || len(d.Flagged) != 0 {
			t.Fatalf("load %+v %+v", h, d)
		}
		sameJSON(t, d.Value, want)
	}
	sameJSON(t, must(rd.DocE2E(ctx, "e", "d", c0.ID)).Value, map[string]any{"$schema": ref, "title": marker, "n": 0})
	// The plain client sees ciphertext only: a fold redirect.
	if _, err := rc.Doc(ctx, "e", "d", c1.ID); err == nil {
		t.Fatal("plain Doc of e2e content")
	}

	// Idempotent retry with the exact same bytes.
	body := must(w.SealPatches(ctx, "e", "d", r2.ID, ops(op("replace", "/n", 2))))
	a := must(wc.Append(ctx, "e", "d", r2.ID, body))
	b := must(wc.Append(ctx, "e", "d", r2.ID, body))
	if a.ID != b.ID || !b.Replayed() {
		t.Fatalf("retry %v %v", a, b)
	}

	// A revision written without validation is flagged with its author and
	// left out of the fold.
	bad := must(w.WithoutValidation().AppendSealed(ctx, "e", "d", a.ID, ops(op("replace", "/n", "two"))))
	d := must(rd.DocE2E(ctx, "e", "d", bad.ID))
	if d.ValidID != a.ID || len(d.Flagged) != 1 || d.Flagged[0].ID != bad.ID || d.Flagged[0].Author != "user:writer" {
		t.Fatalf("flagged %+v", d)
	}
	if n, _ := d.Value.(map[string]any)["n"].(float64); n != 2 {
		t.Fatalf("value %v", d.Value)
	}
	good := must(w.AppendSealed(ctx, "e", "d", bad.ID, ops(op("replace", "/n", 3))))
	d = must(rd.DocE2E(ctx, "e", "d", good.ID))
	if d.ValidID != good.ID || len(d.Flagged) != 1 {
		t.Fatalf("after flag %+v", d)
	}
	want["n"] = 3
	sameJSON(t, d.Value, want)

	// Prune with a sealed snapshot: older revisions answer 410, folds start
	// from the snapshot.
	s.Clock.Advance(10 * time.Minute)
	pr := must(w.PruneE2E(ctx, "e", "d", a.ID))
	if pr.Horizon != a.ID || pr.NSID == "" {
		t.Fatalf("prune %+v", pr)
	}
	if _, err := rd.DocE2E(ctx, "e", "d", c1.ID); !client.IsPruned(err) {
		t.Fatalf("pruned: %v", err)
	}
	h, d := must2(rd.LoadE2E(ctx, "e", "d"))
	if h.ID != good.ID || len(d.Flagged) != 1 {
		t.Fatalf("after prune %+v", d)
	}
	sameJSON(t, d.Value, want)
	if _, err := wc.Prune(ctx, "e", "d", client.PruneRequest{Horizon: good.ID}); err == nil {
		t.Fatal("prune without snapshot")
	}

	// Rotation: the reader is removed; new writes use the new epoch; old
	// revisions still fold for key holders.
	e2 := must(ad.RotateEpoch(ctx, "e", writerPriv.PublicKey()))
	if e2 != 2 {
		t.Fatalf("epoch %d", e2)
	}
	keys := must(rc.FetchKeys(ctx, "e", nil, nil))
	if len(keys) != 1 || keys[0].Kid != "e#1" {
		t.Fatalf("removed reader keys %+v", keys)
	}
	n4 := must(w.AppendSealed(ctx, "e", "d", good.ID, ops(op("replace", "/n", 4))))
	if _, err := rd.DocE2E(ctx, "e", "d", n4.ID); !errors.Is(err, client.ErrNoKeys) {
		t.Fatalf("removed reader: %v", err)
	}
	want["n"] = 4
	sameJSON(t, must(w.DocE2E(ctx, "e", "d", n4.ID)).Value, want)
	sameJSON(t, must(ad.DocE2E(ctx, "e", "d", n4.ID)).Value, want)
	kr, _ := must2(ad.Keyring(ctx, "e"))
	if len(kr.Readers(2)) != 2 || len(kr.Readers(1)) != 3 {
		t.Fatalf("keyring readers %v %v", kr.Readers(1), kr.Readers(2))
	}
	// Adding the reader back wraps the current epoch for them.
	must(ad.AddReader(ctx, "e", readerPriv.PublicKey(), false))
	rd2 := rc.E2E(readerPriv)
	sameJSON(t, must(rd2.DocE2E(ctx, "e", "d", n4.ID)).Value, want)

	// A branch is e2e; with its own keyring its writes bind the branch and
	// folds cross into the base's ciphertext.
	must(adminC.CreateBranch(ctx, "e", client.BranchRequest{Name: "eb"}))
	if lv := must(wc.EncryptionLevel(ctx, "eb")); lv != "e2e" {
		t.Fatalf("branch level %q", lv)
	}
	must(ad.InitKeyring(ctx, "eb", writerPriv.PublicKey()))
	b1 := must(w.AppendSealed(ctx, "eb", "d", n4.ID, ops(op("add", "/branch", true))))
	want["branch"] = true
	sameJSON(t, must(w.DocE2E(ctx, "eb", "d", b1.ID)).Value, want)

	// Tools that can't work over ciphertext refuse (merge without a
	// key-holding view, §F.8.1).
	if _, err := merge.NewPlan(ctx, adminC, "e", "eb", merge.Options{}); err == nil || !strings.Contains(err.Error(), "e2e") {
		t.Fatalf("merge: %v", err)
	}
	for _, mode := range []string{bundle.Snapshot, bundle.Full} {
		if _, err := bundle.PlanExport(ctx, adminC, bundle.ExportOptions{Select: []string{"e"}, Mode: mode}); err == nil || !strings.Contains(err.Error(), "e2e") {
			t.Fatalf("export %s: %v", mode, err)
		}
	}

	// Raw epoch keys work too.
	k1 := must(ad.Key(ctx, "e#1"))
	k2 := must(ad.Key(ctx, "e#2"))
	raw := rc.E2EKeys(map[string][]byte{"e#1": k1, "e#2": k2})
	sameJSON(t, must(raw.DocE2E(ctx, "e", "d", n4.ID)).Value, map[string]any{"$schema": ref, "title": marker, "n": 4, "restored": true})
}

func must2[A, B any](a A, b B, err error) (A, B) {
	if err != nil {
		panic(err)
	}
	return a, b
}
