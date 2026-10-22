package core

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"sync/atomic"
	"testing"

	"github.com/middle-management/patchlog/internal/grant"
)

// v073Create writes a create of name in n under cred.
func v073Create(e *Engine, cred Credentials, name string) (*WriteResult, error) {
	it := Item{Resource: name, IfNoneMatch: true, Steps: []Step{{Patches: []any{map[string]any{"op": "add", "path": "", "value": map[string]any{}}}}}}
	return e.WriteResource(context.Background(), Request{NS: "n", Cred: cred}, it)
}

// v073Status is the status of a core refusal, 0 for none.
func v073Status(err error) int {
	if e, ok := err.(*Error); ok {
		return e.Status
	}
	if err != nil {
		return -1
	}
	return 0
}

// The server stores a grant's authority block alone, as a SignedBlock
// (§C.3, §C.8, v0.63), and serves it as stored; a row stored before, the
// whole chain without proof, is served as its authority block too.
func TestV073StoredGrantIsAuthorityBlock(t *testing.T) {
	var clock atomic.Int64
	e, mint, _ := authEngine(t, &clock)
	ctx := context.Background()
	root, err := grant.Decode(mint(map[string]any{"kid": "k", "sub": "user:w", "ns": []any{"n"}, "can": []any{"create", "read"}}), 0)
	if err != nil {
		t.Fatal(err)
	}
	narrowed, err := root.Narrow(map[string]any{"via": "svc:importer"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v073Create(e, Credentials{Bearer: narrowed.Encode()}, "a"); err != nil {
		t.Fatal(err)
	}
	gid := narrowed.ID()
	authority := narrowed.SignedBlocks()[0]
	var stored []byte
	if err := e.read(ctx, func(t *tx) error {
		return t.QueryRow(`SELECT blocks FROM grants WHERE id = ?`, gid[:]).Scan(&stored)
	}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(stored, authority) || bytes.Contains(stored, []byte("svc:importer")) {
		t.Fatalf("stored %d bytes, want the %d-byte authority SignedBlock", len(stored), len(authority))
	}
	reader := Credentials{Bearer: mint(map[string]any{"kid": "k", "sub": "user:r", "ns": []any{"n"}, "can": []any{"read"}})}
	want := base64.RawURLEncoding.EncodeToString(authority)
	served := func() {
		t.Helper()
		doc, err := e.Grant(ctx, "n", gid.String(), reader)
		if err != nil {
			t.Fatal(err)
		}
		if len(doc.Stored) != 1 || doc.Stored[0] != want || doc.ID != gid.String() {
			t.Fatalf("served %v", doc.Stored)
		}
	}
	served()

	// A row from before: the chain as a Biscuit without proof.
	var legacy []byte
	for i, sb := range narrowed.SignedBlocks() {
		field := byte(3)
		if i == 0 {
			field = 2
		}
		legacy = append(legacy, field<<3|2)
		legacy = binary.AppendUvarint(legacy, uint64(len(sb)))
		legacy = append(legacy, sb...)
	}
	if err := e.update(ctx, func(t *tx) error {
		_, err := t.Exec(`UPDATE grants SET blocks = ? WHERE id = ?`, t.e.blobArg(legacy), gid[:])
		return err
	}); err != nil {
		t.Fatal(err)
	}
	served()
	if g, err := grant.ParseStored(legacy); err != nil || g.ID() != gid {
		t.Fatal("legacy row")
	}
}
