package server

import (
	"strings"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/seal"
)

// Spec v0.73 (P04, seal formats) at the wire: what a sealed (E2) namespace
// serves is in the §E.2.2 formats.

// A large, compressible document is served without a zip header (§E.2.2:
// sealed payloads are never compressed, v0.65).
func TestV073P04SealedNoZip(t *testing.T) {
	t.Parallel()
	e := newSealedEnv(t)
	e.mkNS("s", sealedDoc(map[string]any{"read": "public"}))
	big := strings.Repeat("compressible ", 400)
	id := e.wr("s", "x", "", withNonce(addRoot(map[string]any{"v": encMarker, "big": big})))
	keys, r := e.keysOf("s", nil, "")
	expect(t, r, 200)
	ke := keys["s#1"]
	if ke == nil {
		t.Fatalf("keys %v", keys)
	}

	dr := e.get("/r/s/x/rev/" + id)
	expect(t, dr, 200)
	h, err := seal.ParseHeader(string(dr.Body))
	if err != nil {
		t.Fatal(err)
	}
	if h.Zip != "" || strings.Contains(string(h.Raw), `"zip"`) {
		t.Fatalf("a sealed document carries a zip header: %s", h.Raw)
	}
	if pt := open(t, string(dr.Body), resKey(t, ke, "s", "x"), "s#1", seal.ResourcePL("s", "x", id, seal.KindDoc)); !strings.Contains(string(pt), big) {
		t.Fatalf("document %s", pt)
	}
}

// The namespace document is sealed with pl {ns, id, kind: "doc"}, compared
// exactly here: readers also accept the legacy "config" (§E.2.2 table,
// v0.63).
func TestV073P04NamespaceDocPL(t *testing.T) {
	t.Parallel()
	e := newSealedEnv(t)
	e.mkNS("s", sealedDoc(map[string]any{"read": "public"}))
	keys, r := e.keysOf("s", nil, "")
	expect(t, r, 200)
	head := e.nsHead("s")
	nr := e.get("/ns/s/rev/" + head)
	expect(t, nr, 200)
	h, err := seal.ParseHeader(string(nr.Body))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(jsonv.Canonical(map[string]any(h.PL))), `{"id":"`+head+`","kind":"doc","ns":"s"}`; got != want {
		t.Fatalf("namespace document pl %s, want %s", got, want)
	}
	open(t, string(nr.Body), keys["s#1"], "s#1", seal.NamespaceDocPL("s", head))
}

// An E3 prune's snapshot is bound to pl {ns, name, id}, with no kind
// (§E.3.1, §8.6, v0.63): the gate refuses the pre-v0.63 pl with kind
// "snapshot" (422 invalid) and takes the new one.
func TestV073P04E2EPruneSnapshotPL(t *testing.T) {
	t.Parallel()
	f := newE2E(t, withArchive(t, t.TempDir()))
	e := f.tenv
	k := seal.NewKey()
	ids := []string{etagOf(e.writeRaw("e", "p", "", sealed(t, k, "e#1", "e", "p", "", addRoot(map[string]any{"n": 0.0})), f.writerG))}
	for i := 1; i < 3; i++ {
		ids = append(ids, etagOf(e.writeRaw("e", "p", ids[i-1], sealed(t, k, "e#1", "e", "p", ids[i-1], ops(op("replace", "/n", float64(i)))), f.writerG)))
	}
	e.clock.Advance(10 * time.Minute)
	h := ids[1]
	legacy, err := seal.Seal(k, "e#1", seal.PL{"ns": "e", "name": "p", "id": h, "kind": seal.KindSnapshot}, jsonv.Canonical(map[string]any{"n": 1.0}))
	if err != nil {
		t.Fatal(err)
	}
	expectCode(t, e.prune("e", "p", map[string]any{"horizon": h, "snapshot": legacy}, f.writerG), 422, "invalid")
	snap, err := seal.SealSnapshot(k, "e#1", "e", "p", h, map[string]any{"n": 1.0})
	if err != nil {
		t.Fatal(err)
	}
	if hd, _ := seal.ParseHeader(snap); string(jsonv.Canonical(map[string]any(hd.PL))) != `{"id":"`+h+`","name":"p","ns":"e"}` {
		t.Fatalf("snapshot header %s", hd.Raw)
	}
	// No retention rule matches p: moving its horizon needs a * key (§8.6).
	expect(t, e.prune("e", "p", map[string]any{"horizon": h, "snapshot": snap}, f.adminG), 200)
}
