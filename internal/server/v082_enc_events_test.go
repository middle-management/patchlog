package server

import (
	"context"
	"errors"
	"testing"

	"github.com/middle-management/patchlog/internal/core"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/seal"
)

// v82encSealed is the sealed count of key name ("" is K_n) of namespace
// ns, every epoch.
func v82encSealed(t *testing.T, path, ns, name string) int {
	t.Helper()
	db, pg := v0261DB(t, path)
	return v0261Count(t, db, pg, `SELECT COALESCE(SUM(sealed), 0) FROM seal_counts WHERE name = ? AND ns IN (SELECT ns FROM namespaces WHERE name = ?)`, name, ns)
}

// E2E-1 (§E.2.2 table, §7.3; scenario 69): a sealed namespace's event is
// its one entry in canonical JSON under K_n of the current epoch, with pl
// exactly { ns, event: id }. It isn't the one-entry range: neither its pl
// nor its bytes, and a range doesn't open as an event. E2E-2 (§E.2.2
// Stored once): it is sealed again with fresh bytes at every serve, never
// stored, and each sealing counts toward K_n's bound (§E.2.1).
func TestV082NamespaceEventPL(t *testing.T) {
	t.Parallel()
	var path string
	e := newSealedEnv(t, withFileDB(t), func(o *core.Options) { path = o.Path }, withSealBound(1<<20, 1<<19, 1))
	e.mkNS("s", sealedDoc(map[string]any{"read": "public"}))
	e.wr("s", "a", "", withNonce(addRoot(map[string]any{"v": 1.0})))
	e.wr("s", "b", "", withNonce(addRoot(map[string]any{"v": 1.0})))
	keys, kr := e.keysOf("s", nil, "")
	expect(t, kr, 200)
	kn := nsKey(t, keys["s#1"], "s")
	plain := e.plainNSLog("s", e.nsHead("s")).Entries
	db, pg := v0261DB(t, path)
	stored := v0261Count(t, db, pg, `SELECT COUNT(*) FROM sealed`)

	ch, _, cancel := e.openSSE("/ns/s/events", nil)
	first := map[string]string{}
	prev := ""
	for _, m := range plain {
		ev := next(t, ch)
		id := m["id"].(string)
		h, err := seal.ParseHeader(ev.data)
		if err != nil || ev.id != id || h.Kid != "s#1" || len(h.PL) != 2 || h.PL["ns"] != "s" || h.PL["event"] != id {
			t.Fatalf("event %s: header %s %v", id, h.Raw, err)
		}
		if pt := open(t, ev.data, kn, "s#1", seal.NamespaceEventPL("s", id)); string(pt) != string(canonical(m)) {
			t.Fatalf("event %s: %s", id, pt)
		}
		// Not a range: v0.81's pl, and the stored one-entry range.
		if _, err := seal.OpenExpect(ev.data, kn, "s#1", seal.RangePL("s", prev, id)); !errors.Is(err, seal.ErrMismatch) {
			t.Fatalf("event %s opens as the range (%s, %s]: %v", id, prev, id, err)
		}
		r := e.get("/ns/s/rev/" + id + "/log?since=" + prev)
		expect(t, r, 200)
		if _, err := seal.OpenExpect(string(r.Body), kn, "s#1", seal.NamespaceEventPL("s", id)); !errors.Is(err, seal.ErrMismatch) {
			t.Fatalf("the one-entry range (%s, %s] opens as an event: %v", prev, id, err)
		}
		first[id], prev = ev.data, id
	}
	cancel()

	// Served again: fresh bytes, nothing stored, each sealing counted.
	stored = v0261Count(t, db, pg, `SELECT COUNT(*) FROM sealed`) - stored
	if stored != len(plain) { // the one-entry ranges read above
		t.Fatalf("%d rows stored for %d ranges", stored, len(plain))
	}
	rows, before := v0261Count(t, db, pg, `SELECT COUNT(*) FROM sealed`), v82encSealed(t, path, "s", "")
	for i := 0; i < 2; i++ {
		lg, err := e.e.NamespaceEvents(context.Background(), "s", "", 0, core.Credentials{})
		if err != nil || len(lg.EntryJWEs) != len(plain) {
			t.Fatalf("events: %v", err)
		}
		for k, jwe := range lg.EntryJWEs {
			id := plain[k]["id"].(string)
			if jwe == first[id] {
				t.Fatalf("event %s served with the same bytes twice", id)
			}
			open(t, jwe, kn, "s#1", seal.NamespaceEventPL("s", id))
			first[id] = jwe
		}
	}
	if n := v0261Count(t, db, pg, `SELECT COUNT(*) FROM sealed`); n != rows {
		t.Fatalf("an event was stored: %d rows, were %d", n, rows)
	}
	if got := v82encSealed(t, path, "s", ""); got < before+2*len(plain) {
		t.Fatalf("K_n's count rose by %d for %d sealings", got-before, 2*len(plain))
	}
}

// E2E-2 (§E.2.2, §E.2.1): a resource's purge and prune events keep their
// pl, { ns, name, kind } under K_r, are sealed again at every serve, and
// every sealing counts toward K_r's bound.
func TestV082ResourceEventCounted(t *testing.T) {
	t.Parallel()
	var path string
	e := newSealedEnv(t, withFileDB(t), func(o *core.Options) { path = o.Path }, withSealBound(1<<20, 1<<19, 1))
	e.mkNS("s", sealedDoc(map[string]any{"read": "public"}))
	a1 := e.wr("s", "a", "", withNonce(addRoot(map[string]any{"v": 1.0})))
	since := e.nsHead("s")
	keys, kr := e.keysOf("s", nil, "")
	expect(t, kr, 200)
	expect(t, e.purge("s", "a", a1, "admin"), 204)
	before := v82encSealed(t, path, "s", "a")
	var seen []string
	for i := 0; i < 2; i++ {
		lg, err := e.e.ResourceEvents(context.Background(), "s", "a", since, 0, core.Credentials{})
		if err != nil || len(lg.EntryJWEs) != 1 {
			t.Fatalf("resource events: %+v %v", lg, err)
		}
		h, _ := seal.ParseHeader(lg.EntryJWEs[0])
		if len(h.PL) != 3 || h.PL["kind"] != "purge" {
			t.Fatalf("pl %s", h.Raw)
		}
		pt := open(t, lg.EntryJWEs[0], resKey(t, keys["s#1"], "s", "a"), "s#1", seal.ResourceEventPL("s", "a", seal.KindPurge))
		if m, _ := jsonv.MustParse(pt).(map[string]any); m["kind"] != "purge" || m["id"] != nil || m["prev"] != nil {
			t.Fatalf("purge event %s", pt)
		}
		seen = append(seen, lg.EntryJWEs[0])
	}
	if seen[0] == seen[1] {
		t.Fatal("the purge event was served with the same bytes twice")
	}
	if got := v82encSealed(t, path, "s", "a"); got < before+2 {
		t.Fatalf("K_r's count rose by %d for 2 sealings", got-before)
	}
}

// E2E-2, E2E-9 (§E.2.1 Message bound, §12.1; scenario 60): past the
// bound the event stream's sealings are refused, 503 behind with
// Retry-After, and none is made: the count never falls short of the
// sealings made.
func TestV082EventsPastBound(t *testing.T) {
	t.Parallel()
	var path string
	e := newSealedEnv(t, withFileDB(t), func(o *core.Options) { path = o.Path }, withSealBound(8, 1<<30, 1))
	boundNS(t, e) // K_n: four reserved and one sealed
	made := 0
	var err error
	for i := 0; i < 8 && err == nil; i++ {
		var lg *core.Log
		if lg, err = e.e.NamespaceEvents(context.Background(), "s", "", 1, core.Credentials{}); err == nil {
			made += len(lg.EntryJWEs)
		}
	}
	var ce *core.Error
	if !errors.As(err, &ce) || ce.Status != 503 || ce.Code() != "behind" || ce.Header.Get("Retry-After") == "" {
		t.Fatalf("events past the bound: %v", err)
	}
	if made != 3 {
		t.Fatalf("%d events sealed in the room of 3", made)
	}
	db, pg := v0261DB(t, path)
	if n := v0261Count(t, db, pg, `SELECT sealed + reserved FROM seal_counts WHERE name = ''`); n < 5+made || n > 8 {
		t.Fatalf("K_n counts %d after %d events", n, made)
	}
	// Over the wire: the stream's request is refused the same way.
	r := e.get("/ns/s/events")
	expectCode(t, r, 503, "behind")
	if r.H.Get("Retry-After") == "" {
		t.Fatalf("no Retry-After: %v", r.H)
	}
}

// E2E-9 (§E.2.1 Message bound: "counts may run over, never under"): two
// instances on one database each count from blocks they take; what is
// stored never falls short of the sealings made, whether a block is used
// up, left over at a restart or half given back by a refused read, and
// together they seal no more than the bound allows. Past it each answers
// 503 behind.
func TestV082SealCountNeverUnder(t *testing.T) {
	t.Parallel()
	var path string
	ks := newKeyStore(t)
	const bound = 24
	a := newSealedEnv(t, withFileDB(t), func(o *core.Options) { path = o.Path }, withKeyStore(ks), withSealBound(bound, 1<<30, 4))
	boundNS(t, a) // four entries reserved on K_n, one range sealed
	b := newSealedEnv(t, withPath(path), withKeyStore(ks), withSealBound(bound, 1<<30, 4))
	db, pg := v0261DB(t, path)
	stored := func() int {
		return v0261Count(t, db, pg, `SELECT COALESCE(SUM(sealed + reserved), 0) FROM seal_counts WHERE name = ''`)
	}
	made := 1 // boundNS's range
	check := func(what string) {
		t.Helper()
		if n := stored(); n < made+4 || n > bound {
			t.Fatalf("%s: %d counted for K_n with %d sealings made and 4 reserved, under a bound of %d", what, n, made, bound)
		}
	}
	check("after the first range")
	event := func(e *tenv) error {
		lg, err := e.e.NamespaceEvents(context.Background(), "s", "", 1, core.Credentials{})
		if err == nil {
			made += len(lg.EntryJWEs)
		}
		return err
	}
	// A request cancelled before it starts seals nothing and uncounts
	// nothing.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := a.e.NamespaceEvents(ctx, "s", "", 1, core.Credentials{}); err == nil {
		t.Fatal("a cancelled read succeeded")
	}
	check("after a cancelled read")
	var errA, errB error
	for i := 0; i < 2*bound && (errA == nil || errB == nil); i++ {
		if errA == nil {
			errA = event(a)
			check("a's event")
		}
		if errB == nil {
			errB = event(b)
			check("b's event")
		}
	}
	for _, err := range []error{errA, errB} {
		var ce *core.Error
		if !errors.As(err, &ce) || ce.Status != 503 || ce.Code() != "behind" || ce.Header.Get("Retry-After") == "" {
			t.Fatalf("past the bound: %v", err)
		}
	}
	if made+4 > bound || made < bound/2 {
		t.Fatalf("%d sealings made and 4 reserved under a bound of %d", made, bound)
	}
	// A third instance, as after a restart, starts from what is stored:
	// it has no room either.
	c := newSealedEnv(t, withPath(path), withKeyStore(ks), withSealBound(bound, 1<<30, 4))
	if err := event(c); err == nil {
		t.Fatal("a fresh instance sealed past the bound")
	}
	check("after a restart")
}
