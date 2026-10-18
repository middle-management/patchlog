package server

import (
	"testing"
)

// move moves ns/old, whose head is head, to successor in one batch (§8.1):
// create new (unless "" or in another namespace), then append $successor
// to old and delete it. It returns the tombstone.
func (e *tenv) move(ns, old, head, newName, successor string, extra ...map[string]any) string {
	e.t.Helper()
	set := ops(op("add", "/$successor", successor))
	for _, x := range extra {
		set = append(set, x)
	}
	items := []any{map[string]any{"resource": old, "ifMatch": head, "steps": []any{set, "delete"}}}
	if newName != "" {
		create := map[string]any{"resource": newName, "ifNoneMatch": "*", "steps": []any{addRoot(map[string]any{"moved": "here"})}}
		items = append([]any{create}, items...)
	}
	r := e.do(req{method: "POST", path: "/ns/" + ns + "/batch", author: "alice", body: map[string]any{"items": items}})
	expect(e.t, r, 201)
	return e.head410(ns, old)["tombstone"].(string)
}

// head410 reads a tombstoned head's 410 body, checking HEAD answers alike
// and a second read (the read cache) the same.
func (e *tenv) head410(ns, name string, bearer ...string) map[string]any {
	e.t.Helper()
	r := e.get("/r/"+ns+"/"+name, bearer...)
	expectCode(e.t, r, 410, "gone")
	if again := e.get("/r/"+ns+"/"+name, bearer...); string(again.Body) != string(r.Body) {
		e.t.Fatalf("cached 410 %s, first %s", again.Body, r.Body)
	}
	q := req{method: "HEAD", path: "/r/" + ns + "/" + name}
	if len(bearer) > 0 {
		q.bearer = bearer[0]
	}
	if h := e.do(q); h.Code != 410 || len(h.Body) != 0 || h.H.Get("ETag") != r.H.Get("ETag") {
		e.t.Fatalf("HEAD %d %v", h.Code, h.H)
	}
	return r.Obj()
}

// §8.1 moves: the head's 410 copies successor from the last document's
// well-formed $successor, a bare name or /r/{ns}/{name}, and omits one of
// any other form; validation leaves it out (§6.2 step 5), so a closed
// schema needn't declare it; a [] restore brings the document back with
// it (§8.2); a branch reading the tombstone through serves it too; an
// at-rest namespace reads it through its encryption.
func TestSuccessor410(t *testing.T) {
	t.Parallel()
	e := newSealedEnv(t)
	e.mkNS("schemas", map[string]any{"read": "public"})
	e.mkNS("n", map[string]any{"read": "public"})
	closed := e.create("schemas", "closed", map[string]any{"$schema": dialect, "type": "object",
		"properties": map[string]any{"a": map[string]any{"type": "number"}}, "additionalProperties": false})
	ref := "/r/schemas/closed/rev/" + closed

	for _, c := range []struct{ old, newName, successor string }{
		{"a", "a2", "a2"},
		{"b", "", "/r/elsewhere/b-moved"},
	} {
		head := e.create("n", c.old, map[string]any{"$schema": ref, "a": 1.0})
		tomb := e.move("n", c.old, head, c.newName, c.successor)
		b := e.head410("n", c.old)
		if b["tombstone"] != tomb || b["successor"] != c.successor || b["last"] == nil {
			t.Fatalf("%s: 410 %v", c.old, b)
		}
		last := e.get("/r/n/" + c.old + "/rev/" + b["last"].(string))
		expect(t, last, 200)
		if last.Obj()["$successor"] != c.successor {
			t.Fatalf("%s: last document %s", c.old, last.Body)
		}
	}
	// A malformed $successor is data: a closed schema refuses it, and an
	// untyped document keeps it, which the 410 doesn't name.
	h := e.create("n", "c", map[string]any{"$schema": ref, "a": 1.0})
	expectCode(t, e.write("PATCH", "n", "c", h, ops(op("add", "/$successor", "Not A Name"))), 422, "invalid")
	for i, bad := range []any{"", "Not A Name", "/r/n/a/b", "/r/n.x/a", "/r/n/", 3.0, map[string]any{"ns": "n"}} {
		name := "u" + string(rune('0'+i))
		head := e.create("n", name, map[string]any{"x": 1.0})
		if e.move("n", name, head, "", "") == "" {
			t.Fatal("no tombstone")
		}
		_ = e.create("n", name+"b", map[string]any{"$successor": bad})
		e.del("n", name+"b", e.head("n", name+"b"))
		for _, n := range []string{name, name + "b"} {
			if b := e.head410("n", n); b["successor"] != nil {
				t.Fatalf("%s, $successor %v: 410 %v", n, bad, b)
			}
		}
	}

	// A [] restore brings the document back with $successor (§8.2); a
	// client restoring a moved resource removes it.
	tomb := e.head410("n", "a")["tombstone"].(string)
	restored := e.appendRev("n", "a", tomb, []any{})
	if d := e.doc("n", "a"); d["$successor"] != "a2" {
		t.Fatalf("restored %v", d)
	}
	e.appendRev("n", "a", restored, ops(op("remove", "/$successor")))

	// A branch reads a moved resource through: the 410 is the base's,
	// with its successor, resolved by the client against the branch.
	expect(t, e.branch("n", map[string]any{"name": "br", "at": e.nsHead("n"), "patches": []any{}}, "alice"), 201)
	if b := e.head410("br", "b"); b["successor"] != "/r/elsewhere/b-moved" {
		t.Fatalf("branch read-through 410 %v", b)
	}
	// And a move of its own, out of a read-through resource.
	bh := e.create("n", "d", map[string]any{"d": 1.0})
	expect(t, e.branch("n", map[string]any{"name": "br2", "at": e.nsHead("n"), "patches": []any{}}, "alice"), 201)
	e.move("br2", "d", bh, "d2", "d2")
	if b := e.head410("br2", "d"); b["successor"] != "d2" {
		t.Fatalf("branch move 410 %v", b)
	}
	if r := e.get("/r/n/d"); r.Code != 302 {
		t.Fatalf("base after the branch's move: %d", r.Code)
	}

	// At rest (E1): the document is decrypted to read it.
	e.mkNS("r", map[string]any{"read": "public", "encryption": map[string]any{"level": "at-rest"}})
	rh := e.create("r", "x", map[string]any{"x": 1.0})
	e.move("r", "x", rh, "y", "y")
	if b := e.head410("r", "x"); b["successor"] != "y" {
		t.Fatalf("at-rest 410 %v", b)
	}
}

// A sealed namespace's 410 is clear metadata, so it names no successor
// (§8.1, §E.2.2); a client reads $successor from the document at last,
// which it opens with its keys (client.Moved).
func TestSuccessor410Sealed(t *testing.T) {
	t.Parallel()
	e := newSealedEnv(t)
	e.mkNS("s", sealedDoc(map[string]any{"read": "public"}))
	h := e.wr("s", "x", "", withNonce(addRoot(map[string]any{"x": 1.0})))
	h = e.wr("s", "x", h, withNonce(ops(op("add", "/$successor", "y"))))
	e.del("s", "x", h)
	b := e.head410("s", "x")
	if _, ok := b["successor"]; ok || b["last"] != h {
		t.Fatalf("sealed 410 %v", b)
	}
	// A sealed branch of a plain base, reading a moved resource through,
	// names none either: the namespace serving the 410 decides.
	e.mkNS("p", map[string]any{"read": "public"})
	ph := e.create("p", "m", map[string]any{"m": 1.0})
	e.move("p", "m", ph, "m2", "m2")
	expect(t, e.branch("p", map[string]any{"name": "sb", "at": e.nsHead("p"), "patches": ops(op("add", "/encryption", map[string]any{"level": "sealed"}))}, "alice"), 201)
	if b := e.head410("sb", "m"); b["successor"] != nil {
		t.Fatalf("sealed branch 410 %v", b)
	}
	if b := e.head410("p", "m"); b["successor"] != "m2" {
		t.Fatalf("plain base 410 %v", b)
	}
}

// A remote branch reads a moved resource's last document from the chain
// it mirrors (§G.3), so its 410 names the successor as A's does.
func TestSuccessor410Remote(t *testing.T) {
	t.Parallel()
	a, b, _ := pair(t, nil, nil)
	a.mkNS("main", map[string]any{"read": "public"})
	h := a.create("main", "x", map[string]any{"x": 1.0})
	a.move("main", "x", h, "y", "y")
	expect(t, b.mkRemote("rel", remoteGenesis("main", a.nsHead("main"), nil)), 201)
	if got := b.head410("rel", "x"); got["successor"] != "y" || got["tombstone"] != a.head410("main", "x")["tombstone"] {
		t.Fatalf("remote branch 410 %v", got)
	}
}
