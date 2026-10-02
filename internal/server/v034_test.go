package server

import (
	"strings"
	"testing"
)

// Spec v0.34: drafts (§6.1, §7.4, §7.5) and forcing in_use (§3.5, §6.1,
// §8.5).

func (e *tenv) nsDoc(ns string, bearer ...string) map[string]any {
	e.t.Helper()
	r := e.get("/ns/"+ns+"/rev/"+e.nsHead(ns, bearer...), bearer...)
	expect(e.t, r, 200)
	return r.Obj()
}

// branchEntry returns the GET /ns/{ns}/branches entry of a branch.
func (e *tenv) branchEntry(ns, name string, bearer ...string) map[string]any {
	e.t.Helper()
	r := e.get("/ns/"+ns+"/branches", bearer...)
	expect(e.t, r, 200)
	for _, x := range r.Arr() {
		if m := x.(map[string]any); m["name"] == name {
			return m
		}
	}
	e.t.Fatalf("no branch %s in %s", name, r.Body)
	return nil
}

// §7.4: drafts is only for local branches that aren't e2e, "*" serves
// every namespace, it isn't inherited (nor are merged and abandoned), and
// the branch listing shows it.
func TestV034DraftsMember(t *testing.T) {
	e := newEnv(t)
	e.mkNS("schemas", map[string]any{})
	e.mkNS("matches", map[string]any{})
	expect(t, e.branch("schemas", map[string]any{"name": "schemas-r7", "patches": addDrafts("*")}, "admin"), 201)
	t1 := e.create("schemas-r7", "team", teamSchema())
	draft := "/r/schemas/team/rev/" + t1
	expect(t, e.branch("matches", map[string]any{"name": "matches-r9"}, "admin"), 201)
	// A bare "*" serves every namespace.
	expect(t, e.typed("matches-r9", "m1", draft), 201)

	// The listing shows each branch's drafts.
	d, _ := e.branchEntry("schemas", "schemas-r7")["drafts"].(map[string]any)
	if f, _ := d["for"].([]any); len(f) != 1 || f[0] != "*" {
		t.Fatalf("listing drafts %v", e.branchEntry("schemas", "schemas-r7"))
	}
	if _, has := e.branchEntry("matches", "matches-r9")["drafts"]; has {
		t.Fatal("a branch without drafts lists drafts")
	}

	// Not inherited: a branch of the draft branch starts without drafts,
	// merged or abandoned.
	expect(t, e.patchNS("schemas-r7", ops(op("add", "/merged", map[string]any{"at": e.nsHead("schemas")}), op("add", "/abandoned", true)), ""), 201)
	expect(t, e.branch("schemas-r7", map[string]any{"name": "schemas-r7-b"}, "admin"), 201)
	doc := e.nsDoc("schemas-r7-b")
	for _, k := range []string{"drafts", "merged", "abandoned", "frozen", "successor"} {
		if _, has := doc[k]; has {
			t.Fatalf("branch inherited %s: %v", k, doc)
		}
	}
	// The child serves itself and its branches only: its parent's drafts.for
	// isn't its own.
	t2 := e.appendRev("schemas-r7-b", "team", t1, ops(op("add", "/properties/coach", map[string]any{"type": "string"})))
	expectCode(t, e.typed("matches-r9", "m2", "/r/schemas/team/rev/"+t2), 422, "schema_unavailable")

	// e2e branches can't have drafts.
	r := e.branch("schemas", map[string]any{"name": "schemas-e2e", "patches": ops(
		op("add", "/encryption", map[string]any{"level": "e2e"}),
		op("add", "/drafts", map[string]any{"for": strs([]string{"matches"})}))}, "admin")
	expectCode(t, r, 422, "invalid")
	if !strings.Contains(r.String(), "drafts") {
		t.Fatalf("e2e drafts refusal: %s", r.Body)
	}
}

// §7.4: drafts is 422 in a remote branch (and its branches), where it could
// have no effect.
func TestV034DraftsRemote(t *testing.T) {
	a, b, _ := pair(t, nil, nil)
	a.mkNS("main", map[string]any{"read": "public"})
	a.create("main", "x", map[string]any{"v": 1.0})
	r := b.mkRemote("rel", remoteGenesis("main", a.nsHead("main"), map[string]any{"drafts": map[string]any{"for": strs([]string{"other"})}}))
	expectCode(t, r, 422, "invalid")
	expect(t, b.mkRemote("rel", remoteGenesis("main", a.nsHead("main"), nil)), 201)
	expectCode(t, b.patchNS("rel", addDrafts("other"), ""), 422, "invalid")
	expectCode(t, b.branch("rel", map[string]any{"name": "rel-b", "patches": addDrafts("other")}, "admin"), 422, "invalid")
	expect(t, b.branch("rel", map[string]any{"name": "rel-b"}, "admin"), 201)
	expectCode(t, b.patchNS("rel-b", addDrafts("other"), ""), 422, "invalid")
}

// §6.1, §7.5: a path N can't resolve for the writer because the writer
// can't read it there falls through to drafts; the read in N is by the
// rule for other namespaces too (§6.1 Read permission).
func TestV034DraftsUnreadableN(t *testing.T) {
	e := newAuthEnv(t)
	kS, kM := newKey("ks"), newKey("km")
	e.mkNS("schemas", map[string]any{"read": "grant", "keys": []any{kS.entry("*")}})
	e.mkNS("matches", map[string]any{"read": "grant", "keys": []any{kM.entry("*")}})
	sAdmin := e.grant(kS, "user:s", []string{"schemas", "schemas-r7"}, allVerbs)
	mAdmin := e.grant(kM, "user:m", []string{"matches", "matches-r7"}, allVerbs)
	expect(t, e.branch("schemas", map[string]any{"name": "schemas-r7", "patches": addDrafts("matches-r7")}, sAdmin), 201)
	expect(t, e.branch("matches", map[string]any{"name": "matches-r7"}, mAdmin), 201)
	genesis := addRoot(teamSchema())
	r := e.write("PATCH", "schemas-r7", "team", "", genesis, sAdmin)
	expect(t, r, 201)
	t1 := etagOf(r)
	// Fast-forwarded: schemas has the revision too.
	expect(t, e.batchReq("schemas", map[string]any{"items": []any{map[string]any{"resource": "team", "ifNoneMatch": "*", "steps": []any{genesis}}}}, sAdmin), 201)
	draft := "/r/schemas/team/rev/" + t1
	writeWith := func(name string, ns string, src ...string) *resp {
		t.Helper()
		return e.doMulti("/r/"+ns+"/"+name, mAdmin, addRoot(map[string]any{"$schema": draft, "team": "x"}), "Source-Authorization", src)
	}
	// Neither copy is readable.
	expectCode(t, writeWith("a", "matches-r7"), 422, "schema_unavailable")
	// A grant for the draft branch only: schemas is unreadable for the
	// writer, so the path falls through to the draft.
	branchOnly := e.grant(kS, "user:m", []string{"schemas-r7"}, []string{"read"})
	expect(t, writeWith("b", "matches-r7", "Bearer "+branchOnly), 201)
	// In a namespace that isn't a branch nothing falls through.
	expectCode(t, writeWith("b", "matches", "Bearer "+branchOnly), 422, "schema_unavailable")
	// A Source-Authorization grant reading schemas serves in N.
	baseRead := e.grant(kS, "user:m", []string{"schemas"}, []string{"read"})
	expect(t, writeWith("c", "matches", "Bearer "+baseRead), 201)
}

// §7.5, §7.8: a blob copy's source is read with the request's grant or any
// in Source-Authorization, not only the header's.
func TestV034BlobCopyEitherGrant(t *testing.T) {
	e := newAuthEnv(t, withBlobTuning)
	k := newKey("k")
	kx := newKey("kx")
	e.mkNS("src", map[string]any{"read": "grant", "keys": []any{k.entry("*")}})
	e.mkNS("dst", map[string]any{"read": "grant", "keys": []any{k.entry("*"), kx.entry("read")}})
	both := e.grant(k, "user:b", []string{"src", "dst"}, allVerbs)
	data := []byte("shared")
	bid := e.upload("src", "a", "text/plain", data, both)
	e.create("src", "a", map[string]any{"b": ref(bid, "text/plain", len(data), "")}, both)
	from := blobPath("src", "a", bid)
	// A Source-Authorization grant that doesn't read the source no longer
	// hides the request's own, which does.
	other := e.grant(kx, "user:x", []string{"dst"}, []string{"read"})
	expect(t, e.copyBlob("dst", "a", bid, from, other, both), 201)
	// Neither serves: 404.
	dstOnly := e.grant(k, "user:d", []string{"dst"}, allVerbs)
	expectCode(t, e.copyBlob("dst", "c", bid, from, other, dstOnly), 404, "not_found")
}

// §3.5, §6.1, §8.5: forcing an in_use purge takes ?force=1 with a
// deployment operator key, or a * key of the branch for purges in a
// branch; every entry it writes, propagated ones included, says forced:
// true, which is part of the hashed entry.
func TestV034ForcedPurge(t *testing.T) {
	e := newAuthEnv(t)
	kS, kM := newKey("ks"), newKey("km")
	e.mkNS("schemas", map[string]any{"read": "grant", "keys": []any{kS.entry("*")}})
	e.mkNS("matches", map[string]any{"read": "grant", "keys": []any{kM.entry("*")}})
	sAdmin := e.grant(kS, "user:s", []string{"schemas", "schemas-b"}, allVerbs)
	mAdmin := e.grant(kM, "user:m", []string{"matches"}, allVerbs)
	t1 := e.create("schemas", "team", teamSchema(), sAdmin)
	expect(t, e.branch("schemas", map[string]any{"name": "schemas-b"}, sAdmin), 201)
	sRead := e.grant(kS, "user:m", []string{"schemas"}, []string{"read"})
	expect(t, e.doMulti("/r/matches/m1", mAdmin, addRoot(map[string]any{"$schema": "/r/schemas/team/rev/" + t1, "team": "x"}), "Source-Authorization", []string{"Bearer " + sRead}), 201)

	purge := func(bearer string, force bool, src ...string) *resp {
		t.Helper()
		path := "/r/schemas/team/purge"
		if force {
			path += "?force=1"
		}
		q := req{method: "POST", path: path, ifMatch: t1, bearer: bearer, hdr: map[string]string{}}
		if len(src) > 0 {
			q.hdr["Source-Authorization"] = src[0]
		}
		return e.do(q)
	}
	r := purge(sAdmin, false)
	expectCode(t, r, 409, "in_use")
	if got := referencing(r); len(got) != 0 {
		t.Fatalf("referencing %v listed to a caller who can't read matches", got)
	}
	// The rule for other namespaces: a Source-Authorization grant reading
	// anything in matches (one resource suffices) lists it.
	oneDoc := e.grant(kM, "user:s", []string{"matches"}, []string{"read"}, map[string]any{"rules": []any{map[string]any{"op": "test", "path": "/resource", "value": "m1"}}})
	if got := referencing(purge(sAdmin, false, "Bearer "+oneDoc)); len(got) != 1 || got[0] != "matches" {
		t.Fatalf("referencing with a per-resource reader: %v", got)
	}
	// A * key of a namespace that isn't a branch doesn't force.
	expectCode(t, purge(sAdmin, true), 403, "forbidden")
	// The deployment operator does.
	op := mint(t, e.opPriv, map[string]any{"kid": "operator", "sub": "op:root", "ns": []any{"schemas"}, "can": []any{"purge", "purge-ns"},
		"exp": e.clock.Now().Add(1e12).Format("2006-01-02T15:04:05Z07:00")})
	before := e.nsHead("schemas", sAdmin)
	beforeB := e.nsHead("schemas-b", sAdmin)
	expect(t, purge(op, true), 204)
	for _, x := range []struct{ ns, before string }{{"schemas", before}, {"schemas-b", beforeB}} {
		lg := e.get("/ns/"+x.ns+"/rev/"+e.nsHead(x.ns, sAdmin)+"/log?since="+x.before, sAdmin).Arr()
		if len(lg) != 1 {
			t.Fatalf("%s: %d entries", x.ns, len(lg))
		}
		en := lg[0].(map[string]any)
		want := map[string]any{"resource": "team", "kind": "purge", "target": t1, "forced": true}
		if en["forced"] != true || en["id"] != hashID(t, x.before, canonical(want)) {
			t.Fatalf("%s: forced purge entry %v", x.ns, en)
		}
	}
	// A purge nothing refuses isn't forced, ?force=1 or not.
	t2 := e.create("schemas", "free", teamSchema("z"), sAdmin)
	before = e.nsHead("schemas", sAdmin)
	expect(t, e.do(req{method: "POST", path: "/r/schemas/free/purge?force=1", ifMatch: t2, bearer: sAdmin}), 204)
	lg := e.get("/ns/schemas/rev/"+e.nsHead("schemas", sAdmin)+"/log?since="+before, sAdmin).Arr()
	if en := lg[0].(map[string]any); en["forced"] != nil {
		t.Fatalf("an unrefused purge says forced: %v", en)
	}
}

// §8.5: a namespace purge refused as in_use is forced the same way, and its
// purge-ns entry says forced: true.
func TestV034ForcedNamespacePurge(t *testing.T) {
	e := newEnv(t)
	e.mkNS("schemas", map[string]any{})
	e.mkNS("matches", map[string]any{})
	expect(t, e.branch("schemas", map[string]any{"name": "schemas-r7", "patches": addDrafts("matches-r7")}, "admin"), 201)
	t1 := e.create("schemas-r7", "team", teamSchema())
	expect(t, e.branch("matches", map[string]any{"name": "matches-r7"}, "admin"), 201)
	expect(t, e.typed("matches-r7", "m1", "/r/schemas/team/rev/"+t1), 201)
	expect(t, e.patchNS("schemas-r7", ops(op("add", "/frozen", true)), ""), 201)
	head := e.nsHead("schemas-r7")
	expectCode(t, e.do(req{method: "POST", path: "/ns/schemas-r7/purge", ifMatch: head, author: "admin"}), 409, "in_use")
	expect(t, e.do(req{method: "POST", path: "/ns/schemas-r7/purge?force=1", ifMatch: head, author: "admin"}), 204)
	lg := e.get("/ns/schemas-r7/rev/" + e.nsHead("schemas-r7") + "/log?since=" + head).Arr()
	en := lg[0].(map[string]any)
	if en["kind"] != "purge-ns" || en["forced"] != true || en["id"] != hashID(t, head, canonical(map[string]any{"kind": "purge-ns", "forced": true})) {
		t.Fatalf("forced purge-ns entry %v", en)
	}
}
