package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"testing"
)

// teamSchema is a schema whose documents need a string "team".
func teamSchema(extra ...string) map[string]any {
	props := map[string]any{"team": map[string]any{"type": "string"}}
	for _, p := range extra {
		props[p] = map[string]any{"type": "string"}
	}
	return map[string]any{"$schema": dialect, "type": "object", "properties": props, "required": []any{"team"}}
}

func addDrafts(list ...string) []any {
	return ops(op("add", "/drafts", map[string]any{"for": strs(list)}))
}

// typed creates a document with $schema ref in ns.
func (e *tenv) typed(ns, name, ref string, who ...string) *resp {
	e.t.Helper()
	return e.write("PATCH", ns, name, "", addRoot(map[string]any{"$schema": ref, "team": "x"}), who...)
}

// §6.1 Never into a branch, drafts in branches; §7.4 drafts.for.
func TestDraftSchemasResolve(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.mkNS("schemas", map[string]any{})
	e.mkNS("matches", map[string]any{})
	expect(t, e.branch("schemas", map[string]any{"name": "schemas-r7"}, "admin"), 201)
	t1 := e.create("schemas-r7", "team", teamSchema())
	draft := "/r/schemas/team/rev/" + t1
	expect(t, e.branch("matches", map[string]any{"name": "matches-r7"}, "admin"), 201)
	expect(t, e.branch("matches", map[string]any{"name": "matches-r8"}, "admin"), 201)
	expect(t, e.branch("matches-r7", map[string]any{"name": "matches-r7-x"}, "admin"), 201)

	// A path naming the branch is refused, drafts or not.
	expectCode(t, e.typed("schemas-r7", "a", "/r/schemas-r7/team/rev/"+t1), 422, "schema_ref")
	expectCode(t, e.typed("matches-r7", "a", "/r/schemas-r7/team/rev/"+t1), 422, "schema_ref")

	// The draft serves its own branch and its branches, always.
	expect(t, e.typed("schemas-r7", "doc", draft), 201)
	expect(t, e.branch("schemas-r7", map[string]any{"name": "schemas-r7-b"}, "admin"), 201)
	expect(t, e.typed("schemas-r7-b", "doc2", draft), 201)

	// Without drafts.for, nobody else.
	expectCode(t, e.typed("matches-r7", "m1", draft), 422, "schema_unavailable")

	// A revision a candidate reads through doesn't count there: schemas-r7-b
	// lists matches-r7 but only reads t1 through from schemas-r7.
	expect(t, e.patchNS("schemas-r7-b", addDrafts("matches-r7"), ""), 201)
	expectCode(t, e.typed("matches-r7", "m1", draft), 422, "schema_unavailable")
	// Its own revision does.
	t2 := e.appendRev("schemas-r7-b", "team", t1, ops(op("add", "/properties/coach", map[string]any{"type": "string"})))
	expect(t, e.typed("matches-r7", "m2", "/r/schemas/team/rev/"+t2), 201)
	expect(t, e.typed("matches-r7-x", "m2", "/r/schemas/team/rev/"+t2), 201)
	expectCode(t, e.typed("matches-r8", "m2", "/r/schemas/team/rev/"+t2), 422, "schema_unavailable")

	// drafts.for by name, then by prefix.
	expect(t, e.patchNS("schemas-r7", addDrafts("matches-r7"), ""), 201)
	expect(t, e.typed("matches-r7", "m1", draft), 201)
	expect(t, e.typed("matches-r7-x", "m1", draft), 201) // a branch of a listed namespace
	expectCode(t, e.typed("matches-r8", "m1", draft), 422, "schema_unavailable")
	expect(t, e.patchNS("schemas-r7", ops(op("replace", "/drafts/for", strs([]string{"matches-*", "matches"}))), ""), 201)
	expect(t, e.typed("matches-r8", "m1", draft), 201)

	// Paths in a namespace that isn't a branch resolve only there, even
	// when drafts.for names it.
	expectCode(t, e.typed("matches", "m1", draft), 422, "schema_unavailable")

	// The whole $ref closure resolves the same way.
	rt := e.create("schemas-r7", "match", map[string]any{"$schema": dialect, "type": "object",
		"properties": map[string]any{"home": map[string]any{"$ref": draft}}})
	expect(t, e.write("PATCH", "matches-r8", "m3", "", addRoot(map[string]any{"$schema": "/r/schemas/match/rev/" + rt, "home": map[string]any{"team": "a"}})), 201)
	expectCode(t, e.write("PATCH", "matches-r8", "m4", "", addRoot(map[string]any{"$schema": "/r/schemas/match/rev/" + rt, "home": map[string]any{"team": 3.0}})), 422, "invalid")

	// Within a batch to a branch, an earlier item's schema is a draft for
	// the later ones.
	s9 := addRoot(teamSchema("nine"))
	s9id := hashID(t, "", canonical(s9))
	body := map[string]any{"items": []any{
		map[string]any{"resource": "s9", "ifNoneMatch": "*", "steps": []any{s9}},
		map[string]any{"resource": "d9", "ifNoneMatch": "*", "steps": []any{addRoot(map[string]any{"$schema": "/r/schemas/s9/rev/" + s9id, "team": "t"})}},
	}}
	expect(t, e.batchReq("schemas-r7", body, "alice"), 201)
	expect(t, e.typed("matches-r8", "m9", "/r/schemas/s9/rev/"+s9id), 201)

	// drafts in a namespace document that isn't a branch's: invalid.
	expectCode(t, e.patchNS("matches", addDrafts("x"), ""), 422, "invalid")
	expectCode(t, e.patchNS("schemas-r7", addDrafts("Bad Name"), ""), 422, "invalid")
}

func referencing(r *resp) []string {
	var out []string
	arr, _ := r.Obj()["referencing"].([]any)
	for _, x := range arr {
		out = append(out, x.(string))
	}
	return out
}

// §6.1 Purged or unknown references: a purge that would remove the last
// copy satisfying a reference is in_use; a fast-forward leaves another
// copy; a forced purge goes ahead. §7.4: narrowing drafts.for is in_use.
func TestDraftSchemasInUse(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.mkNS("schemas", map[string]any{})
	e.mkNS("matches", map[string]any{})
	expect(t, e.branch("schemas", map[string]any{"name": "schemas-r7", "patches": addDrafts("matches-r7")}, "admin"), 201)
	genesis := addRoot(teamSchema())
	r := e.write("PATCH", "schemas-r7", "team", "", genesis)
	expect(t, r, 201)
	t1 := etagOf(r)
	draft := "/r/schemas/team/rev/" + t1
	expect(t, e.branch("matches", map[string]any{"name": "matches-r7"}, "admin"), 201)
	expect(t, e.typed("matches-r7", "m1", draft), 201)

	// The draft's only copy.
	r = e.purge("schemas-r7", "team", t1, "admin")
	expectCode(t, r, 409, "in_use")
	if got := referencing(r); len(got) != 1 || got[0] != "matches-r7" {
		t.Fatalf("referencing %v", got)
	}
	// Narrowing drafts.for, or dropping it, would leave m1 without a copy.
	expectCode(t, e.patchNS("schemas-r7", ops(op("remove", "/drafts")), ""), 409, "in_use")
	expectCode(t, e.patchNS("schemas-r7", ops(op("replace", "/drafts/for", strs([]string{"other"}))), ""), 409, "in_use")
	expect(t, e.patchNS("schemas-r7", ops(op("replace", "/drafts/for", strs([]string{"matches-*"}))), ""), 201)
	// A namespace purge of the draft branch too.
	expect(t, e.patchNS("schemas-r7", ops(op("add", "/frozen", true)), ""), 201)
	r = e.do(req{method: "POST", path: "/ns/schemas-r7/purge", ifMatch: e.nsHead("schemas-r7"), author: "admin"})
	expectCode(t, r, 409, "in_use")
	expect(t, e.patchNS("schemas-r7", ops(op("remove", "/frozen")), ""), 201)

	// Documents can't be merged into the base before their schema.
	mergeM1 := map[string]any{"items": []any{map[string]any{"resource": "m1", "ifNoneMatch": "*",
		"steps": []any{addRoot(map[string]any{"$schema": draft, "team": "x"})}}}}
	expectCode(t, e.batchReq("matches", mergeM1, "admin"), 422, "batch")
	// Fast-forward the schema: the same patches give the same id.
	r = e.batchReq("schemas", map[string]any{"items": []any{map[string]any{"resource": "team", "ifNoneMatch": "*", "steps": []any{genesis}}}}, "admin")
	expect(t, r, 201)
	if e.head("schemas", "team") != t1 {
		t.Fatal("the fast-forward changed the id")
	}
	expect(t, e.batchReq("matches", mergeM1, "admin"), 201)
	// Now the branch's copy isn't the last one.
	expect(t, e.purge("schemas-r7", "team", t1, "admin"), 204)
	// The base's copy is: referenced from matches and matches-r7.
	r = e.purge("schemas", "team", t1, "admin")
	expectCode(t, r, 409, "in_use")
	if got := referencing(r); len(got) != 2 {
		t.Fatalf("referencing %v", got)
	}
	// An operator forces it (dev mode: a * key).
	expect(t, e.do(req{method: "POST", path: "/r/schemas/team/purge?force=1", ifMatch: t1, author: "admin"}), 204)
}

// §6.1: every revision a branch wrote counts as referencing, not only its
// head; a tombstoned document still counts.
func TestDraftSchemasEveryRevisionCounts(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.mkNS("schemas", map[string]any{})
	e.mkNS("matches", map[string]any{})
	expect(t, e.branch("schemas", map[string]any{"name": "schemas-r7", "patches": addDrafts("matches-*")}, "admin"), 201)
	t1 := e.create("schemas-r7", "team", teamSchema())
	t2 := e.create("schemas-r7", "team2", teamSchema("b"))
	expect(t, e.branch("matches", map[string]any{"name": "matches-r7"}, "admin"), 201)
	m1 := e.create("matches-r7", "m1", map[string]any{"$schema": "/r/schemas/team/rev/" + t1, "team": "x"})
	// The head moves to team2, then is untyped: t1 is still referenced.
	m2 := e.appendRev("matches-r7", "m1", m1, ops(op("replace", "/$schema", "/r/schemas/team2/rev/"+t2)))
	m3 := e.appendRev("matches-r7", "m1", m2, ops(op("remove", "/$schema")))
	expectCode(t, e.purge("schemas-r7", "team", t1, "admin"), 409, "in_use")
	tomb := e.del("matches-r7", "m1", m3)
	expectCode(t, e.purge("schemas-r7", "team2", t2, "admin"), 409, "in_use")
	// Purging the referencing resource first frees both.
	expect(t, e.purge("matches-r7", "m1", tomb, "admin"), 204)
	expect(t, e.purge("schemas-r7", "team", t1, "admin"), 204)
	expect(t, e.purge("schemas-r7", "team2", t2, "admin"), 204)
}

// D.8: two purges, each of one of the last two copies of a referenced
// draft, can't both succeed.
func TestDraftSchemasConcurrentPurges(t *testing.T) {
	t.Parallel()
	e := newEnv(t, withFileDB(t))
	e.mkNS("schemas", map[string]any{})
	e.mkNS("matches", map[string]any{})
	expect(t, e.branch("matches", map[string]any{"name": "matches-r7"}, "admin"), 201)
	for round := 0; round < 4; round++ {
		genesis := addRoot(teamSchema(fmt.Sprintf("round%d", round)))
		bs := []string{fmt.Sprintf("schemas-a%d", round), fmt.Sprintf("schemas-b%d", round)}
		for _, b := range bs {
			expect(t, e.branch("schemas", map[string]any{"name": b, "patches": addDrafts("matches-r7")}, "admin"), 201)
			expect(t, e.write("PATCH", b, "team", "", genesis), 201)
		}
		t1 := e.head(bs[0], "team")
		expect(t, e.typed("matches-r7", fmt.Sprintf("m%d", round), "/r/schemas/team/rev/"+t1), 201)
		var wg sync.WaitGroup
		codes := make([]int, 2)
		for i, b := range bs {
			wg.Add(1)
			go func(i int, b string) {
				defer wg.Done()
				codes[i] = e.purge(b, "team", t1, "admin").Code
			}(i, b)
		}
		wg.Wait()
		ok := 0
		for _, c := range codes {
			switch c {
			case 204:
				ok++
			case 409:
			default:
				t.Fatalf("purge answered %d", c)
			}
		}
		if ok != 1 {
			t.Fatalf("round %d: %d purges succeeded (%v)", round, ok, codes)
		}
	}
}

// §G.3: a remote branch whose documents reference a draft fails with 422:
// its schemas are mirrored only from their own namespaces.
func TestDraftSchemasRemoteBranch(t *testing.T) {
	t.Parallel()
	a, b, _ := pair(t, nil, nil)
	a.mkNS("schemas", map[string]any{"read": "public"})
	a.mkNS("main", map[string]any{"read": "public"})
	expect(t, a.branch("schemas", map[string]any{"name": "schemas-r7", "patches": addDrafts("main-r7")}, "admin"), 201)
	t1 := a.create("schemas-r7", "team", teamSchema())
	expect(t, a.branch("main", map[string]any{"name": "main-r7"}, "admin"), 201)
	expect(t, a.typed("main-r7", "m1", "/r/schemas/team/rev/"+t1), 201)
	r := b.mkRemote("rel", remoteGenesis("main-r7", a.nsHead("main-r7"), nil))
	expectCode(t, r, 422, "schema_unavailable")
	expect(t, b.get("/ns/rel"), 404)
	// Once the schema is in its namespace, the branch can be mirrored.
	expect(t, a.batchReq("schemas", map[string]any{"items": []any{map[string]any{"resource": "team", "ifNoneMatch": "*", "steps": []any{addRoot(teamSchema())}}}}, "admin"), 201)
	expect(t, b.mkRemote("rel", remoteGenesis("main-r7", a.nsHead("main-r7"), nil)), 201)
}

// doMulti sends a JSON PATCH with a header repeated once per value.
func (e *tenv) doMulti(path, bearer string, body any, header string, values []string) *resp {
	e.t.Helper()
	b, err := json.Marshal(body)
	if err != nil {
		e.t.Fatal(err)
	}
	hr, err := http.NewRequest("PATCH", e.srv.URL+path, bytes.NewReader(b))
	if err != nil {
		e.t.Fatal(err)
	}
	hr.Header.Set("Content-Type", "application/json-patch+json")
	hr.Header.Set("If-None-Match", "*")
	hr.Header.Set("Authorization", "Bearer "+bearer)
	for _, v := range values {
		hr.Header.Add(header, v)
	}
	r, err := client.Do(hr)
	if err != nil {
		e.t.Fatal(err)
	}
	defer r.Body.Close()
	rb, _ := io.ReadAll(r.Body)
	return &resp{Code: r.StatusCode, H: r.Header, Body: rb}
}

// §6.1: the writer needs read on the draft in the candidate, with the
// request's grant (naming the candidate, verifying under its keys) or with
// any grant of a repeated Source-Authorization.
func TestDraftSchemasReadGrant(t *testing.T) {
	t.Parallel()
	e := newAuthEnv(t)
	kS, kM, kBoth := newKey("ks"), newKey("km"), newKey("kboth")
	e.mkNS("schemas", map[string]any{"read": "grant", "keys": []any{kS.entry("*"), kBoth.entry("read", "create", "purge")}})
	e.mkNS("matches", map[string]any{"read": "grant", "keys": []any{kM.entry("*"), kBoth.entry("read", "create", "purge")}})
	sAdmin := e.grant(kS, "user:s", []string{"schemas", "schemas-r7"}, allVerbs)
	mAdmin := e.grant(kM, "user:m", []string{"matches", "matches-r7"}, allVerbs)
	expect(t, e.branch("schemas", map[string]any{"name": "schemas-r7", "patches": addDrafts("matches-r7")}, sAdmin), 201)
	expect(t, e.branch("matches", map[string]any{"name": "matches-r7"}, mAdmin), 201)
	t1 := e.create("schemas-r7", "team", teamSchema(), sAdmin)
	draft := "/r/schemas/team/rev/" + t1

	writeWith := func(name, bearer string, src ...string) *resp {
		t.Helper()
		return e.doMulti("/r/matches-r7/"+name, bearer, addRoot(map[string]any{"$schema": draft, "team": "x"}), "Source-Authorization", src)
	}
	// The writer's grant can't read schemas-r7: as if the draft didn't exist.
	expectCode(t, writeWith("a", mAdmin), 422, "schema_unavailable")
	// A grant in Source-Authorization that reads it serves; the header may
	// be repeated (or joined), and a grant for another namespace is passed
	// over.
	reader := e.grant(kS, "user:m", []string{"schemas-r7"}, []string{"read"})
	other := e.grant(kM, "user:m", []string{"matches"}, []string{"read"})
	expect(t, writeWith("b", mAdmin, "Bearer "+reader), 201)
	expect(t, writeWith("c", mAdmin, "Bearer "+other, "Bearer "+reader), 201)
	expect(t, writeWith("d", mAdmin, "Bearer "+other+", Bearer "+reader), 201)
	// A reader restricted to another resource doesn't serve.
	onlyX := e.grant(kS, "user:m", []string{"schemas-r7"}, []string{"read"}, map[string]any{"rules": []any{map[string]any{"op": "test", "path": "/resource", "value": "x"}}})
	expectCode(t, writeWith("e", mAdmin, "Bearer "+onlyX), 422, "schema_unavailable")
	// The request's own grant serves when it names the candidate and
	// verifies under its keys.
	both := e.grant(kBoth, "user:b", []string{"matches-r7", "schemas-r7"}, []string{"read", "create"})
	expect(t, writeWith("f", both), 201)
	notNamed := e.grant(kBoth, "user:b", []string{"matches-r7"}, []string{"read", "create"})
	expectCode(t, writeWith("g", notNamed), 422, "schema_unavailable")
	// The in_use answer lists only the referencing namespaces the caller
	// can read.
	r := e.purge("schemas-r7", "team", t1, sAdmin)
	expectCode(t, r, 409, "in_use")
	if got := referencing(r); len(got) != 0 {
		t.Fatalf("referencing %v listed to a caller who can't read it", got)
	}
	sm := e.grant(kBoth, "user:b", []string{"schemas-r7", "matches-r7"}, []string{"read", "purge"})
	r = e.purge("schemas-r7", "team", t1, sm)
	expectCode(t, r, 409, "in_use")
	if got := referencing(r); len(got) != 1 || got[0] != "matches-r7" {
		t.Fatalf("referencing %v", got)
	}
	// Forcing needs a * key.
	expectCode(t, e.do(req{method: "POST", path: "/r/schemas-r7/team/purge?force=1", ifMatch: t1, bearer: sm}), 403, "forbidden")
	// A * key of the branch (here inherited from its base) forces it.
	expect(t, e.do(req{method: "POST", path: "/r/schemas-r7/team/purge?force=1", ifMatch: t1, bearer: sAdmin}), 204)
}
