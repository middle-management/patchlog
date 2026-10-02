package core

import (
	"context"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/pgtest"
)

// §7.4: the members the spec defines are validated strictly, in their
// shapes, and any other member must start with "x-".
func TestCheckMembers(t *testing.T) {
	id := ids.Revision(nil, []byte("x")).String()
	ok := []string{
		`{}`,
		`{"read":"public","x-title":"Docs","x-":1,"x-nested":{"anything":[1,"two"]}}`,
		`{"catalog":{"trust":["matches","docs"],"mode":"tree"}}`,
		`{"catalog":{"mode":"dag"}}`,
		`{"catalog":{}}`,
		`{"catalogs":{"cat-season":{"place":["group:match-desk","user:anna"]},"topics":{}}}`,
		`{"merged":{"at":"` + id + `"}}`,
		`{"cleanup":{"merged":"P7D","superseded":"P30D","abandoned":"PT12H"}}`,
		`{"cleanup":{}}`,
		`{"abandoned":true}`,
		`{"abandoned":false}`,
		`{"revoked":["` + id + `"]}`,
		`{"merge":{"authors":[]},"frozen":true,"successor":"next","maxLag":"PT60S"}`,
	}
	bad := map[string]string{
		`{"title":"Docs"}`:                                    `/title is not a namespace-document member`,
		`{"X-title":"Docs"}`:                                  `/X-title is not`,
		`{"xtitle":1}`:                                        `e.g. /x-xtitle`,
		`{"a/b":1}`:                                           `/a~1b is not`,
		`{"catalog":[]}`:                                      `/catalog must be`,
		`{"catalog":{"trust":"matches"}}`:                     `/catalog/trust must be an array`,
		`{"catalog":{"trust":["Matches"]}}`:                   `/catalog/trust/0 must be a namespace name`,
		`{"catalog":{"mode":"forest"}}`:                       `/catalog/mode must be "tree" or "dag"`,
		`{"catalog":{"trusts":[]}}`:                           `/catalog/trusts is not a known field`,
		`{"catalogs":[]}`:                                     `/catalogs must be`,
		`{"catalogs":{"Cat":{"place":[]}}}`:                   `catalog namespace names`,
		`{"catalogs":{"cat":[]}}`:                             `/catalogs/cat must be`,
		`{"catalogs":{"cat":{"place":"group:x"}}}`:            `/catalogs/cat/place must be an array`,
		`{"catalogs":{"cat":{"place":["match-desk"]}}}`:       `/catalogs/cat/place/0 must be a subject`,
		`{"catalogs":{"cat":{"place":["group:"]}}}`:           `/catalogs/cat/place/0 must be a subject`,
		`{"catalogs":{"cat":{"move":[]}}}`:                    `/catalogs/cat/move is not a known field`,
		`{"merged":true}`:                                     `/merged must be`,
		`{"merged":{"at":"nope"}}`:                            `/merged must be`,
		`{"merged":{"at":"` + id + `","by":"x"}}`:             `/merged must be`,
		`{"cleanup":"P7D"}`:                                   `/cleanup must be`,
		`{"cleanup":{"merged":"7 days"}}`:                     `/cleanup/merged must be an ISO 8601 duration`,
		`{"cleanup":{"merged":7}}`:                            `/cleanup/merged must be an ISO 8601 duration`,
		`{"cleanup":{"purged":"P7D"}}`:                        `/cleanup/purged is not a known field`,
		`{"abandoned":"yes"}`:                                 `/abandoned must be a boolean`,
		`{"revoked":["1aaaa"]}`:                               `/revoked/0 must be a revocation id`,
		`{"revoked":["` + id + `","not an id"]}`:              `/revoked/1 must be a revocation id`,
		`{"x-title":1,"titel":2,"catalog":{"mode":"forest"}}`: `/catalog/mode`, // in member order
		`{"keys":[{"kid":"a","x-note":"ops"}]}`:               `/keys/0/x-note is not a key field`,
	}
	for _, s := range ok {
		if err := checkMembers(jsonv.MustParse([]byte(s)).(map[string]any), nil); err != nil {
			t.Errorf("%s: %v", s, err)
		}
	}
	for s, want := range bad {
		err := checkMembers(jsonv.MustParse([]byte(s)).(map[string]any), nil)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v, want %q", s, err, want)
		}
	}
	// The 422 names the member and says what other members must look like.
	err := checkMembers(map[string]any{"title": "x"}, nil)
	ae := configErr(err)
	if ae.Status != 422 || ae.Body["code"] != "invalid" || ae.Body["path"] != "/title" || !strings.Contains(ae.Body["message"].(string), `must start with "x-"`) {
		t.Fatalf("unknown member error %v", ae)
	}
}

// A member the document a write starts from already holds, unchanged, was
// stored under an earlier version and is kept as data; one the write adds
// or changes is checked (§7.4).
func TestCheckMembersKeepsStoredMembers(t *testing.T) {
	prev := map[string]any{"read": "public", "title": "Old", "cleanup": map[string]any{"merged": "7 days"}}
	same := map[string]any{"read": "grant", "title": "Old", "cleanup": map[string]any{"merged": "7 days"}, "frozen": true}
	if err := checkMembers(same, prev); err != nil {
		t.Fatalf("stored members refused: %v", err)
	}
	for name, doc := range map[string]map[string]any{
		"changed member":  {"title": "New"},
		"added member":    {"title": "Old", "subtitle": "x"},
		"changed cleanup": {"cleanup": map[string]any{"merged": "8 days"}},
	} {
		if err := checkMembers(doc, prev); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if err := checkMembers(map[string]any{"read": "public"}, prev); err != nil {
		t.Fatalf("removing stored members refused: %v", err)
	}
}

// Within revoked and keys, entries the document a write starts from holds
// are kept; only new or changed entries are checked (§7.4), so a
// revocation can be added next to a malformed one an older version stored.
func TestCheckMembersKeepsStoredEntries(t *testing.T) {
	id := ids.Revision(nil, []byte("x")).String()
	key := map[string]any{"kid": "ops", "alg": "Ed25519", "pub": "p", "x-note": "old"}
	prev := map[string]any{"revoked": []any{"1aaaa"}, "keys": []any{key}}
	other := map[string]any{"kid": "ops-2", "alg": "Ed25519", "pub": "q"}
	if err := checkMembers(map[string]any{"revoked": []any{"1aaaa", id}, "keys": []any{key, other}}, prev); err != nil {
		t.Fatalf("adding next to stored entries refused: %v", err)
	}
	err := checkMembers(map[string]any{"revoked": []any{"1aaaa", "2bbbb"}}, prev)
	if err == nil || !strings.Contains(err.Error(), "/revoked/1 must be a revocation id") {
		t.Fatalf("new malformed revocation: %v", err)
	}
	changed := map[string]any{"kid": "ops", "alg": "Ed25519", "pub": "p", "x-note": "new"}
	err = checkMembers(map[string]any{"keys": []any{other, changed}}, prev)
	if err == nil || !strings.Contains(err.Error(), "/keys/1/x-note is not a key field") {
		t.Fatalf("changed key entry with an x- field: %v", err)
	}
}

// A branch is a new namespace: of its base's document as stored it keeps
// only the members this version defines, so a member an older version
// stored is refused with a message saying how to rename it (§7.4).
func TestDefinedMembers(t *testing.T) {
	base := map[string]any{"read": "public", "title": "Old", "cleanup": map[string]any{"merged": "7 days"}, "x-a": 1.0}
	got := definedMembers(base)
	if len(got) != 2 || got["read"] != "public" || got["cleanup"] == nil {
		t.Fatalf("defined members %v", got)
	}
	e := &Engine{opt: Options{Limits: DefaultLimits(), Maximums: DefaultLimits()}}
	_, ae := e.newConfig(base, got, base)
	if ae == nil || ae.Status != 422 || ae.Body["path"] != "/title" ||
		!strings.Contains(ae.Body["message"].(string), `{"op":"move","from":"/title","path":"/x-title"}`) {
		t.Fatalf("inherited member: %v", ae)
	}
}

// A shadow keeps the encryption members this version defines, and only
// valid ones (§G.3): a base of a newer version may carry others.
func TestShadowEncryption(t *testing.T) {
	e := &Engine{opt: Options{Limits: DefaultLimits(), Maximums: DefaultLimits()}}
	got, err := e.shadowEncryption("matches", map[string]any{"level": "e2e", "epoch": 3.0, "historyEpochs": 2.0, "pad": true, "suite": "future"})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"level": "e2e", "epoch": 3.0, "historyEpochs": 2.0, "pad": true}
	if !jsonv.Equal(jsonv.FromGo(got), jsonv.FromGo(want)) {
		t.Fatalf("shadow encryption %v", got)
	}
	if _, err := e.shadowEncryption("matches", map[string]any{"level": "e2e", "epoch": "three"}); err == nil || err.Status != 502 {
		t.Fatalf("malformed epoch: %v", err)
	}
	// Checked under this deployment's limits, which reading the shadow's
	// document uses: here they leave no room for an e2e namespace (§6.6).
	small := DefaultLimits()
	small.PatchSetSize = 200 << 10
	e = &Engine{opt: Options{Limits: small, Maximums: small}}
	if _, err := e.shadowEncryption("matches", map[string]any{"level": "e2e"}); err == nil || err.Status != 502 {
		t.Fatalf("e2e under limits without room for it: %v", err)
	}
}

// A namespace whose document was stored before this version, with members
// it doesn't define, can still be configured, frozen and branched; a write
// that changes such a member must give it an "x-" name (§7.4).
func TestStoredMembersAfterUpgrade(t *testing.T) {
	e, err := Open(Options{Path: pgtest.DB(t), BlobDir: t.TempDir(), AuthDisabled: true, RetentionInterval: -1, Remote: RemoteOptions{FollowInterval: -1}})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	ctx := context.Background()
	// As an earlier version stored it: no member check then.
	old := map[string]any{"read": "public", "title": "Old", "cleanup": map[string]any{"merged": "P7D", "note": "x"}, "revoked": []any{"1aaaa"}}
	if err := e.update(ctx, func(t *tx) error {
		t.insertNamespace("old", []any{map[string]any{"op": "add", "path": "", "value": old}}, old, false, t.authorID("op"))
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	req := Request{NS: "old", Cred: Credentials{Author: "admin"}}
	write := func(patches ...any) error {
		h, err := e.NamespaceHead(ctx, "old", req.Cred)
		if err != nil {
			t.Fatal(err)
		}
		_, err = e.WriteConfig(ctx, req, ConfigChange{IfMatch: h.Config, Patches: patches})
		return err
	}
	status := func(err error) (int, any) {
		if err == nil {
			return 201, nil
		}
		ae, ok := err.(*Error)
		if !ok {
			t.Fatal(err)
		}
		return ae.Status, ae.Body["path"]
	}
	add := func(path string, v any) any { return map[string]any{"op": "add", "path": path, "value": v} }

	// Writes that leave the stored members alone.
	if s, _ := status(write(add("/frozen", true))); s != 201 {
		t.Fatalf("freezing: %d", s)
	}
	if s, _ := status(write(add("/frozen", false), add("/x-note", "kept"))); s != 201 {
		t.Fatalf("unfreezing: %d", s)
	}
	// An older version stored "1aaaa" as a revocation; a real one can be
	// added next to it, a malformed one can't.
	rid := ids.Revision(nil, []byte("grant")).String()
	if s, _ := status(write(add("/revoked/-", rid))); s != 201 {
		t.Fatalf("revoking next to a stored malformed revocation: %d", s)
	}
	if s, p := status(write(add("/revoked/-", "2bbbb"))); s != 422 || p != nil {
		t.Fatalf("adding a malformed revocation: %d %v", s, p)
	}
	// A branch is a new namespace, so it can't hold the base's stored
	// "title"; its patches can rename it. The defined members it inherits,
	// such as cleanup, are kept as stored.
	_, err = e.CreateBranch(ctx, Request{NS: "old", Cred: req.Cred}, BranchRequest{Name: "old-b"})
	if s, p := status(err); s != 422 || p != "/title" || !strings.Contains(err.(*Error).Body["message"].(string), `"op":"move"`) {
		t.Fatalf("branch inheriting a stored member: %d %v %v", s, p, err)
	}
	_, err = e.CreateBranch(ctx, Request{NS: "old", Cred: req.Cred}, BranchRequest{Name: "old-c",
		Patches: []any{map[string]any{"op": "replace", "path": "/title", "value": "C"}}})
	if s, p := status(err); s != 422 || p != "/title" {
		t.Fatalf("branch changing a stored member: %d %v", s, p)
	}
	if _, err := e.CreateBranch(ctx, Request{NS: "old", Cred: req.Cred}, BranchRequest{Name: "old-b",
		Patches: []any{map[string]any{"op": "move", "from": "/title", "path": "/x-title"}}}); err != nil {
		t.Fatalf("branch renaming a stored member: %v", err)
	}
	// Changing a stored member checks it.
	if s, p := status(write(map[string]any{"op": "replace", "path": "/title", "value": "New"})); s != 422 || p != "/title" {
		t.Fatalf("changing a stored member: %d %v", s, p)
	}
	if s, _ := status(write(map[string]any{"op": "replace", "path": "/cleanup/merged", "value": "P8D"})); s != 422 {
		t.Fatalf("changing a stored cleanup with an unknown field: %d", s)
	}
	// Moving it to an x- member, and fixing cleanup, are accepted.
	if s, _ := status(write(map[string]any{"op": "move", "from": "/title", "path": "/x-title"}, map[string]any{"op": "remove", "path": "/cleanup/note"})); s != 201 {
		t.Fatalf("moving to x-title: %d", s)
	}
	info, err := e.NamespaceHead(ctx, "old", req.Cred)
	if err != nil {
		t.Fatal(err)
	}
	rev, err := e.NamespaceRev(ctx, "old", info.Head, req.Cred)
	if err != nil {
		t.Fatal(err)
	}
	doc := jsonv.MustParse(rev.Doc).(map[string]any)
	if doc["x-title"] != "Old" || doc["title"] != nil || doc["x-note"] != "kept" {
		t.Fatalf("document %s", rev.Doc)
	}
}
