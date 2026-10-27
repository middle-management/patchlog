package core

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/pgtest"
	"github.com/middle-management/patchlog/internal/schema"
)

// Spec v0.73, package P27: schema rules markers (§6.1 "A schema stored
// under an earlier version is compiled as that version did", F-S1).

// idnSchema is a schema written now whose documents' e must be an
// idn-email: asserted under V073, unknown (ignored) under Legacy.
func idnSchema() map[string]any {
	return map[string]any{"$schema": schema.Dialect2020, "type": "object",
		"properties": map[string]any{"e": map[string]any{"type": "string", "format": "idn-email"}}}
}

// legacySchema is a schema only the rules before v0.73 accept: a format
// draft 2020-12 doesn't define, which write mode refuses (§6.2 step 5).
func legacySchema() map[string]any {
	return map[string]any{"$schema": schema.Dialect2020, "type": "object",
		"properties": map[string]any{"c": map[string]any{"type": "string", "format": "color"}}}
}

func genesisCanon(doc any) []byte {
	return jsonv.Canonical([]any{map[string]any{"op": "add", "path": "", "value": doc}})
}

// rowRulesOf is the stored revisions.rules of revision id in ns/name.
func (s *schemaEnv) rowRulesOf(ns, name, id string) sql.NullInt64 {
	s.t.Helper()
	rid, err := ids.Parse(id)
	if err != nil {
		s.t.Fatal(err)
	}
	var r sql.NullInt64
	err = s.e.read(context.Background(), func(t *tx) error {
		res := t.resource(t.nsByName(ns).id, name)
		t.must(t.QueryRow(`SELECT rules FROM revisions WHERE res = ? AND id = ?`, res.id, rid[:]).Scan(&r))
		return nil
	})
	if err != nil {
		s.t.Fatal(err)
	}
	return r
}

// storedBefore makes revision id of ns/name a row stored before markers
// existed (rules NULL), as an upgraded database holds.
func (s *schemaEnv) storedBefore(ns, name, id string) {
	s.t.Helper()
	rid, _ := ids.Parse(id)
	err := s.e.update(context.Background(), func(t *tx) error {
		res := t.resource(t.nsByName(ns).id, name)
		_, err := t.Exec(`UPDATE revisions SET rules = NULL WHERE res = ? AND id = ?`, res.id, rid[:])
		return err
	})
	if err != nil {
		s.t.Fatal(err)
	}
	s.e.FlushCaches()
}

// legacyRow makes ns/name a resource whose head is a schema revision
// stored before the upgrade with doc, which today's write rules refuse: a
// placeholder is written, then its row is given doc's genesis patch set
// and id, with no marker. It returns the id.
func (s *schemaEnv) legacyRow(ns, name string, doc any) string {
	s.t.Helper()
	placeholder := s.put(ns, name, "", map[string]any{"$schema": schema.Dialect2020, "title": "placeholder " + name})
	pid, _ := ids.Parse(placeholder)
	canon := genesisCanon(doc)
	id := ids.Revision(nil, canon)
	err := s.e.update(context.Background(), func(t *tx) error {
		res := t.resource(t.nsByName(ns).id, name)
		if _, err := t.Exec(`UPDATE revisions SET id = ?, patches = ?, rules = NULL, size = NULL, digest = NULL WHERE res = ? AND id = ?`,
			id[:], t.putPatches(res.id, id, canon, nil), res.id, pid[:]); err != nil {
			return err
		}
		_, err := t.Exec(`DELETE FROM heads WHERE res = ?`, res.id)
		return err
	})
	if err != nil {
		s.t.Fatal(err)
	}
	s.e.FlushCaches()
	return id.String()
}

func expectAPI(t *testing.T, err error, status int, code string) {
	t.Helper()
	var ae *Error
	if !errors.As(err, &ae) || ae.Status != status || ae.Body["code"] != code {
		t.Fatalf("want %d %s, got %v", status, code, err)
	}
}

// CIS-17: revisions written now carry the V073 marker, stored beside the
// row and outside its id; a document typed by a schema revision is
// validated under that revision's marker: V073 asserts idn-email, and a
// revision stored before the upgrade (no marker) compiles as v0.55 did,
// leaving it unasserted (§6.1).
func TestV073RulesMarkerTypedDocs(t *testing.T) {
	t.Parallel()
	s := newSchemaEnv(t)
	s.mkNS("n")
	sid := s.put("n", "s", "", idnSchema())
	if want := ids.Revision(nil, genesisCanon(idnSchema())).String(); sid != want {
		t.Fatalf("revision id %s, want %s: the marker is outside the id", sid, want)
	}
	if r := s.rowRulesOf("n", "s", sid); !r.Valid || r.Int64 != int64(schema.V073) {
		t.Fatalf("stored marker %v, want %d", r, schema.V073)
	}
	did := s.put("n", "plain", "", map[string]any{"v": 1.0})
	if r := s.rowRulesOf("n", "plain", did); !r.Valid || r.Int64 != int64(schema.V073) {
		t.Fatalf("a document's marker %v, want %d", r, schema.V073)
	}
	path := "/r/n/s/rev/" + sid
	_, err := s.e.WriteResource(context.Background(), s.req("n"), createItem("d1", map[string]any{"$schema": path, "e": "not an email"}))
	expectAPI(t, err, 422, "invalid")
	s.put("n", "d2", "", map[string]any{"$schema": path, "e": "user@example.com"})

	// Stored before the upgrade: as v0.55 compiled it.
	s.storedBefore("n", "s", sid)
	s.put("n", "d3", "", map[string]any{"$schema": path, "e": "not an email"})

	// Within one batch, a document typed by a schema an earlier item
	// writes follows that revision's marker too.
	pid := ids.Revision(nil, genesisCanon(map[string]any{"$schema": schema.Dialect2020, "title": "batch",
		"properties": map[string]any{"e": map[string]any{"format": "idn-email"}}})).String()
	_, err = s.batch("n", []Item{
		createItem("bs", map[string]any{"$schema": schema.Dialect2020, "title": "batch", "properties": map[string]any{"e": map[string]any{"format": "idn-email"}}}),
		createItem("bd", map[string]any{"$schema": "/r/n/bs/rev/" + pid, "e": "not an email"}),
	}, false)
	if got := itemFails(t, err); got[1] != "invalid" || len(got) != 1 {
		t.Fatalf("batch failures %v, want item 1 invalid", got)
	}
}

// CIS-17 and the carry-over of P03: a content-addressed copy of a schema
// revision stored under the earlier rules (a fast-forward merge, a
// same-deployment import, a branch's replay) inherits its Legacy marker, so
// it is checked as it was stored and compiles as it did; new content, and
// a copy from a namespace the write can't take content from, is held to
// today's rules (§6.1, §G.4.4, F-S1).
func TestV073CopyInheritsLegacyMarker(t *testing.T) {
	t.Parallel()
	s := newSchemaEnv(t)
	for _, ns := range []string{"old", "other", "third"} {
		s.mkNS(ns)
	}
	x := s.legacyRow("old", "s", legacySchema())
	// Today's rules refuse that content as new.
	_, err := s.e.WriteResource(context.Background(), s.req("third"), createItem("fresh", map[string]any{
		"$schema": schema.Dialect2020, "title": "new content", "properties": map[string]any{"c": map[string]any{"format": "color"}}}))
	expectAPI(t, err, 422, "invalid")
	// A copy into a namespace that neither reads old through nor names it
	// as the batch's source is new content too.
	_, err = s.e.WriteResource(context.Background(), s.req("third"), createItem("s", legacySchema()))
	expectAPI(t, err, 422, "invalid")

	// A branch of old replays it: the same id, read through from its base.
	if _, err := s.e.CreateBranch(context.Background(), s.req("old"), BranchRequest{Name: "old-b", IfNoneMatch: true}); err != nil {
		t.Fatal(err)
	}
	if got := s.put("old-b", "t", "", legacySchema()); got != x {
		t.Fatalf("copy id %s, want %s", got, x)
	}
	if r := s.rowRulesOf("old-b", "t", x); !r.Valid || r.Int64 != int64(schema.Legacy) {
		t.Fatalf("copy's marker %v, want %d (Legacy)", r, schema.Legacy)
	}

	// A batch whose local source is old, as a merge or a same-deployment
	// import sends it: the copy inherits the marker.
	at := s.nsHeadID("old")
	res, err := s.e.Batch(context.Background(), s.req("other"), []Item{createItem("s", legacySchema())}, nil,
		map[string]any{"ns": "old", "at": at}, false)
	if err != nil {
		t.Fatalf("batch with old as source: %v", err)
	}
	if res.Items[0].IDs[0] != x {
		t.Fatal("not the same id")
	}
	// Documents typed by the copy compile under Legacy: an unknown format
	// is ignored, the rest validates.
	path := "/r/other/s/rev/" + x
	s.put("other", "d", "", map[string]any{"$schema": path, "c": "not a colour"})
	_, err = s.e.WriteResource(context.Background(), s.req("other"), createItem("e", map[string]any{"$schema": path, "c": 5.0}))
	expectAPI(t, err, 422, "invalid")
}

// nsHeadID is the id of ns's last namespace log entry.
func (s *schemaEnv) nsHeadID(ns string) string {
	s.t.Helper()
	var id string
	err := s.e.read(context.Background(), func(t *tx) error {
		n := t.nsByName(ns)
		id = t.nsLogID(n.headSeq.Int64).String()
		return nil
	})
	if err != nil {
		s.t.Fatal(err)
	}
	return id
}

// CIS-17: a database from before markers gets the column, and its rows,
// NULL, read as Legacy; rows written afterwards are V073 (§6.1).
func TestV073RulesMarkerMigration(t *testing.T) {
	t.Parallel()
	path := pgtest.FreshDB(t)
	if path == ":memory:" {
		path = filepath.Join(t.TempDir(), "markers.db")
	}
	open := func() *Engine {
		lim := DefaultLimits()
		fast := Rate{1e9, 1e9}
		lim.RatePerResource, lim.RatePerPrincipal, lim.RatePerNamespace = fast, fast, fast
		e, err := Open(Options{Path: path, BlobDir: t.TempDir(), AuthDisabled: true, Limits: lim, Purger: discardPurger{},
			RetentionInterval: -1, BlobSweepInterval: -1, RepurgeInterval: -1, Remote: RemoteOptions{FollowInterval: -1}})
		if err != nil {
			t.Fatal(err)
		}
		return e
	}
	e := open()
	s := &schemaEnv{t: t, e: e}
	s.now.Store(time.Now().UnixMilli())
	s.mkNS("n")
	sid := s.put("n", "s", "", idnSchema())
	// The database as an earlier version left it: no column, and no
	// record of migration 003_revisions_rules, which adds it.
	applied := "mmmigrate_applied"
	if e.pg {
		applied = "mmmigrate.applied"
	}
	for _, q := range []string{`ALTER TABLE revisions DROP COLUMN rules`,
		`DELETE FROM ` + applied + ` WHERE (namespace = 'patchlog' OR namespace LIKE 'patchlog@%') AND name = 'revisions_rules'`} {
		if _, err := e.db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	e.Close()
	e = open()
	t.Cleanup(func() { e.Close() })
	s.e = e
	if r := s.rowRulesOf("n", "s", sid); r.Valid {
		t.Fatalf("migrated row's marker %v, want NULL", r)
	}
	p := "/r/n/s/rev/" + sid
	s.put("n", "d", "", map[string]any{"$schema": p, "e": "not an email"})
	newer := idnSchema()
	newer["title"] = "written after the upgrade"
	s2 := s.put("n", "s2", "", newer)
	if r := s.rowRulesOf("n", "s2", s2); !r.Valid || r.Int64 != int64(schema.V073) {
		t.Fatalf("new row's marker %v, want %d", r, schema.V073)
	}
	_, err := e.WriteResource(context.Background(), s.req("n"), createItem("d2", map[string]any{"$schema": "/r/n/s2/rev/" + s2, "e": "not an email"}))
	expectAPI(t, err, 422, "invalid")
}

// CIS-17 (P27 review), §6.1 "A schema stored under an earlier version is
// compiled as that version did", wherever it is reached from: a revision
// stored before the upgrade (Legacy), reached through the $ref of a schema
// written now (V073), compiles as it does when a document names it, not
// under the V073 marker of the root: semver asserted (v0.55 asserted it),
// idn-email not (v0.55 ignored it). The V073 schema's own idn-email is
// asserted.
func TestV073LegacyRevisionInV073Closure(t *testing.T) {
	t.Parallel()
	s := newSchemaEnv(t)
	s.mkNS("n")
	ctx := context.Background()
	l := s.legacyRow("n", "l", map[string]any{"$schema": schema.Dialect2020, "type": "object",
		"properties": map[string]any{"v": map[string]any{"type": "string", "format": "semver"}, "e": map[string]any{"type": "string", "format": "idn-email"}}})
	lpath := "/r/n/l/rev/" + l
	// Named directly: as v0.55 compiled it.
	_, err := s.e.WriteResource(ctx, s.req("n"), createItem("d1", map[string]any{"$schema": lpath, "v": "not a version"}))
	expectAPI(t, err, 422, "invalid")
	s.put("n", "d2", "", map[string]any{"$schema": lpath, "e": "not an email"})

	// Through the $ref of a schema written now: the same.
	sid := s.put("n", "s", "", map[string]any{"$schema": schema.Dialect2020, "type": "object",
		"properties": map[string]any{"old": map[string]any{"$ref": lpath}, "e": map[string]any{"type": "string", "format": "idn-email"}}})
	spath := "/r/n/s/rev/" + sid
	_, err = s.e.WriteResource(ctx, s.req("n"), createItem("d3", map[string]any{"$schema": spath, "old": map[string]any{"v": "not a version"}}))
	expectAPI(t, err, 422, "invalid")
	s.put("n", "d4", "", map[string]any{"$schema": spath, "old": map[string]any{"e": "not an email"}})
	// The V073 schema's own formats are V073's.
	_, err = s.e.WriteResource(ctx, s.req("n"), createItem("d5", map[string]any{"$schema": spath, "e": "not an email"}))
	expectAPI(t, err, 422, "invalid")
	// And so for a schema whose root is only a $ref, written in one batch
	// with documents typed by it and by the stored revision (one
	// transaction, the root an earlier item's, both markers).
	pendingRoot := func(title string) (map[string]any, string) {
		doc := map[string]any{"$schema": schema.Dialect2020, "title": title, "$ref": lpath}
		return doc, "/r/n/" + title + "/rev/" + ids.Revision(nil, genesisCanon(doc)).String()
	}
	rdoc, rpath := pendingRoot("r")
	s.mustBatch("n", []Item{createItem("r", rdoc),
		createItem("d6", map[string]any{"$schema": rpath, "e": "not an email"}),
		createItem("d8", map[string]any{"$schema": lpath, "e": "not an email"})})
	r2doc, r2path := pendingRoot("r2")
	_, err = s.batch("n", []Item{createItem("r2", r2doc),
		createItem("d7", map[string]any{"$schema": r2path, "v": "not a version"})}, false)
	if got := itemFails(t, err); len(got) != 1 || got[1] != "invalid" {
		t.Errorf("d7 typed by a pending V073 root that $refs the stored revision: %v, want item 1 invalid", got)
	}
	// Written since, it compiles the same way.
	s.put("n", "d9", "", map[string]any{"$schema": rpath, "e": "not an email"})
	_, err = s.e.WriteResource(ctx, s.req("n"), createItem("d10", map[string]any{"$schema": rpath, "v": "not a version"}))
	expectAPI(t, err, 422, "invalid")
}

// CIS-17 regression (P27 review): a schema written now may $ref a revision
// stored before the upgrade whose pattern RE2 took as written though
// §6.6's translation refuses it (P03, TestV073WriteRefsStoredPattern).
// The write of that schema is accepted, and so are the documents typed by
// it: the stored revision's pattern compiles as it did. Compiled under the
// root's V073 marker, every one was refused ("lone surrogate").
func TestV073StoredPatternInV073Closure(t *testing.T) {
	t.Parallel()
	s := newSchemaEnv(t)
	s.mkNS("n")
	ctx := context.Background()
	l := s.legacyRow("n", "oldpat", map[string]any{"$schema": schema.Dialect2020, "type": "object",
		"properties": map[string]any{"a": map[string]any{"type": "string", "pattern": "^a\\x{D800}?$"}}})
	lpath := "/r/n/oldpat/rev/" + l
	s.put("n", "d1", "", map[string]any{"$schema": lpath, "a": "a"})
	sid := s.put("n", "s", "", map[string]any{"$schema": schema.Dialect2020, "$ref": lpath})
	spath := "/r/n/s/rev/" + sid
	s.put("n", "d2", "", map[string]any{"$schema": spath, "a": "a"})
	_, err := s.e.WriteResource(ctx, s.req("n"), createItem("d3", map[string]any{"$schema": spath, "a": "b"}))
	expectAPI(t, err, 422, "invalid")
}
