package core

import (
	"database/sql"
	"errors"

	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/schema"
)

// Schema rules markers (§6.1: "A schema stored under an earlier version is
// compiled as that version did").
//
// Each revision row records, in revisions.rules, the rules its document was
// written under (schema.Rules): V073 for those written now, Legacy for a
// copy of a revision stored under the earlier rules. Rows from before the
// column, and those a remote branch mirrors from another deployment
// (§G.3), whose marker there this deployment can't know, are NULL, read
// as Legacy. The marker never changes, and isn't part of the revision id.
//
// A schema document's marker selects how it is checked when written (V073:
// write mode; Legacy: the stored mode, as v0.55 checked it) and how it
// compiles; a document typed by $schema is validated under the marker of
// the schema revision it names, which governs that revision's whole $ref
// closure (schema.Validator.ValidateRules), and compiled validators are
// cached by path and marker.
//
// A revision whose document is a schema document and whose id other rows
// already have is a content-addressed copy of them (§3.3): a fast-forward
// merge, a same-deployment import or a branch's replay of its base's
// revision. It inherits their marker, Legacy if any is, so one id compiles
// one way (F-S1). Only rows the write may take content from count: in the
// namespace written and its local bases, and in a batch's local source,
// read unrestricted, and its bases (copiesIn), so the marker reveals
// nothing about namespaces the writer can't read. Anything else is new
// content, judged by today's rules (§G.4.4): an import from another
// deployment too, whose source marker isn't carried.

// validateStep is step 5 for one step (§6.1, §6.2): it fixes the rules
// marker of the revision the step writes (docRules), which step 7 stores,
// and validates the resulting document: a schema document under that
// marker, any other under the marker of the schema revision it names.
func (t *tx) validateStep(step *stepState, sc *schemaCtx, pending map[string]any) (string, *Error) {
	rules := t.docRules(step.id, step.doc, sc)
	step.legacy = rules == schema.Legacy
	return t.validateDoc(step.doc, rules, sc, pending)
}

// rulesColumn is the revisions.rules value of the revision a step writes,
// its schema rules marker (validateStep).
func (s *stepState) rulesColumn() int {
	if s.legacy {
		return int(schema.Legacy)
	}
	return int(schema.V073)
}

// docRules is the rules marker of a revision with id and document doc
// written now: V073, unless doc is a schema document and rows the write may
// copy from already have id (copiesIn), whose marker it inherits, Legacy if
// any of them is. Other documents' markers select nothing.
func (t *tx) docRules(id ids.ID, doc any, sc *schemaCtx) schema.Rules {
	if !schema.IsSchemaDoc(doc) {
		return schema.V073
	}
	if r, ok := sc.copied[id]; ok {
		return r
	}
	nss := sc.copiesIn(t)
	var n int
	var least sql.NullInt64
	t.must(t.QueryRow(`SELECT COUNT(*), MIN(COALESCE(r.rules, 0)) FROM revisions r JOIN resources s ON s.res = r.res
		WHERE r.id = ? AND r.kind = 0 AND `+t.e.inArray("s.ns", "bigint"), id[:], t.e.arrayArg(nss)).Scan(&n, &least))
	rules := schema.V073
	if n > 0 && least.Int64 == int64(schema.Legacy) {
		rules = schema.Legacy
	}
	if sc.copied == nil {
		sc.copied = map[ids.ID]schema.Rules{}
	}
	sc.copied[id] = rules
	return rules
}

// rowRules is the rules marker revision row seq was stored with: NULL
// (written before markers, or mirrored) is Legacy. A row's marker never
// changes, whoever resolves it: the transaction keeps it (t.schemas, by
// seq), read ahead with the heads of a batch's pinned schemas
// (prefetchRules).
func (t *tx) rowRules(seq int64) schema.Rules {
	if l, ok := t.schemas[schemaKey{seq: seq}]; ok {
		return l.rules
	}
	var r sql.NullInt64
	t.must(t.QueryRow(`SELECT rules FROM revisions WHERE seq = ?`, seq).Scan(&r))
	return t.knowRules(seq, r)
}

// knowRules keeps the marker of row seq, stored as r, for the transaction.
func (t *tx) knowRules(seq int64, r sql.NullInt64) schema.Rules {
	rules := schema.Legacy
	if r.Valid && r.Int64 == int64(schema.V073) {
		rules = schema.V073
	}
	if t.schemas == nil {
		t.schemas = map[schemaKey]schemaLoaded{}
	}
	t.schemas[schemaKey{seq: seq}] = schemaLoaded{rules: rules}
	return rules
}

// prefetchRules reads the rules markers of the revision rows seqs in one
// statement (rowRules), but those the transaction knows.
func (t *tx) prefetchRules(seqs []int64) {
	var want []int64
	for _, s := range seqs {
		if _, ok := t.schemas[schemaKey{seq: s}]; !ok {
			want = append(want, s)
		}
	}
	if len(want) == 0 {
		return
	}
	rows, err := t.Query(`SELECT seq, rules FROM revisions WHERE `+t.e.inArray("seq", "bigint"), t.e.arrayArg(want))
	t.must(err)
	defer rows.Close()
	for rows.Next() {
		var seq int64
		var r sql.NullInt64
		t.must(rows.Scan(&seq, &r))
		t.knowRules(seq, r)
	}
	t.must(rows.Err())
}

// schemaRules is the rules marker of the schema revision ref resolved to
// for the writer of sc (loadSchema): an earlier item's of the same write,
// as docRules fixes it, or that of the row it was read from.
func (t *tx) schemaRules(ref schema.Ref, sc *schemaCtx, pending map[string]any) schema.Rules {
	if d, ok := pending[ref.Path()]; ok {
		id, err := ids.Parse(ref.Rev)
		if err != nil {
			return schema.V073
		}
		return t.docRules(id, d, sc)
	}
	l, ok := t.schemas[schemaKey{sc: sc, path: ref.Path()}]
	if !ok || l.seq == 0 {
		return schema.Legacy
	}
	return t.rowRules(l.seq)
}

// validateDoc is step 5: resolve $schema and validate (§6.1) under rules,
// the marker of the revision written, for a schema document. It returns
// the document's $schema, if typed.
func (t *tx) validateDoc(doc any, rules schema.Rules, sc *schemaCtx, pending map[string]any) (string, *Error) {
	m, ok := doc.(map[string]any)
	if !ok {
		return "", nil
	}
	sv, has := m["$schema"]
	if !has {
		return "", nil
	}
	s, _ := sv.(string)
	load := func(ref schema.Ref) (any, error) { return t.loadSchema(ref, sc, pending) }
	// The validator keeps compiled schemas across writes and writers, so
	// availability and read permission are checked here for the whole
	// $ref closure.
	// A schema document (a dialect $schema) starts the closure at its own
	// $refs, so a cached revision the writer may not read is still refused,
	// and the error names the revision that didn't resolve, not the dialect.
	var queue []schema.Ref
	typedBy, typed := schema.ParseRef(s)
	if typed {
		queue = []schema.Ref{typedBy}
	} else if schema.IsDialect(s) {
		queue = schema.Refs(doc)
	}
	{
		seen := map[string]bool{}
		for len(queue) > 0 {
			r := queue[0]
			queue = queue[1:]
			if seen[r.Path()] {
				continue
			}
			seen[r.Path()] = true
			d, err := load(r)
			if err != nil {
				return "", schemaErr(err, r.Path())
			}
			queue = append(queue, t.schemaRefs(r, d, sc, pending)...)
		}
	}
	if typed {
		// The schema revision's own marker governs its closure.
		rules = t.schemaRules(typedBy, sc, pending)
	}
	if err := t.e.validator.ValidateRules(doc, load, rules); err != nil {
		return "", schemaErr(err, s)
	}
	return s, nil
}

// pinnedSchemas lists the schema revisions that the documents of a write's
// steps pin by $schema, for step 5 to read them ahead (prefetchSchemas),
// leaving out the paths of the write's own documents (pendingKey under
// pns): loadSchema finds those among them, without reading their
// namespace, when they come first. A schema document's $refs, and the
// $ref closures, are resolved as they are reached (validateDoc).
func pinnedSchemas(st []*itemState, pns string) []schema.Ref {
	own := map[string]bool{}
	for _, s := range st {
		for _, step := range s.steps {
			if !step.del && !step.sealed {
				own[pendingKey(pns, s.Resource, step.id)] = true
			}
		}
	}
	var refs []schema.Ref
	for _, s := range st {
		for _, step := range s.steps {
			if step.del || step.sealed {
				continue
			}
			m, _ := step.doc.(map[string]any)
			sv, _ := m["$schema"].(string)
			if r, ok := schema.ParseRef(sv); ok && !own[r.Path()] {
				refs = append(refs, r)
			}
		}
	}
	return refs
}

// schemaUnavailable is the 422 schema_unavailable of a schema revision
// path that doesn't resolve for the writer, which path names (§6.1,
// §12.1). ref, the member's name before v0.63, carries it too, for one
// release.
func schemaUnavailable(path string, kv ...any) *Error {
	return apiErr(422, "schema_unavailable", append([]any{"path", path, "ref", path}, kv...)...)
}

func schemaErr(err error, path string) *Error {
	var re *schema.RefError
	var ue *schema.UnavailableError
	var ve *schema.ValidationError
	var se *schema.SchemaError
	switch {
	case errors.As(err, &re):
		return apiErr(422, "schema_ref", "message", re.Msg)
	case errors.Is(err, schema.ErrBranch):
		return apiErr(422, "schema_ref", "message", "a schema reference must not name a branch")
	case errors.As(err, &ue):
		return schemaUnavailable(ue.Ref)
	case schema.RefPath(err) != "":
		// The revision that didn't resolve, wherever in the closure it is,
		// never the document's own $schema (a dialect URL for a schema).
		return schemaUnavailable(schema.RefPath(err))
	case errors.Is(err, schema.ErrUnavailable), errors.Is(err, schema.ErrForbidden):
		return schemaUnavailable(path)
	case errors.As(err, &ve):
		var details []any
		for _, d := range ve.Errors {
			details = append(details, map[string]any{"pointer": d.Pointer, "message": d.Message})
		}
		return apiErr(422, "invalid", "errors", details)
	case errors.As(err, &se):
		return apiErr(422, "invalid", "message", "invalid schema: "+se.Msg)
	}
	return invalid(err.Error())
}

// loadSchema resolves a schema revision path for a writer (§6.1): from the
// write's own earlier items, in the path's namespace, or, in a write to a
// branch, among the drafts in branches of that namespace (loadDraft). A
// path naming a branch is ErrBranch for a writer who can read the revision
// there, whatever the drafts, and unavailable for any other (drafts are
// looked up by the paths of namespaces that aren't branches).
//
// Within a transaction, which reads one snapshot, a path resolves the same
// way for the same writer (sc) every time: the result is kept for the
// transaction (t.schemas), so a batch's documents typed by the same schemas
// resolve and parse each once, not once for every document and $ref.
func (t *tx) loadSchema(ref schema.Ref, sc *schemaCtx, pending map[string]any) (any, error) {
	if d, ok := pending[ref.Path()]; ok {
		return d, nil
	}
	t.deps.addSchema(ref)
	key := schemaKey{sc: sc, path: ref.Path()}
	if r, ok := t.schemas[key]; ok {
		return r.doc, r.err
	}
	d, seq, err := t.loadSchemaIn(ref, sc)
	if err != nil && !errors.Is(err, schema.ErrBranch) {
		if dd, dseq, ok := t.loadDraft(ref, sc); ok {
			d, seq, err = dd, dseq, nil
		} else {
			d = nil
		}
	}
	if t.schemas == nil {
		t.schemas = map[schemaKey]schemaLoaded{}
	}
	t.schemas[key] = schemaLoaded{doc: d, err: err, seq: seq}
	return d, err
}

// schemaKey and schemaLoaded are a transaction's resolved schema paths,
// per writer (loadSchema); and, by seq alone, the rules markers of
// revision rows, which are the row's whoever resolves it (rowRules).
type schemaKey struct {
	sc   *schemaCtx
	path string
	seq  int64
}

type schemaLoaded struct {
	doc any
	err error
	// seq is the row doc was read from, whose rules marker its compile
	// follows (schemaRules); 0 if none. rules is a row's marker, in an
	// entry by seq.
	seq   int64
	rules schema.Rules
	// refs is schema.Refs(doc), once hasRefs (schemaRefs).
	refs    []schema.Ref
	hasRefs bool
}

// schemaRefs is schema.Refs of d, the schema loadSchema resolved ref to,
// kept with it for the transaction (t.schemas): every document typed by a
// schema walks its $ref closure (validateDoc).
func (t *tx) schemaRefs(ref schema.Ref, d any, sc *schemaCtx, pending map[string]any) []schema.Ref {
	key := schemaKey{sc: sc, path: ref.Path()}
	l, ok := t.schemas[key]
	if _, own := pending[key.path]; own || !ok {
		return schema.Refs(d)
	}
	if !l.hasRefs {
		l.refs, l.hasRefs = schema.Refs(d), true
		t.schemas[key] = l
	}
	return l.refs
}

// loadSchemaIn resolves a schema revision path in its own namespace. The
// writer needs read on the copy (§6.1 Read permission): in the namespace
// written, with the write's own grant; in any other, by the rule for other
// namespaces (§7.5). From a sealed namespace, public or not, in the
// namespace written too, it also needs keys that open the revision under
// the epoch it is served under (schemaKeysOpen). A revision it can't read
// there is ErrForbidden, which falls through to drafts in a branch
// (loadSchema), as an absent one does.
func (t *tx) loadSchemaIn(ref schema.Ref, sc *schemaCtx) (any, int64, error) {
	n := t.schemaNS(ref.NS)
	if n == nil || n.purged {
		return nil, 0, schema.ErrUnavailable
	}
	if n.isBranch() {
		// Never into a branch (schema_ref), but that tells only a writer
		// who can read the revision there: for any other the path doesn't
		// resolve, as in a namespace that doesn't exist (§6.1).
		if row := t.schemaRevRow(n, ref); row != nil && t.schemaReadable(n, ref.Name, sc) && t.schemaKeysOpen(n, ref.Name, row, sc) {
			return nil, 0, schema.ErrBranch
		}
		return nil, 0, schema.ErrUnavailable
	}
	if t.e2eContent(n, ref.Name) {
		// The server can't read schemas in an e2e namespace (§E.3.2).
		return nil, 0, schema.ErrUnavailable
	}
	// A namespace that opens its schemas with schemaReads lets writes to a
	// listed namespace resolve them without read (§6.1); only schema
	// documents, checked once loaded.
	readable := t.schemaReadable(n, ref.Name, sc)
	if !readable && (sc.target == nil || !t.schemaReadsServe(n, sc.target)) {
		return nil, 0, schema.ErrForbidden
	}
	row := t.schemaRevRow(n, ref)
	if row == nil {
		return nil, 0, schema.ErrUnavailable
	}
	if readable && !t.schemaKeysOpen(n, ref.Name, row, sc) {
		return nil, 0, schema.ErrForbidden
	}
	d, err := t.schemaDocAt(row)
	if err != nil {
		return nil, 0, err
	}
	if !readable && !schema.IsSchemaDoc(d) {
		return nil, 0, schema.ErrForbidden
	}
	return d, row.seq, nil
}

// schemaReadable reports whether the writer of sc may read resource name
// of n (§6.1 Read permission): in the namespace written, with the write's
// own grant; in any other, by the rule for other namespaces (§7.5), with
// it or a grant in Source-Authorization.
func (t *tx) schemaReadable(n *nsRow, name string, sc *schemaCtx) bool {
	if sc.target != nil && n.id == sc.target.id {
		return t.canRead(n, t.config(n.configSeq), sc.a, name)
	}
	return t.credsRead(n, name, sc.creds)
}

// schemaKeysOpen reports whether the writer of sc gets keys opening schema
// revision row of resource name in n, as resolving it takes in a sealed
// namespace, public or not, the namespace written included (§6.1 Read
// permission, §2.1 Protection): §E.2.3's keys for the epoch the revision
// is served under, to the request's own grant or one in
// Source-Authorization (keywindow.go). Other namespaces need none here
// (schemaReads is refused in sealed ones, §6.1).
func (t *tx) schemaKeysOpen(n *nsRow, name string, row *revRow, sc *schemaCtx) bool {
	if !t.isSealedNS(n) {
		return true
	}
	return t.revKeyOpen(n, name, row, sc.creds)
}

// schemaNS is nsByName for the namespace of a schema path (loadSchemaIn),
// which the transaction remembers (memo.schemaNS): a batch whose documents
// are typed by many schemas of one namespace reads its row once, not once
// per schema.
func (t *tx) schemaNS(name string) *nsRow {
	if n, ok := t.memo.schemaNS[name]; ok {
		// Taking the lock (a row read while namespaces weren't locked,
		// noLock) forgets the row, which is then read again under it.
		t.lockNS(n.id, lockShared)
		if n, ok := t.memo.schemaNS[name]; ok {
			t.deps.addNS(&n)
			return &n
		}
	}
	n := t.nsByName(name)
	if n != nil {
		t.memoSchemaNS(n)
	}
	return n
}

func (t *tx) memoSchemaNS(n *nsRow) {
	if t.memo.schemaNS == nil {
		t.memo.schemaNS = map[string]nsRow{}
	}
	t.memo.schemaNS[n.name] = *n
}

// prefetchSchemas reads ahead what resolving refs, schema revision paths,
// reads in storage (loadSchemaIn): the rows of their namespaces in one
// statement, then for each namespace the rows of the resources they name
// and of those resources' heads in two more (prefetchHeads). On Postgres
// every namespace's lock is taken first, shared as nsByName takes it and
// in ascending key order, and the rows are read once all are held
// (pglock.go). loadSchemaIn then answers a path whose revision is its
// resource's head from the transaction's memo; an older revision is looked
// up in the resource's ancestry, and a schema's $ref closure resolved, as
// before. (A batch whose documents were typed by a thousand schemas of one
// namespace read three rows for each, a statement each: the namespace's,
// the resource's and its head's.)
func (t *tx) prefetchSchemas(refs []schema.Ref) {
	byNS := map[string]map[string]bool{}
	for _, r := range refs {
		if byNS[r.NS] == nil {
			byNS[r.NS] = map[string]bool{}
		}
		byNS[r.NS][r.Name] = true
	}
	if len(byNS) == 0 {
		return
	}
	nsNames := sortedKeys(byNS)
	if t.locking() {
		want := map[int32]lockMode{}
		var unknown []string
		for _, name := range nsNames {
			if v, ok := t.e.ids.nss.Load(name); ok {
				want[lockKey(v.(int64))] = lockShared
			} else {
				unknown = append(unknown, name)
			}
		}
		if len(unknown) > 0 {
			rows, err := t.Query(`SELECT ns, name FROM namespaces WHERE `+t.e.inArray("name", "text"), t.e.arrayArg(unknown))
			t.must(err)
			for rows.Next() {
				var id int64
				var name string
				t.must(rows.Scan(&id, &name))
				want[lockKey(id)] = lockShared
				if !t.dirty {
					t.e.ids.nss.Store(name, id)
				}
			}
			t.must(rows.Err())
			rows.Close()
		}
		t.lockAll(want)
	}
	var read []string
	for _, name := range nsNames {
		if _, ok := t.memo.schemaNS[name]; !ok {
			read = append(read, name)
		}
	}
	if len(read) > 0 {
		rows, err := t.Query(`SELECT `+nsCols+` FROM namespaces WHERE `+t.e.inArray("name", "text"), t.e.arrayArg(read))
		t.must(err)
		for rows.Next() {
			n, err := scanNS(rows)
			t.must(err)
			if !n.isShadow() { // never a path's (nsByName)
				t.memoSchemaNS(n)
			}
		}
		t.must(rows.Err())
		rows.Close()
	}
	var heads []int64
	for _, name := range nsNames {
		n := t.schemaNS(name) // as loadSchemaIn reads it (writeDeps)
		// loadSchemaIn reads no resource of a namespace that is unknown,
		// purged, a branch or e2e.
		if n == nil || n.purged || n.isBranch() || t.isE2E(n) {
			continue
		}
		names := sortedKeys(byNS[name])
		t.prefetchHeads(n, names, nil)
		for _, nm := range names {
			if r := t.memo.res[resKey{n.id, nm}]; r != nil && r.headSeq.Valid {
				heads = append(heads, r.headSeq.Int64)
			}
		}
	}
	// The heads' rules markers, which a document typed by one compiles
	// under (schemaRules).
	t.prefetchRules(heads)
}

// schemaRevRow finds revision ref.Rev of resource ref.Name in n: nil if
// unknown, purged or a tombstone.
func (t *tx) schemaRevRow(n *nsRow, ref schema.Ref) *revRow {
	v := t.resolve(n, ref.Name, nil)
	if v.head == nil || v.state == Purged || v.state == NotFound {
		return nil
	}
	id, err := ids.Parse(ref.Rev)
	if err != nil {
		return nil
	}
	row := t.findInAncestry(v.head, id)
	if row == nil || row.kind == kindTombstone {
		return nil
	}
	return row
}

// schemaRevIn loads revision ref.Rev of resource ref.Name in n, a
// namespace that isn't a branch: ErrUnavailable if unknown, purged,
// pruned or a tombstone.
func (t *tx) schemaRevIn(n *nsRow, ref schema.Ref) (any, error) {
	row := t.schemaRevRow(n, ref)
	if row == nil {
		return nil, schema.ErrUnavailable
	}
	return t.schemaDocAt(row)
}

// schemaDocAt is the document of schema revision row.
func (t *tx) schemaDocAt(row *revRow) (any, error) {
	// A revision with its patch set is the document its id determines:
	// parsed once, kept apart from the document cache, which a large write
	// fills with its own (docBytesAt).
	if row.patches.Valid {
		if d, ok := t.e.schemaDocs.get(row.id); ok {
			return d, nil
		}
	}
	d, err := t.docAt(row)
	if err != nil {
		return nil, schema.ErrUnavailable
	}
	if row.patches.Valid {
		t.e.schemaDocs.put(row.id, d)
	}
	return d, nil
}
