package core

import (
	"errors"

	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/schema"
)

// validateDoc is step 5: resolve $schema and validate (§6.1). It returns the
// document's $schema, if typed.
func (t *tx) validateDoc(doc any, sc *schemaCtx, pending map[string]any) (string, *Error) {
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
	if r, ok := schema.ParseRef(s); ok {
		queue = []schema.Ref{r}
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
	if err := t.e.validator.Validate(doc, load); err != nil {
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
		return apiErr(422, "schema_unavailable", "ref", ue.Ref)
	case schema.RefPath(err) != "":
		// The revision that didn't resolve, wherever in the closure it is,
		// never the document's own $schema (a dialect URL for a schema).
		return apiErr(422, "schema_unavailable", "ref", schema.RefPath(err))
	case errors.Is(err, schema.ErrUnavailable), errors.Is(err, schema.ErrForbidden):
		return apiErr(422, "schema_unavailable", "ref", path)
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
// path naming a branch is ErrBranch, whatever the drafts.
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
	key := schemaKey{sc, ref.Path()}
	if r, ok := t.schemas[key]; ok {
		return r.doc, r.err
	}
	d, err := t.loadSchemaIn(ref, sc)
	if err != nil && !errors.Is(err, schema.ErrBranch) {
		if dd, ok := t.loadDraft(ref, sc); ok {
			d, err = dd, nil
		} else {
			d = nil
		}
	}
	if t.schemas == nil {
		t.schemas = map[schemaKey]schemaLoaded{}
	}
	t.schemas[key] = schemaLoaded{doc: d, err: err}
	return d, err
}

// schemaKey and schemaLoaded are a transaction's resolved schema paths
// (loadSchema).
type schemaKey struct {
	sc   *schemaCtx
	path string
}

type schemaLoaded struct {
	doc any
	err error
	// refs is schema.Refs(doc), once hasRefs (schemaRefs).
	refs    []schema.Ref
	hasRefs bool
}

// schemaRefs is schema.Refs of d, the schema loadSchema resolved ref to,
// kept with it for the transaction (t.schemas): every document typed by a
// schema walks its $ref closure (validateDoc).
func (t *tx) schemaRefs(ref schema.Ref, d any, sc *schemaCtx, pending map[string]any) []schema.Ref {
	key := schemaKey{sc, ref.Path()}
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
func (t *tx) loadSchemaIn(ref schema.Ref, sc *schemaCtx) (any, error) {
	n := t.schemaNS(ref.NS)
	if n == nil || n.purged {
		return nil, schema.ErrUnavailable
	}
	if n.isBranch() {
		return nil, schema.ErrBranch
	}
	if t.e2eContent(n, ref.Name) {
		// The server can't read schemas in an e2e namespace (§E.3.2).
		return nil, schema.ErrUnavailable
	}
	// A namespace that opens its schemas with schemaReads lets writes to a
	// listed namespace resolve them without read (§6.1); only schema
	// documents, checked once loaded.
	var readable bool
	if sc.target != nil && n.id == sc.target.id {
		readable = t.canRead(n, t.config(n.configSeq), sc.a, ref.Name)
	} else {
		readable = t.credsRead(n, ref.Name, sc.creds)
	}
	if readable {
		row := t.schemaRevRow(n, ref)
		if row == nil {
			return nil, schema.ErrUnavailable
		}
		if !t.schemaKeysOpen(n, ref.Name, row, sc) {
			return nil, schema.ErrForbidden
		}
		return t.schemaDocAt(row)
	}
	if sc.target == nil || !t.schemaReadsServe(n, sc.target) {
		return nil, schema.ErrForbidden
	}
	d, err := t.schemaRevIn(n, ref)
	if err != nil {
		return nil, err
	}
	if !schema.IsSchemaDoc(d) {
		return nil, schema.ErrForbidden
	}
	return d, nil
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
	for _, name := range nsNames {
		n := t.schemaNS(name) // as loadSchemaIn reads it (writeDeps)
		// loadSchemaIn reads no resource of a namespace that is unknown,
		// purged, a branch or e2e.
		if n == nil || n.purged || n.isBranch() || t.isE2E(n) {
			continue
		}
		t.prefetchHeads(n, sortedKeys(byNS[name]), nil)
	}
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
