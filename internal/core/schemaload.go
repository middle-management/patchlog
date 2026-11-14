package core

import (
	"bytes"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/jsv"
	"github.com/middle-management/patchlog/internal/lru"
	"github.com/middle-management/patchlog/internal/schema"
)

// Schema rules markers: metadata only since v0.74.
//
// Every schema compiles under this version, whatever version stored it
// (§6.1, SPEC-CHANGELOG v0.74 Core), so the markers below select nothing:
// schema.Validator.ValidateMarked ignores them, a schema document is
// checked in write mode, and each revision of a closure compiles under
// current rules, a stored revision only an earlier version accepted being
// an invalid schema (a write pinning it is 422 invalid). They are still
// recorded and served, unchanged, so a database or a remote mirror keeps
// the same rows either side of the upgrade:
//
// Each revision row records, in revisions.rules, the rules its document was
// written under (schema.Rules): V073 for those written now, Legacy for a
// copy of a revision stored under the earlier rules. Rows from before the
// column are NULL, read as Legacy. The marker never changes, and isn't
// part of the revision id.
//
// A schema revision read in the clear carries its marker in
// schema.RulesHeader (Rev.SchemaRules). The rows a remote branch mirrors
// from another deployment (§G.3) keep the marker the base serves each
// schema revision with (fetchRules, F-S1), and are NULL where it serves
// none.
//
// A revision whose document is a schema document and whose id other rows
// already have is a content-addressed copy of them (§3.3): a fast-forward
// merge, a same-deployment import or a branch's replay of its base's
// revision. It inherits their marker, Legacy if any is. Only rows the
// write may take content from count: in the namespace written and its
// local bases, and in a batch's local source, read unrestricted, and its
// bases (copiesIn), so the marker reveals nothing about namespaces the
// writer can't read.

// validateStep is step 5 for one step (§6.1, §6.2): it fixes the rules
// marker of the revision the step writes (docRules), which step 7 stores,
// and validates the resulting document under this version's rules (§6.1):
// a schema document in write mode, any other against the schema revision
// it names, each revision of its closure compiled under current rules;
// the markers select nothing (ValidateMarked).
//
// A patch to a document this engine has itself validated against the same
// schema revision is validated only where it can have changed the verdict
// (changedPaths, jsv.ValidateChange); anything else in full.
func (t *tx) validateStep(step *stepState, sc *schemaCtx, pending map[string]any) (string, *Error) {
	rules := t.docRules(step.id, step.doc, sc)
	step.legacy = rules == schema.Legacy
	changed, partial := t.e.changedPaths(step)
	typed, err := t.validateDoc(step.doc, len(step.docCanon), changed, partial, sc, pending)
	if err == nil {
		if _, ok := schema.ParseRef(typed); ok {
			t.e.validated.put(step.id, typed)
		}
	}
	return typed, err
}

// validatedDocs remembers which revisions this engine, since it started,
// has found valid against which schema revision: the proof that a patch
// to one may be validated by its changes alone. That a revision is stored
// is no such proof: a remote branch mirrors revisions another deployment
// validated (§G.3), and those of an earlier version of this one were
// validated as that version read schemas and formats. A revision id fixes
// its document (§3.3) and a schema revision path its schema, so the fact
// holds wherever and whenever the id is met again; the first patch to a
// document after a restart is validated in full.
type validatedDocs struct {
	mu sync.Mutex
	c  lru.Cache[ids.ID, string]
}

// validatedDocsMax is how many revisions validatedDocs remembers, the
// least recently used forgotten first: an id and a schema path each.
const validatedDocsMax = 1 << 17

func (v *validatedDocs) put(id ids.ID, schemaRef string) {
	v.mu.Lock()
	v.c.MaxEntries = validatedDocsMax
	v.c.Put(id, schemaRef, 1)
	v.mu.Unlock()
}

func (v *validatedDocs) get(id ids.ID) string {
	v.mu.Lock()
	s, _ := v.c.Get(id)
	v.mu.Unlock()
	return s
}

// ValidationCounts returns how many documents with a $schema step 5 has
// validated in full and how many by their changes, since the engine
// started.
func (e *Engine) ValidationCounts() (full, change int64) {
	return e.validatedFull.Load(), e.validatedChange.Load()
}

// validateBoth makes every step that is validated by its changes also be
// validated in full, and panics if the two disagree: a switch for test
// runs (PATCHLOG_TEST_VALIDATE_BOTH=1 go test ./...), read once.
var validateBoth = os.Getenv("PATCHLOG_TEST_VALIDATE_BOTH") != ""

// changedPaths decides how step 5 validates a step's document: by its
// changes, which it returns as JSON Pointers into the instance
// (schema.Instance), or (false) in full. By its changes only if all hold:
//
//   - the step appends a patch set to a live document: not a create, a
//     restore, a delete or a sealed step;
//   - the document it applied to and the one it results in name the same
//     schema revision in $schema, and no operation touches $schema;
//   - this engine has validated the document it applied to against that
//     revision (validatedDocs): an earlier write, or an earlier step of
//     this one.
//
// The changes are those of the patch's operations (jsv.ChangedPathsIn: an
// insertion into or removal from an array is the array). The top-level
// members step 5 leaves out of the instance ($nonce and $successor of
// their forms, schema.LeftOut) are no change to it when they were left
// out before and are now; in any other case they stay, and name a member
// of the instance, or nothing in it, which is validated as the root.
func (e *Engine) changedPaths(step *stepState) ([]string, bool) {
	if e.opt.FullValidation || step.action != "append" || step.sealed || step.del || step.parentID == nil {
		return nil, false
	}
	m, ok := step.doc.(map[string]any)
	if !ok || step.prev.schema == "" {
		return nil, false
	}
	if s, _ := m["$schema"].(string); s != step.prev.schema {
		return nil, false
	}
	if _, ok := schema.ParseRef(step.prev.schema); !ok {
		return nil, false
	}
	if e.validated.get(*step.parentID) != step.prev.schema {
		return nil, false
	}
	ops, ok := step.raw.([]any)
	if !ok {
		return nil, false
	}
	paths, err := jsv.ChangedPathsIn(step.doc, ops)
	if err != nil {
		return nil, false
	}
	out := paths[:0]
	for _, p := range paths {
		if p == "" {
			return nil, false
		}
		top := p[1:]
		if i := strings.IndexByte(top, '/'); i >= 0 {
			top = top[:i]
		}
		switch top {
		case "$schema":
			return nil, false
		case "$nonce", "$successor":
			wasOut := step.prev.nonceOut
			if top == "$successor" {
				wasOut = step.prev.successorOut
			}
			// Left out before, and left out or gone now: no change to
			// the instance.
			if v, has := m[top]; wasOut && (!has || schema.LeftOut(top, v)) {
				continue
			}
		}
		out = append(out, p)
	}
	return out, true
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
// (written before markers, or mirrored from a base that served none) is
// Legacy. A row's marker never
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

// schemaRulesHeader is Rev.SchemaRules for revision row r served with
// document b: its marker if b is a schema document, "" otherwise.
func (t *tx) schemaRulesHeader(r *revRow, b []byte) string {
	if !bytes.Contains(b, schemaDialectMember) {
		return ""
	}
	doc, err := jsonv.Parse(b)
	if err != nil || !schema.IsSchemaDoc(doc) {
		return ""
	}
	return t.rowRules(r.seq).String()
}

// schemaDialectMember is how a schema document's $schema reads in its
// canonical bytes (§3.1), which every schema document holds.
var schemaDialectMember = []byte(`"$schema":"` + schema.Dialect2020 + `"`)

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

// validateDoc is step 5: resolve $schema and validate (§6.1). With
// partial, the document is one changed at changed from one known valid
// against the same schema revision (changedPaths), and is validated there.
// It returns the document's $schema, if typed.
func (t *tx) validateDoc(doc any, size int, changed []string, partial bool, sc *schemaCtx, pending map[string]any) (string, *Error) {
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
	// Each revision of the closure compiles under this version's rules,
	// whatever its marker (§6.1), so neither rules nor the markers of the
	// closure select anything.
	span := validateSpan(t.ctx, s, doc, size)
	budget := max(t.e.opt.MaxValidationSteps, 0)
	var steps int
	var err error
	mode := "full"
	if partial {
		mode = "change"
		t.e.validatedChange.Add(1)
		steps, err = t.e.validator.ValidateChangeBudget(doc, load, changed, budget)
		if validateBoth {
			_, ferr := t.e.validator.ValidateBudget(doc, load, 0)
			var be *schema.BudgetError
			if !errors.As(err, &be) && (err == nil) != (ferr == nil) {
				panic(fmt.Sprintf("core: validation by changes %q of a document typed %s says %v, in full %v:\n%s", changed, s, err, ferr, jsonv.Canonical(doc)))
			}
		}
	} else {
		t.e.validatedFull.Add(1)
		steps, err = t.e.validator.ValidateBudget(doc, load, budget)
	}
	endValidateSpan(span, err, steps, mode)
	if err != nil {
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
	var be *schema.BudgetError
	switch {
	case errors.As(err, &be):
		return limitErr(422, "validationSteps", int64(be.Steps), int64(be.Budget), "validating the document against its schema takes too many steps")
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
	// seq is the row doc was read from, whose rules marker doc compiles
	// under (schemaRules); 0 if none. rules is a row's marker, in an
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
		// The server can't read a revision written while its namespace
		// was e2e (§6.1, §E.3.2).
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
		// purged or a branch, and of an e2e one only revisions from
		// before its raise, read without the prefetch.
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
	// The heads' rules markers (schemaRules), metadata only since v0.74
	// (§6.1).
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
