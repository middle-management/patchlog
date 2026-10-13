package bundle

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/middle-management/patchlog/internal/annot"
	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/patch"
	"github.com/middle-management/patchlog/internal/pointer"
	"github.com/middle-management/patchlog/internal/schema"
	"github.com/middle-management/patchlog/internal/verify"
)

// Renamed imports (§G.4.4 Renaming). An import that maps source namespaces
// to new names (ImportOptions.NSMap, src=dst) clones them: it rewrites
// every reference to a renamed namespace in the documents it brings
// ($schema, $ref, pinned and live x-ref values), and every pin of a
// revision that gets a new id, which takes it. Rewritten documents are new
// content: a full-history document whose steps change is written step by
// step with new ids, never fast-forwarded, its signatures left behind, and
// its batches' source.ids record the source ids. Its new ids are computed
// here, before anything is written, in the order its pins need them; the
// batches that write them go once those of the revisions they pin have
// committed (buildNodes), and each checks that the ids it produced are
// these (submitBatch), so every dependent is written with the ids its
// dependencies' batches returned (§G.4.4 Rewriting waits for its targets).
// A document whose steps change nothing keeps its ids, since ids don't
// include the namespace, and is imported as any other (create,
// fast-forward, present).
//
// A mapping onto a branch whose base chain reaches the source namespace,
// such as an import into a branch first (§F.3), renames nothing: a
// branch's paths name its base (§F.9), so references and ids stay.
//
// References are found where they are declared: a document's $schema, a
// schema's $ref, and the x-ref positions its schema declares (§6.5), as
// the source's schemas declare them. A string of the reference form
// anywhere else can't be found, so it stays, and the report lists it
// (UndeclaredRef.Renamed), as for pinned strings in snapshot documents.
// Catalog placement names (<ns>.<name>) aren't renamed, and a namespace's
// configuration isn't in the bundle (§G.7).
//
// Refused before anything is written (CheckError): an incremental
// document (requires) that may change, whose base the target holds under
// ids this import doesn't know (one that doesn't change keeps its ids, and
// requires works as without renaming, as for a branch bundle onto its
// base); a pin into a renamed namespace, or of a document that changes,
// whose revision the import doesn't write (external, left out by -only,
// or a snapshot's), whose new id isn't known; and a schema whose $id
// names its own revision path, which can't be rewritten with it (§6.1).

// rewritten is a full-history document as a renamed import writes it:
// per line of the bundle, the rewritten step and the id it produces.
type rewritten struct {
	ids   []string
	steps []client.Step
	sizes []int // the steps' canonical sizes (stepSizes)
	idx   map[string]int
	doc   any // the document after the last step (a tombstone's last live one)
	live  bool
	done  int // the lines rewritten so far
}

// head is the head an import writes of a full-history document: the
// bundle's, or the rewritten one.
func (d *bdoc) head() string {
	if d.rw != nil {
		return d.rw.ids[len(d.rw.ids)-1]
	}
	return d.info.Head
}

// position is where id is in the history an import writes of d.
func (d *bdoc) position(id string) (int, bool) {
	if d.rw != nil {
		i, ok := d.rw.idx[id]
		return i, ok
	}
	i, ok := d.idx[id]
	return i, ok
}

// idAt is the id of line i as the import writes it.
func (d *bdoc) idAt(i int) string {
	if d.rw != nil {
		return d.rw.ids[i]
	}
	return d.lines[i].ID
}

// stepsFrom are the steps that write d's lines from i on.
func (d *bdoc) stepsFrom(i int) []client.Step {
	if d.rw != nil {
		return d.rw.steps[i:]
	}
	return stepsOfLines(d.lines[i:])
}

// lineIDs are the source ids of lines.
func lineIDs(ls []*Line) []string {
	out := make([]string, len(ls))
	for i, l := range ls {
		out[i] = l.ID
	}
	return out
}

// stepRefs is what a step of a full-history document references that a
// renamed import may rewrite (mayRename), as rename finds it.
type stepRefs struct {
	// declared are such strings at the declared positions of the step's
	// resulting document, by pointer.
	declared map[string]string
	// leaves are such strings in the values of its add and replace ops.
	leaves []leaf
}

// leaf is a string in an op's value, and where it lands.
type leaf struct {
	op       int    // the op's index in the patch set
	at       string // its pointer within the op's value
	s        string
	to       string // its pointer in the step's resulting document, "" if it lands nowhere
	declared bool   // to is a declared position
}

// strings are the reference strings of a step that rewriting reads.
func (sr *stepRefs) strings() []string {
	var out []string
	for _, lf := range sr.leaves {
		if lf.declared {
			out = append(out, lf.s)
		}
	}
	for _, s := range sr.declared {
		out = append(out, s)
	}
	return out
}

// resolveRenames decides which mappings rename (§G.4.4): every src=dst of
// a namespace of the bundle, or of its external dependencies, with src !=
// dst, but one onto a branch whose base chain reaches src (ontoBranch),
// which keeps references and ids.
func (im *importer) resolveRenames(ctx context.Context) error {
	im.renames = map[string]string{}
	in := map[string]bool{}
	for ns := range im.h.At {
		in[ns] = true
	}
	for _, e := range im.h.External {
		if ext, ok := ParseExternal(e); ok {
			in[ext.NS] = true
		}
	}
	srcs := make([]string, 0, len(im.opt.NSMap))
	for src := range im.opt.NSMap {
		srcs = append(srcs, src)
	}
	sort.Strings(srcs)
	var names []string
	for _, src := range srcs {
		dst := im.opt.NSMap[src]
		if !in[src] || dst == "" || dst == src {
			continue
		}
		onto, err := im.ontoBranch(ctx, src, dst)
		if err != nil {
			return err
		}
		if onto {
			continue
		}
		im.renames[src] = dst
		names = append(names, src+"="+dst)
	}
	if len(names) == 0 {
		return nil
	}
	im.rep.Renamed = im.renames
	im.rep.Notes = append(im.rep.Notes, fmt.Sprintf("renames %s (§G.4.4): references to them are rewritten where they are declared, and documents that change get new ids; "+
		"catalog placement names (<ns>.<name>) aren't renamed, and namespace configuration isn't in the bundle (§G.7): "+
		"create the renamed targets with theirs first, or the import creates them with defaults", strings.Join(names, ", ")))
	return nil
}

// ontoBranch reports whether target namespace dst is a branch whose base
// chain reaches src, in the target or, for a remote branch, in the
// bundle's origin, where its base.chain lists the bases it verified
// (§G.3).
func (im *importer) ontoBranch(ctx context.Context, src, dst string) (bool, error) {
	ns := dst
	for i := 0; i < 64; i++ {
		doc, ok, err := im.namespaceDoc(ctx, ns)
		if err != nil {
			return false, fmt.Errorf("import: target namespace %s: %w", ns, err)
		}
		if !ok {
			return false, nil
		}
		b, _ := doc["base"].(map[string]any)
		if b == nil {
			return false, nil
		}
		bns, _ := b["ns"].(string)
		if bns == src {
			if o, remote := b["origin"].(string); remote && o != im.h.Origin {
				return false, nil
			}
			return true, nil
		}
		if o, remote := b["origin"].(string); remote {
			chain, _ := b["chain"].([]any)
			for _, x := range chain {
				if x == src && o == im.h.Origin {
					return true, nil
				}
			}
			return false, nil
		}
		ns = bns
	}
	return false, nil
}

// brought reports whether the import writes d's namespace (ImportOptions.Only).
func (im *importer) brought(d *bdoc) bool { return im.only == nil || im.only[d.ns] }

// mayChange marks the full-history documents a renamed import may rewrite:
// those with strings that name a renamed namespace, and those that pin
// one of them, in turn (pinKeys). The others keep their ids and aren't
// read again.
func (im *importer) mayChange() map[string]bool {
	out := map[string]bool{}
	for k, d := range im.docs {
		if d.info.History != Full {
			continue
		}
		for ns := range d.refNS {
			if _, ok := im.renames[ns]; ok {
				out[k] = true
				break
			}
		}
	}
	for grew := true; grew; {
		grew = false
		for k, d := range im.docs {
			if out[k] || d.info.History != Full {
				continue
			}
			for p := range d.pinKeys {
				if out[p] {
					out[k], grew = true, true
					break
				}
			}
		}
	}
	return out
}

// mayRename reports whether rewriting may change reference string s: it
// names a renamed namespace, or pins a document that may change.
func (im *importer) mayRename(s string) bool {
	r, ok := annot.ParseRefString(s)
	if !ok {
		return false
	}
	if _, ok := im.renames[r.NS]; ok {
		return true
	}
	return r.Rev != "" && im.potential[Key(r.NS, r.Name)]
}

// pinProblem is why a pin r, in a renamed namespace if renamed, can't be
// rewritten, or "": the import doesn't write the revision it pins, and
// that revision gets a new id or lives in a renamed namespace. A pin a
// whole import leaves as it is (one into a namespace not renamed, of a
// document that doesn't change) has none.
func (im *importer) pinProblem(r annot.Ref, renamed bool) string {
	t := im.docs[Key(r.NS, r.Name)]
	if t != nil && t.info.History == Full {
		if _, in := t.idx[r.Rev]; in && (im.brought(t) || !im.potential[t.key]) {
			return ""
		}
	}
	if !renamed && (t == nil || !im.potential[t.key]) {
		return ""
	}
	why := "which the bundle doesn't carry (external)"
	switch {
	case t != nil && t.info.History == Snapshot:
		why = "a snapshot document's, whose revisions get the ids of its upstream chain"
	case t != nil && !im.brought(t):
		why = "which the import leaves out (-only): import its namespace with this one"
	case t != nil:
		why = "which isn't in the bundle's history of it (the base of requires)"
	}
	return fmt.Sprintf("it pins revision %s of %s, %s, so its new id isn't known", r.Rev, Key(r.NS, r.Name), why)
}

// renamedRef is reference string s as a renamed import writes it: its
// namespace renamed, and a pinned revision that gets a new id taking it,
// any fragment kept. wait reports a pin of a revision whose new id isn't
// computed yet (rename), problem one that can't be rewritten (pinProblem).
func (im *importer) renamedRef(s string) (out string, wait bool, problem string) {
	r, ok := annot.ParseRefString(s)
	if !ok {
		return s, false, ""
	}
	ns, renamed := im.renames[r.NS]
	if !renamed {
		ns = r.NS
	}
	rev := r.Rev
	if rev != "" {
		if p := im.pinProblem(r, renamed); p != "" {
			return s, false, p
		}
		if t := im.docs[Key(r.NS, r.Name)]; t != nil && t.rw != nil {
			i := t.idx[rev]
			if i >= t.rw.done {
				return s, true, ""
			}
			rev = t.rw.ids[i]
		}
	}
	if ns == r.NS && rev == r.Rev {
		return s, false, ""
	}
	out = "/r/" + ns + "/" + r.Name
	if rev != "" {
		out += "/rev/" + rev
	}
	if i := strings.IndexByte(s, '#'); i >= 0 {
		out += s[i:]
	}
	return out, false, ""
}

// rename computes how a renamed import writes the full-history documents
// it brings (d.rw), and checks what it can't rewrite. Nothing is read
// from the target but schemas and, in a sealed target or one that
// requires nonces, what an earlier run of the same import wrote there
// (resume).
//
// A first pass replays each document that may change (mayChange) and
// finds, per step, the references that may need rewriting where they are
// declared, and where the strings its ops write land. A document changes
// if one of them names a renamed namespace, or pins a document that
// changes. A second pass rewrites the documents that change, step by step,
// each step once the revisions it pins have their new ids: a revision's
// id covers what it pins, so pins can't form a cycle, but two documents
// may pin each other's earlier revisions, which takes several passes.
func (im *importer) rename(ctx context.Context) error {
	if len(im.renames) == 0 {
		return nil
	}
	im.potential = im.mayChange()
	var problems []string
	// Pins of documents left out (-only) that may change.
	outs := make([]string, 0, len(im.outRefs))
	for k := range im.outRefs {
		outs = append(outs, k)
	}
	sort.Strings(outs)
	for _, k := range outs {
		if !im.potential[k] {
			continue
		}
		for _, rev := range sortedSet(im.outRefs[k]) {
			if rev != "" {
				problems = append(problems, fmt.Sprintf("imported documents pin revision %s of %s, which the import leaves out (-only) and which a renamed import may give a new id: import its namespace with them", rev, k))
			}
		}
	}

	type scanned struct {
		steps []*stepRefs
		id    string // a schema's $id, "" if none
	}
	scans := map[string]*scanned{}
	var docs []*bdoc
	loader := im.schemaLoader(ctx)
	var undeclared []UndeclaredRef
	for _, k := range im.keys {
		d := im.docs[k]
		if d.info.History != Full || !im.potential[k] {
			continue
		}
		if d.requires != "" {
			// Its lines go on from a revision the target holds under ids
			// this import doesn't know, if an earlier one rewrote it.
			problems = append(problems, fmt.Sprintf("%s is incremental (requires %s), and a renamed import can't rewrite it: "+
				"import a whole bundle of it (exported without requires) under the new names", k, d.requires))
			continue
		}
		steps, id, und, probs, err := im.scanRenames(d, loader)
		if err != nil {
			return err
		}
		scans[k] = &scanned{steps: steps, id: id}
		docs = append(docs, d)
		undeclared = append(undeclared, und...)
		problems = append(problems, probs...)
	}

	// Which documents change: a declared reference to a renamed
	// namespace, or a pin of a document that changes, in turn.
	changed := map[string]bool{}
	pins := map[string]map[string]bool{} // key → the documents its declared references pin
	for _, d := range docs {
		pins[d.key] = map[string]bool{}
		for _, sr := range scans[d.key].steps {
			if sr == nil {
				continue
			}
			for _, s := range sr.strings() {
				r, _ := annot.ParseRefString(s)
				if _, ok := im.renames[r.NS]; ok {
					changed[d.key] = true
				}
				if r.Rev != "" {
					pins[d.key][Key(r.NS, r.Name)] = true
				}
			}
		}
	}
	for grew := true; grew; {
		grew = false
		for _, d := range docs {
			if changed[d.key] {
				continue
			}
			for p := range pins[d.key] {
				if changed[p] {
					changed[d.key], grew = true, true
					break
				}
			}
		}
	}
	for _, d := range docs {
		if id := scans[d.key].id; id != "" {
			_, renamed := im.renames[d.ns]
			if renamed || changed[d.key] {
				problems = append(problems, fmt.Sprintf("%s is a schema whose $id names its own revision path (%s), which a renamed import can't rewrite with it: "+
					"its new path would name its new id, which covers the $id (§6.1); remove $id from the schema at the source", d.key, id))
			}
		}
	}
	if len(problems) > 0 {
		return &CheckError{Problems: problems}
	}
	for _, u := range undeclared {
		if r, _ := annot.ParseRefString(u.Value); im.renames[r.NS] != "" || (r.Rev != "" && changed[Key(r.NS, r.Name)]) {
			im.rep.Undeclared = append(im.rep.Undeclared, u)
		}
	}

	// The second pass.
	var states []*renameState
	for _, d := range docs {
		if !changed[d.key] {
			continue
		}
		n := len(d.lines)
		d.rw = &rewritten{ids: make([]string, n), steps: make([]client.Step, n), sizes: make([]int, n), idx: map[string]int{}}
		d.rep.Renamed = true
		states = append(states, &renameState{d: d, steps: scans[d.key].steps})
	}
	for _, st := range states {
		if im.sealedT[st.d.tns] {
			if err := im.resume(ctx, st); err != nil {
				return fmt.Errorf("import: %s: %w", st.d.key, err)
			}
		}
	}
	for {
		progress := false
		for _, st := range states {
			for st.pos < len(st.d.lines) {
				wait, err := im.renameStep(st)
				if err != nil {
					return fmt.Errorf("import: %s: %w", st.d.key, err)
				}
				if wait {
					break
				}
				progress = true
			}
		}
		if !progress {
			break
		}
	}
	for _, st := range states {
		if st.pos < len(st.d.lines) {
			return fmt.Errorf("import: %s: its pinned references to rewritten documents can't be resolved: they form a cycle at revision %s, which a bundle can't hold", st.d.key, st.d.lines[st.pos].ID)
		}
		st.d.rw.doc, st.d.rw.live = st.dst, st.dstLive
	}
	return nil
}

// sortedSet is a set's members, sorted.
func sortedSet(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// scanRenames is rename's first pass over a full-history document: per
// step, the references that may need rewriting (stepRefs); a schema's
// $id, if it has one; the strings that may need rewriting where they
// aren't declared; and the pins that can't be rewritten (pinProblem).
func (im *importer) scanRenames(d *bdoc, load schema.Loader) (steps []*stepRefs, id string, und []UndeclaredRef, problems []string, err error) {
	steps = make([]*stepRefs, len(d.lines))
	seen := map[string]bool{} // undeclared pointer and value, and pins with problems
	var doc any
	live := false
	for i, l := range d.lines {
		if l.Kind != "rev" {
			live = false
			continue
		}
		ps, err := jsonv.Expand(l.Patches)
		if err != nil {
			return nil, "", nil, nil, err
		}
		ops, _ := ps.([]any)
		exists := live || (doc != nil && l.Parent != "")
		after, err := applyPatchSet(doc, exists, ps)
		if err != nil {
			return nil, "", nil, nil, fmt.Errorf("import: %s: replaying %s: %w", d.key, l.ID, err)
		}
		decl, sid, err := declaredRefs(after, load)
		if err != nil {
			return nil, "", nil, nil, fmt.Errorf("import: %s: x-ref walk at %s: %w", d.key, l.ID, err)
		}
		if sid != "" && id == "" {
			id = sid
		}
		sr := &stepRefs{declared: map[string]string{}}
		for p, s := range decl {
			if !im.mayRename(s) {
				continue
			}
			sr.declared[p] = s
			r, _ := annot.ParseRefString(s)
			if r.Rev == "" || seen["pin "+s] {
				continue
			}
			_, renamed := im.renames[r.NS]
			if why := im.pinProblem(r, renamed); why != "" {
				seen["pin "+s] = true
				problems = append(problems, fmt.Sprintf("%s: the reference %s at %s in revision %s can't be rewritten: %s", d.key, s, p, l.ID, why))
			}
		}
		for j, o := range ops {
			m, _ := o.(map[string]any)
			if m["op"] != "add" && m["op"] != "replace" {
				continue
			}
			walkStrings(m["value"], func(at *strPath, s string) {
				if im.mayRename(s) {
					sr.leaves = append(sr.leaves, leaf{op: j, at: at.String(), s: s})
				}
			})
		}
		if len(sr.leaves) > 0 {
			if err := land(doc, exists, ops, sr); err != nil {
				return nil, "", nil, nil, fmt.Errorf("import: %s: replaying %s: %w", d.key, l.ID, err)
			}
			for _, lf := range sr.leaves {
				if lf.declared || lf.to == "" || seen[lf.to+" "+lf.s] {
					continue
				}
				seen[lf.to+" "+lf.s] = true
				und = append(und, UndeclaredRef{Doc: d.key, Pointer: lf.to, Value: lf.s, Renamed: true, Rev: l.ID})
			}
		}
		if len(sr.declared) > 0 || len(sr.leaves) > 0 {
			steps[i] = sr
		}
		doc, live = after, true
	}
	return steps, id, und, problems, nil
}

// declaredRefs are the strings of the reference form at the declared
// positions of a document (§G.4.4 Renaming), by pointer: a schema's
// $ref (schema.RefLocations), or a document's $schema and the x-ref
// positions of its schema (§6.5), as the source's schemas declare them.
// id is a schema's $id, "" if it has none.
func declaredRefs(doc any, load schema.Loader) (refs map[string]string, id string, err error) {
	m, ok := doc.(map[string]any)
	if !ok {
		return nil, "", nil
	}
	s, ok := m["$schema"].(string)
	if !ok {
		return nil, "", nil
	}
	refs = map[string]string{}
	if schema.IsDialect(s) {
		for _, r := range schema.RefLocations(doc) {
			refs[r.Pointer.String()] = r.Raw
		}
		id, _ = m["$id"].(string)
		return refs, id, nil
	}
	refs["/$schema"] = s
	found, err := annot.FindRefs(doc, load)
	if err != nil {
		return nil, "", err
	}
	for _, r := range found {
		refs[r.Pointer] = r.Raw
	}
	return refs, "", nil
}

// marker stands for leaf i while land looks for where it lands.
func marker(i int) string { return "\x00patchlog-rename\x00" + strconv.Itoa(i) }

// land finds where the leaves of a step land in its resulting document:
// the step applied to before, test ops left out, with each leaf replaced
// by a marker, which is then looked for. A leaf copied to several places
// lands at a declared one if any is.
func land(before any, exists bool, ops []any, sr *stepRefs) error {
	c, _ := jsonv.Clone(ops).([]any)
	for i, lf := range sr.leaves {
		m := c[lf.op].(map[string]any)
		v, err := setAt(m["value"], lf.at, marker(i))
		if err != nil {
			return err
		}
		m["value"] = v
	}
	marked := make([]any, 0, len(c))
	for _, o := range c {
		if m, _ := o.(map[string]any); m["op"] != "test" {
			marked = append(marked, o)
		}
	}
	after, err := applyPatchSet(before, exists, marked)
	if err != nil {
		return err
	}
	const prefix = "\x00patchlog-rename\x00"
	walkStrings(after, func(at *strPath, s string) {
		if !strings.HasPrefix(s, prefix) {
			return
		}
		i, err := strconv.Atoi(s[len(prefix):])
		if err != nil || i >= len(sr.leaves) {
			return
		}
		lf := &sr.leaves[i]
		p := at.String()
		_, declared := sr.declared[p]
		if lf.to == "" || (declared && !lf.declared) {
			lf.to, lf.declared = p, declared
		}
	})
	return nil
}

// applyPatchSet applies a patch set to doc (exists: doc is live, or a
// restore's last live one), without changing doc.
func applyPatchSet(doc any, exists bool, patches any) (any, error) {
	ops, err := patch.Parse(patches)
	if err != nil {
		return nil, err
	}
	out, _, err := patch.Apply(doc, exists, ops, patch.Options{})
	return out, err
}

// renameState is where rename's second pass is in a document: the next
// line, and the source's document and the rewritten one before it.
type renameState struct {
	d                *bdoc
	steps            []*stepRefs
	src, dst         any
	srcLive, dstLive bool
	pos              int
}

// renameStep rewrites the next line of a document, unless a revision it
// pins has no new id yet (wait). The strings its ops write at declared
// positions are rewritten (renamedRef), test ops compare with the
// rewritten document, and a reference already in the document whose
// position its schema now declares is rewritten by a replace op added to
// the step. In a sealed target, or one that requires nonces, the step
// gets a fresh $nonce, as new content does there (§C.7, §E.2.5). Gestures
// stay: their ids aren't revision ids (§7.2).
func (im *importer) renameStep(st *renameState) (wait bool, err error) {
	d, rw, i := st.d, st.d.rw, st.pos
	l, sr := d.lines[i], st.steps[i]
	to := map[string]string{}
	if sr != nil {
		for _, s := range sr.strings() {
			t, w, problem := im.renamedRef(s)
			if problem != "" {
				return false, fmt.Errorf("%s in revision %s: %s", s, l.ID, problem)
			}
			if w {
				return true, nil
			}
			to[s] = t
		}
	}
	parent := ""
	if i > 0 {
		parent = rw.ids[i-1]
	}
	var step client.Step
	var refs []RewrittenRef
	if l.Kind != "rev" {
		step = client.DeleteStep()
		st.srcLive, st.dstLive = false, false
	} else {
		ps, err := jsonv.Expand(l.Patches)
		if err != nil {
			return false, err
		}
		srcOps, _ := ps.([]any)
		ops, _ := jsonv.Clone(srcOps).([]any)
		if sr != nil {
			for _, lf := range sr.leaves {
				if !lf.declared || to[lf.s] == lf.s {
					continue
				}
				m := ops[lf.op].(map[string]any)
				if m["value"], err = setAt(m["value"], lf.at, to[lf.s]); err != nil {
					return false, err
				}
				refs = append(refs, RewrittenRef{Pointer: lf.to, From: lf.s, To: to[lf.s], Rev: l.ID})
			}
		}
		srcExists := st.srcLive || (st.src != nil && l.Parent != "")
		dstExists := st.dstLive || (st.dst != nil && parent != "")
		if err := fixTests(st.src, srcExists, st.dst, dstExists, srcOps, ops); err != nil {
			return false, err
		}
		dst, err := applyPatchSet(st.dst, dstExists, ops)
		if err != nil {
			return false, fmt.Errorf("revision %s rewritten: %w", l.ID, err)
		}
		src, err := applyPatchSet(st.src, srcExists, srcOps)
		if err != nil {
			return false, err
		}
		if sr != nil {
			ptrs := make([]string, 0, len(sr.declared))
			for p := range sr.declared {
				ptrs = append(ptrs, p)
			}
			sort.Strings(ptrs)
			for _, p := range ptrs {
				s := sr.declared[p]
				if to[s] == s {
					continue
				}
				// Still the source's string: written where it wasn't
				// declared, by an earlier step, or by a copy or move.
				if v, ok := getAt(dst, p); !ok || v != any(s) {
					continue
				}
				op := map[string]any{"op": "replace", "path": p, "value": to[s]}
				ops = append(ops, op)
				if dst, err = applyPatchSet(dst, true, []any{op}); err != nil {
					return false, err
				}
				refs = append(refs, RewrittenRef{Pointer: p, From: s, To: to[s], Rev: l.ID})
			}
		}
		step = client.PatchStep(ops)
		if im.sealedT[d.tns] {
			step = nonced([]client.Step{step})[0]
			ns := step.Patches.([]any)
			if dst, err = applyPatchSet(dst, true, ns[len(ns)-1:]); err != nil {
				return false, err
			}
		}
		st.src, st.dst, st.srcLive, st.dstLive = src, dst, true, true
	}
	step = step.WithGesture(l.Gesture, l.Undoes)
	id, size := "", 0
	if step.Delete {
		id, err = client.ExpectedTombstone(parent)
	} else {
		var canon []byte
		if canon, err = canonical(step.Patches); err == nil {
			size = len(canon)
			id, err = revisionID(parent, canon)
		}
	}
	if err != nil {
		return false, err
	}
	rw.ids[i], rw.steps[i], rw.sizes[i], rw.idx[id] = id, step, size, i
	rw.done, st.pos = i+1, i+1
	d.rep.Rewritten = append(d.rep.Rewritten, refs...)
	return false, nil
}

// getAt is the value at a JSON Pointer in doc.
func getAt(doc any, ptr string) (any, bool) {
	p, err := pointer.Parse(ptr)
	if err != nil {
		return nil, false
	}
	return pointer.Get(doc, p)
}

// fixTests makes the test ops of a rewritten patch set (ops, the source's
// srcOps) compare with the rewritten document: a test that holds in the
// source tests for what the rewritten document holds there, applying the
// ops one at a time to both.
func fixTests(src any, srcExists bool, dst any, dstExists bool, srcOps, ops []any) error {
	has := false
	for _, o := range ops {
		if m, _ := o.(map[string]any); m["op"] == "test" {
			has = true
			break
		}
	}
	if !has {
		return nil
	}
	s, d := jsonv.Clone(src), jsonv.Clone(dst)
	for j, o := range ops {
		m := o.(map[string]any)
		if m["op"] == "test" {
			path, _ := m["path"].(string)
			sv, ok1 := getAt(s, path)
			dv, ok2 := getAt(d, path)
			if sm, _ := srcOps[j].(map[string]any); ok1 && ok2 && jsonv.Equal(sv, sm["value"]) {
				m["value"] = jsonv.Clone(dv)
			}
			continue
		}
		var err error
		if s, err = applyOne(s, srcExists, srcOps[j]); err != nil {
			return err
		}
		if d, err = applyOne(d, dstExists, o); err != nil {
			return err
		}
		srcExists, dstExists = true, true
	}
	return nil
}

// applyOne applies one op to doc, which it may change.
func applyOne(doc any, exists bool, op any) (any, error) {
	ops, err := patch.Parse([]any{op})
	if err != nil {
		return nil, err
	}
	out, _, err := patch.Apply(doc, exists, ops, patch.Options{InPlace: true})
	return out, err
}

// resume takes the start of a rewritten document from the target, where an
// earlier run of the same renamed import wrote it: in a sealed target, or
// one that requires nonces, rewritten steps carry fresh nonces, so their
// ids differ from one run to the next. The target's head must be the
// revision that the latest import batch from the bundle's namespace
// recorded for a source id of the bundle (source.ids, mergePoints), and
// its chain from genesis that long: those revisions stand for the
// bundle's lines up to that source id, the documents that pin them take
// their ids, and the next steps go on from them.
func (im *importer) resume(ctx context.Context, st *renameState) error {
	d := st.d
	th, err := im.head(ctx, d.tns, d.name)
	if err != nil {
		return err
	}
	if th.State != client.Live && th.State != client.Tombstoned {
		return nil
	}
	pts, err := im.mergePoints(ctx, d.tns)
	if err != nil {
		return err
	}
	pt, ok := pts[d.key]
	if !ok || pt.baseT != th.ID {
		return nil
	}
	k, in := d.idx[pt.baseU]
	if !in {
		return nil
	}
	es, err := im.c.Log(ctx, d.tns, d.name, th.ID, "")
	if client.IsPruned(err) || client.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if len(es) != k+1 || es[0].Parent != "" {
		return nil
	}
	dst, dstLive, err := verify.Replay(nil, false, es)
	if err != nil {
		return nil // pruned: classified against the target as it is
	}
	src, srcLive, err := verify.Replay(nil, false, lineEntries(d.lines[:k+1]))
	if err != nil {
		return err
	}
	rw := d.rw
	for i, s := range stepsOfLog(es) {
		rw.ids[i], rw.steps[i], rw.idx[es[i].ID] = es[i].ID, s, i
		if !s.Delete {
			if canon, err := canonical(s.Patches); err == nil {
				rw.sizes[i] = len(canon)
			}
		}
	}
	rw.done, st.pos = k+1, k+1
	st.src, st.srcLive, st.dst, st.dstLive = src, srcLive, dst, dstLive
	return nil
}

// lineEntries are history lines as log entries.
func lineEntries(ls []*Line) []client.LogEntry {
	out := make([]client.LogEntry, len(ls))
	for i, l := range ls {
		out[i] = l.LogEntry()
	}
	return out
}
