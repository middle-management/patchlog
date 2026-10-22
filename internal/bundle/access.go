package bundle

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/seal"
	"github.com/middle-management/patchlog/internal/verify"
)

// This file is the importer's side of §G.5.1: the source can't enforce
// what happens to its content, so the importer does. Every target namespace
// (and upstream namespace) is checked against the access level of the
// source namespace it receives, before anything is planned or written.

// AccessError reports targets less protected than their source, or that
// can't receive it at all (§G.5.1). Nothing was written.
type AccessError struct{ Problems []string }

func (e *AccessError) Error() string {
	return "import: " + strings.Join(e.Problems, "; ")
}

// targetAccess is the protection of a namespace document as a target
// (§2.1), with its encryption.level ("sealed" when served as a JWE): as
// a source's, except that a sealed namespace whose read is public is
// public, since anyone reads what lands there.
func targetAccess(level string, doc map[string]any) string {
	switch {
	case level == "e2e":
		return AccessE2E
	case doc["read"] == "public":
		return AccessPublic
	case level == "sealed":
		return AccessSealed
	}
	return AccessPrivate
}

// docLevel is a namespace document's encryption.level, "" for none.
func docLevel(doc any) string {
	m, _ := doc.(map[string]any)
	enc, _ := m["encryption"].(map[string]any)
	lv, _ := enc["level"].(string)
	return lv
}

// docAccess is the protection a namespace document would give as a
// target.
func docAccess(doc any) string {
	m, _ := doc.(map[string]any)
	return targetAccess(docLevel(doc), m)
}

// e2eEpochs lists the epochs the lines of an e2e namespace are sealed
// under: the kids of sealed patch sets, and the newest epoch of the
// namespace each keyring line holds a key of (keyringEpoch).
// err is a failure to read the target, which a requires decides for
// (e2eRestoresRequires).
// Each document keeps its lines' epochs (bdoc.epochs) for the batches
// (splitEpochs): a sealed line's kid's, a keyring line's newest epoch
// after it, 0 for a tombstone or a restore.
// It checks those lines as §G.5.1 has the importer do at step 1: every
// rev line but the keyring's is one sealed op whose pl.ns and kid name the
// namespace, or a restore's [], one whose parent is a tombstone (§6.2).
// Anything else (plaintext history from before the source became
// end-to-end, a [] appended to a live revision or created with, or a line
// a branch reads through from a base, sealed under the base's name) is a
// problem: such history is carried over as a merge by a client that holds
// both sets of keys, with new ids. Tombstones carry no patches.
func (im *importer) e2eEpochs(ctx context.Context, ns string) (lo, hi int, problems []string, err error) {
	note := func(e int) {
		if lo == 0 || e < lo {
			lo = e
		}
		if e > hi {
			hi = e
		}
	}
	for _, k := range im.keys {
		d := im.docs[k]
		if d.ns != ns {
			continue
		}
		d.epochs = make([]int, len(d.lines))
		if d.name == keyringName {
			var doc any
			live := false
			for i, l := range d.lines {
				var rerr error
				if doc, live, rerr = verify.Replay(doc, live, []client.LogEntry{l.LogEntry()}); rerr != nil {
					problems = append(problems, fmt.Sprintf("e2e namespace %s: %s: %v", ns, k, rerr))
					break
				}
				if e := keyringEpoch(doc, ns); live && e > 0 {
					note(e)
					d.epochs[i] = e
				}
			}
			continue
		}
		for i, l := range d.lines {
			if l.Kind != "rev" {
				continue
			}
			if ps, isArr := l.Patches.([]any); isArr && len(ps) == 0 {
				// A restore's [] only: its parent, the line before it, is a
				// tombstone. An incremental document's first line follows
				// requires, the target's (e2eRestoresRequires).
				restore := i > 0 && d.lines[i-1].Kind == "tombstone"
				if i == 0 && l.Parent != "" {
					if restore, err = im.e2eRestoresRequires(ctx, d); err != nil {
						return 0, 0, nil, err
					}
				}
				if !restore {
					problems = append(problems, fmt.Sprintf("e2e namespace %s: revision %s of %s is [] after a revision that isn't a tombstone, so it isn't one sealed op or a restore's [], as history from before the source became end-to-end may be: "+
						"only a client holding both sets of keys carries it over, as a merge with new ids (§6.2, §G.5.1, Addendum E Levels)", ns, l.ID, d.name))
				}
				continue
			}
			jwe, ok := seal.SealedJWE(l.Patches)
			if !ok {
				problems = append(problems, fmt.Sprintf("e2e namespace %s: revision %s of %s isn't one sealed op or a restore's [], as history from before the source became end-to-end isn't: "+
					"only a client holding both sets of keys carries it over, as a merge with new ids (§G.5.1, Addendum E Levels)", ns, l.ID, d.name))
				continue
			}
			h, err := seal.ParseHeader(jwe)
			if err != nil {
				problems = append(problems, fmt.Sprintf("e2e namespace %s: revision %s of %s: %v", ns, l.ID, d.name, err))
				continue
			}
			kns, e, kerr := seal.ParseKid(h.Kid)
			plNS, _ := h.PL["ns"].(string)
			if kerr != nil || kns != ns || plNS != ns {
				problems = append(problems, fmt.Sprintf("e2e namespace %s: revision %s of %s is sealed under kid %q with pl.ns %q, not for %s, as a line a branch reads through from its base is: "+
					"only a client holding both sets of keys carries it over, as a merge with new ids (§G.5.1)", ns, l.ID, d.name, h.Kid, plNS, ns))
				continue
			}
			note(e)
			d.epochs[i] = e
		}
	}
	if lo == 0 {
		lo, hi = 1, 1
	}
	return lo, hi, problems, nil
}

// keyringEpoch is the newest epoch of namespace ns a keyring document
// holds a key of, read from its entries' kids (§E.3.2), 0 for none. A
// keyring in the format before v0.63 (seal.Keyring) names it as current.
func keyringEpoch(doc any, ns string) int {
	if kr, err := seal.ParseKeyringV2(doc); err == nil {
		return kr.Current(ns)
	}
	if kr, err := seal.ParseKeyring(doc); err == nil && kr.NS == ns {
		return kr.Current
	}
	return 0
}

// e2eRestoresRequires reports whether an incremental document's first
// line, a [] whose parent is requires, may stand as a restore. The import
// writes that line only where the target's head is requires, and then
// requires must be a tombstone there. Where the target's head is another,
// or it has none, the line isn't written: the target holds it already, or
// the requires check or classification (step 2) leaves the document out.
func (im *importer) e2eRestoresRequires(ctx context.Context, d *bdoc) (bool, error) {
	th, err := im.head(ctx, d.tns, d.name)
	if client.IsNotFound(err) || client.IsGone(err) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	return th.ID != d.requires || th.State == client.Tombstoned, nil
}

// e2eKeyringConflict reports an existing e2e target whose keyring has a
// different history from the bundle's, classified by ancestry as step 2
// classifies it (§G.4.4): a kid would then name two keys, so the import is
// refused at step 1 (§G.5.1). A target without the keyring, one that has
// an earlier revision of the bundle's or has gone on from its head isn't.
func (im *importer) e2eKeyringConflict(ctx context.Context, ns string) (string, error) {
	d := im.docs[Key(ns, keyringName)]
	if d == nil || !im.brought(d) {
		return "", nil
	}
	th, err := im.head(ctx, d.tns, keyringName)
	if err != nil {
		return "", err
	}
	if _, in := d.idx[th.ID]; in || th.State == client.NotFound || th.State == client.Purged || (d.requires != "" && th.ID == d.requires) {
		return "", nil
	}
	behind, err := im.inChain(ctx, d.tns, keyringName, th.ID, d.info.Head)
	if err != nil || behind {
		return "", err
	}
	return fmt.Sprintf("e2e namespace %s: the target's keyring has a different history from the bundle's (target head %s), so a kid would name two keys: "+
		"refused before anything is written (§G.5.1); its key holders reconcile the keyrings first", ns, th.ID), nil
}

// e2eLacking is the lowest epoch of a sealed line of e2e namespace ns that
// the target lacks, 0 if it lacks none: the lines after a document's
// target head where the bundle has that head, or all of its lines where
// the target has none or holds its requires. A document whose target is
// purged, ahead or diverged is classified later, and writes none of them.
func (im *importer) e2eLacking(ctx context.Context, ns string) (int, error) {
	low := 0
	for _, k := range im.keys {
		d := im.docs[k]
		if d.ns != ns || d.name == keyringName || d.epochs == nil {
			continue
		}
		th, err := im.head(ctx, d.tns, d.name)
		if err != nil {
			return 0, err
		}
		from := -1
		switch i, in := d.idx[th.ID]; {
		case th.State == client.NotFound:
			from = 0
		case in:
			from = i + 1
		case d.requires != "" && th.ID == d.requires:
			from = 0
		}
		if from < 0 {
			continue
		}
		for _, e := range d.epochs[from:] {
			if e > 0 && (low == 0 || e < low) {
				low = e
			}
		}
	}
	return low, nil
}

// targetInfo is what checkAccess reads of an existing namespace.
type targetInfo struct {
	access string // its protection as a target (§2.1)
	sealed bool   // at E2
	epoch  int    // encryption.epoch, where it has encryption
	nonce  bool   // requires nonces (§C.7)
	// unread is why a sealed namespace's document can't be read (no
	// keys), so neither its read nor its nonce setting is known.
	unread error
}

// existing reads a target namespace's protection and whether it requires
// nonces (§C.7), or reports it missing. A sealed one's document is read
// with the importer's keys, for its read (§2.1).
func (im *importer) existing(ctx context.Context, ns string) (ti targetInfo, ok bool, err error) {
	lv, err := im.c.EncryptionLevel(ctx, ns)
	if client.IsNotFound(err) || client.IsGone(err) {
		return ti, false, nil
	}
	if err != nil {
		return ti, false, err
	}
	doc, ok, err := im.namespaceDoc(ctx, ns)
	if lv == "sealed" && errors.Is(err, client.ErrNoKeys) {
		return targetInfo{access: AccessSealed, sealed: true, unread: err}, true, nil
	}
	if err != nil || !ok {
		return ti, ok, err
	}
	ti = targetInfo{access: targetAccess(lv, doc), sealed: lv == "sealed", nonce: docNonce(doc)}
	if enc, _ := doc["encryption"].(map[string]any); enc != nil {
		ti.epoch = 1
		if f, ok := enc["epoch"].(float64); ok {
			ti.epoch = int(f)
		}
	}
	return ti, true, nil
}

// checkAccess checks every target against its source's access level
// (§G.5.1) and decides how missing targets are created.
func (im *importer) checkAccess(ctx context.Context) error {
	im.create, im.sealedT, im.e2eAt = map[string]any{}, map[string]bool{}, map[string]int{}
	type target struct {
		src      string
		upstream bool
	}
	targets := map[string]target{}
	snapshots := map[string]bool{}
	for _, k := range im.keys {
		d := im.docs[k]
		targets[d.tns] = target{src: d.ns}
		if d.info.History == Snapshot {
			targets[im.upstreamNS(d.ns)] = target{src: d.ns, upstream: true}
			snapshots[d.ns] = true
		}
	}
	names := make([]string, 0, len(targets))
	for t := range targets {
		names = append(names, t)
	}
	sort.Strings(names)
	var problems []string
	// An e2e namespace's blob lines carry the writers' ciphertext: the
	// sealed type and no nonce, since declared lists carry only ids
	// (§E.3.1, §G.5.1). Any other is refused before anything is uploaded.
	for _, k := range im.keys {
		d := im.docs[k]
		if im.h.AccessOf(d.ns) != AccessE2E {
			continue
		}
		bids := make([]string, 0, len(d.blobs))
		for bid := range d.blobs {
			bids = append(bids, bid)
		}
		sort.Strings(bids)
		for _, bid := range bids {
			if l := d.blobs[bid]; normType(l.Type) != SealedBlobType || l.Nonce != "" {
				problems = append(problems, fmt.Sprintf("blob %s of e2e namespace %s (%s) has type %q and nonce %q: an e2e namespace's blob lines have type %s and no nonce (§E.3.1, §G.5.1)",
					bid, d.ns, d.name, l.Type, l.Nonce, SealedBlobType))
			}
		}
	}
	nonces := map[string]bool{}       // targets that require nonces (nonce.go)
	sealedTarget := map[string]bool{} // targets that are, or are created, sealed
	for _, tns := range names {
		tg := targets[tns]
		src := im.h.AccessOf(tg.src)
		ti, ok, err := im.existing(ctx, tns)
		if err == nil {
			err = ti.unread
		}
		if err != nil {
			return fmt.Errorf("import: target namespace %s: %w", tns, err)
		}
		have, epoch, nonce, sealed := ti.access, ti.epoch, ti.nonce, ti.sealed
		if src == AccessE2E {
			// Ciphertext, verbatim (§G.5.1): only an e2e target of the
			// same name can take it. No override: it can't work otherwise.
			lo, _, probs, err := im.e2eEpochs(ctx, tg.src)
			if err != nil {
				return fmt.Errorf("import: target namespace %s: %w", tns, err)
			}
			problems = append(problems, probs...)
			switch {
			case snapshots[tg.src]:
				problems = append(problems, fmt.Sprintf("e2e namespace %s has snapshot documents, which only a client holding its keys can import (§G.5.1)", tg.src))
			case tns != tg.src:
				problems = append(problems, fmt.Sprintf("e2e namespace %s can only be imported under its own name, not as %s: its sealed patch sets bind pl.ns (§E.3.1); "+
					"importing it under another name is a merge that re-encrypts, by a client holding both sets of keys (§F.8, §G.5.1)", tg.src, tns))
			case ok && have != AccessE2E:
				problems = append(problems, fmt.Sprintf("e2e namespace %s can only go into an e2e target, and %s is %s (§G.5.1)", tg.src, tns, have))
			case ok:
				// An existing target is moved up one epoch at a time as
				// the lines arrive, as a created one is (splitEpochs), so
				// its keyring mustn't conflict with the bundle's, and it
				// can't be below the bundle's lowest epoch or past that of
				// a line it lacks: step 3 accepts only the epoch in force
				// (§E.3.1, §G.5.1).
				p, err := im.e2eKeyringConflict(ctx, tg.src)
				if err != nil {
					return fmt.Errorf("import: target namespace %s: %w", tns, err)
				}
				if p != "" {
					problems = append(problems, p)
				}
				lack, err := im.e2eLacking(ctx, tg.src)
				if err != nil {
					return fmt.Errorf("import: target namespace %s: %w", tns, err)
				}
				switch {
				case epoch < lo:
					problems = append(problems, fmt.Sprintf("e2e namespace %s: the target's encryption.epoch is %d, below the bundle's lowest epoch %d (§G.5.1)", tg.src, epoch, lo))
				case lack > 0 && epoch > lack:
					problems = append(problems, fmt.Sprintf("e2e namespace %s: the target's encryption.epoch is %d, past epoch %d of a line it lacks, which it no longer accepts (§E.3.1, §G.5.1)", tg.src, epoch, lack))
				}
				im.e2eAt[tns] = epoch
			default:
				// Created at the bundle's lowest epoch, and moved up as the
				// lines arrive (splitEpochs).
				im.create[tns] = map[string]any{"read": "grant", "encryption": map[string]any{"level": "e2e", "epoch": float64(lo)}}
				im.e2eAt[tns] = lo
			}
			continue
		}
		if !ok {
			doc := im.defaultNSDoc(ctx, &node{ns: tns, srcNS: tg.src, upstream: tg.upstream})
			if im.opt.NamespaceDoc == nil {
				// Created as protected as the source (§G.5.1).
				switch src {
				case AccessPrivate:
					doc = map[string]any{"read": "grant"}
				case AccessSealed:
					doc = map[string]any{"read": "grant", "encryption": map[string]any{"level": "sealed"}}
				}
			}
			im.create[tns] = doc
			have, nonce, sealed = docAccess(doc), docNonce(doc), docLevel(doc) == "sealed"
		}
		im.sealedT[tns] = sealed
		sealedTarget[tns] = sealed
		nonces[tns] = nonce
		// Ranks apply only between namespaces (§2.1): a bundle of this
		// deployment's namespace back into itself isn't ranked.
		self := im.local && tns == tg.src
		switch {
		case have == AccessE2E:
			problems = append(problems, fmt.Sprintf("%s is e2e: importing plaintext into it means sealing each patch set with its keys in a client (§G.5.1), which this importer doesn't do", tns))
		case (src == AccessPrivate || src == AccessSealed) && have == AccessPublic && !self:
			what := "public"
			if sealed {
				what = "sealed with read public, which ranks public as a target (§2.1)"
			}
			msg := fmt.Sprintf("%s is %s, less protected than its source %s (%s): a private or sealed namespace's content goes only into a private or sealed one (§G.5.1)", tns, what, tg.src, src)
			if !im.opt.AllowLessProtected {
				problems = append(problems, msg+"; override explicitly to import it anyway")
				continue
			}
			im.rep.Notes = append(im.rep.Notes, msg+"; imported anyway, as the operator overrode it")
		}
	}
	// Where a snapshot document's target is sealed, the patch sets
	// generated in its upstream namespace carry a fresh $nonce too, whatever
	// the upstream's own level (§G.4.4): the target fast-forwards from them,
	// and its writers add one to every patch set (§E.2.5).
	for _, k := range im.keys {
		if d := im.docs[k]; d.info.History == Snapshot && sealedTarget[d.tns] {
			im.sealedT[im.upstreamNS(d.ns)] = true
		}
	}
	// The upstream namespaces of the snapshot documents a partial import
	// holds (partial.go) aren't targets, but their chains are compared as
	// a target's are: without the $nonce a sealed or nonce-requiring one,
	// or one whose target is sealed, gives each patch set.
	for _, k := range im.heldKeys {
		d := im.docs[k]
		u := im.upstreamNS(d.ns)
		if _, ok := targets[u]; ok {
			continue
		}
		ti, ok, err := im.existing(ctx, u)
		if err != nil {
			return fmt.Errorf("import: upstream namespace %s: %w", u, err)
		}
		if ok && (ti.sealed || ti.nonce) {
			im.sealedT[u] = true
			continue
		}
		if ok {
			if tt, tok, err := im.existing(ctx, d.tns); err != nil {
				return fmt.Errorf("import: target namespace %s: %w", d.tns, err)
			} else if tok && tt.sealed {
				im.sealedT[u] = true
			}
		}
	}
	im.requireNonces(nonces)
	if len(problems) > 0 {
		return &AccessError{Problems: problems}
	}
	return nil
}

// nsDoc is the document a missing namespace is created with.
func (im *importer) nsDoc(ctx context.Context, n *node) any {
	if doc, ok := im.create[n.ns]; ok {
		return doc
	}
	return im.defaultNSDoc(ctx, n)
}

// moveEpoch readies an e2e target for a batch of epoch e above its own,
// once every batch of its node in flight has committed: those are sealed
// under an epoch before, which step 3 accepts only while it is in force
// (§E.3.1, §G.5.1). The batch moves the target to e itself, in its config
// change, with the keyring line that brings e's key (raise); moveEpoch
// moves it up to e-1, one epoch at a time (§E.2.1: an epoch only moves by
// one), with encryption.epoch config writes of their own, only where the
// bundle has no line of the epochs between, as where the source's keyring
// skipped one. It needs config on the target, with a * key (§7.4).
func (im *importer) moveEpoch(ctx context.Context, run *runner, n *node, e int) error {
	if e <= im.e2eAt[n.ns] {
		return nil
	}
	if err := run.waitFor(func(f *flight) bool { return f.n == n }); err != nil {
		return err
	}
	for next := im.e2eAt[n.ns] + 1; next < e; next++ {
		var err error
		im.io(func() {
			var h *client.NSHead
			if h, err = im.c.NSHead(ctx, n.ns); err == nil {
				_, err = im.c.PatchConfig(ctx, n.ns, h.Config, epochOps(next))
			}
		})
		if err != nil {
			return fmt.Errorf("import: moving %s to epoch %d: %w", n.ns, next, err)
		}
		im.e2eAt[n.ns] = next
	}
	return nil
}

// raise is the config change of an e2e target's batch whose epoch is the
// one after the target's (moveEpoch): it moves the target up to it in the
// same atomic write as the batch's lines, the keyring line that brings
// that epoch's key first among them (splitEpochs), so a batch that fails
// moves nothing (§7.5, §E.2.1). A dry run checks the lines against the
// configuration it produces, as the submit does (§7.5). nil for any other
// batch.
func (im *importer) raise(ctx context.Context, b *batch) (*client.BatchConfig, error) {
	at, ok := im.e2eAt[b.n.ns]
	if !ok || b.epoch != at+1 {
		return nil, nil
	}
	var h *client.NSHead
	var err error
	im.io(func() { h, err = im.c.NSHead(ctx, b.n.ns) })
	if err != nil {
		return nil, fmt.Errorf("import: moving %s to epoch %d: %w", b.n.ns, b.epoch, err)
	}
	return &client.BatchConfig{IfMatch: h.Config, Patches: epochOps(b.epoch)}, nil
}

// epochOps set encryption.epoch to e: with add, since a namespace document
// may leave the member out at epoch 1 (§E.2.1).
func epochOps(e int) []any {
	return []any{map[string]any{"op": "add", "path": "/encryption/epoch", "value": float64(e)}}
}

// withoutNonce leaves a document's $nonce out of a comparison. A document
// held as its canonical form (snapDoc) is parsed: its members are read.
func withoutNonce(v any) any {
	if r, ok := v.(jsonv.Raw); ok {
		v = jsonv.MustParse(r)
	}
	m, ok := v.(map[string]any)
	if !ok {
		return v
	}
	if _, has := m["$nonce"]; !has {
		return v
	}
	c := make(map[string]any, len(m))
	for k, x := range m {
		if k != "$nonce" {
			c[k] = x
		}
	}
	return c
}

// nonced adds a fresh $nonce to every patch set the importer generates for
// a sealed namespace (§E.2.5), or one that requires nonces (§C.7), both
// marked in sealedT. Full-history lines are never changed: their ids are
// the source's.
// newNonce is the source of the $nonce values nonced adds; tests that
// compare the requests of two imports make it deterministic
// (export_test.go), since other users of crypto/rand in the process, such
// as a database driver's authentication, would shift a shared source.
var newNonce = seal.NewNonce

func nonced(steps []client.Step) []client.Step {
	out := make([]client.Step, len(steps))
	for i, s := range steps {
		out[i] = s
		if s.Delete {
			continue
		}
		noRawPatchSet(s.Patches)
		ps, _ := s.Patches.([]any)
		out[i].Patches = append(append([]any{}, ps...), map[string]any{"op": "add", "path": seal.NoncePath, "value": newNonce()})
	}
	return out
}

// noKeysHint explains a sealed target the importer has no keys for.
func noKeysHint(ns string, err error) error {
	if errors.Is(err, client.ErrNoKeys) {
		return fmt.Errorf("import: target namespace %s is sealed and the importer has no keys for it: it needs a read grant, and the identity the grant's enc names if the keys are wrapped (§E.2.3): %w", ns, err)
	}
	return err
}
