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

// targetAccess is the protection of an existing namespace document, with
// its encryption.level as served ("sealed" when the document is a JWE).
func targetAccess(level string, doc map[string]any) string {
	switch {
	case level == "e2e":
		return AccessE2E
	case level == "sealed":
		return AccessSealed
	case doc["read"] == "public":
		return AccessPublic
	}
	return AccessPrivate
}

// docAccess is the protection a namespace document would give.
func docAccess(doc any) string {
	m, _ := doc.(map[string]any)
	enc, _ := m["encryption"].(map[string]any)
	lv, _ := enc["level"].(string)
	return targetAccess(lv, m)
}

// e2eEpochs lists the epochs the lines of an e2e namespace are sealed
// under: the kids of sealed patch sets, and the keyring's current epochs.
func (im *importer) e2eEpochs(ns string) (lo, hi int, err error) {
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
		if d.name == keyringName {
			var doc any
			live := false
			for _, l := range d.lines {
				if doc, live, err = verify.Replay(doc, live, []client.LogEntry{l.LogEntry()}); err != nil {
					return 0, 0, fmt.Errorf("%s: %w", k, err)
				}
				if kr, err := seal.ParseKeyring(doc); live && err == nil {
					note(kr.Current)
				}
			}
			continue
		}
		for _, l := range d.lines {
			jwe, ok := seal.SealedJWE(l.Patches)
			if !ok {
				continue // a tombstone, or a [] restore
			}
			h, err := seal.ParseHeader(jwe)
			if err != nil {
				return 0, 0, fmt.Errorf("%s: %s: %w", k, l.ID, err)
			}
			kns, e, err := seal.ParseKid(h.Kid)
			if err != nil {
				return 0, 0, fmt.Errorf("%s: %s: %w", k, l.ID, err)
			}
			if kns != ns {
				return 0, 0, fmt.Errorf("%s: %s is sealed under %s, not a key of %s", k, l.ID, h.Kid, ns)
			}
			note(e)
		}
	}
	if lo == 0 {
		lo, hi = 1, 1
	}
	return lo, hi, nil
}

// existing reads a target namespace's protection and whether it requires
// nonces (§C.7), or reports it missing.
func (im *importer) existing(ctx context.Context, ns string) (access string, epoch int, nonce, ok bool, err error) {
	lv, err := im.c.EncryptionLevel(ctx, ns)
	if client.IsNotFound(err) || client.IsGone(err) {
		return "", 0, false, false, nil
	}
	if err != nil {
		return "", 0, false, false, err
	}
	if lv == "sealed" {
		// Its document needs keys; its level is enough, and generated
		// patch sets get a fresh $nonce there anyway.
		return AccessSealed, 0, false, true, nil
	}
	doc, ok, err := im.namespaceDoc(ctx, ns)
	if err != nil || !ok {
		return "", 0, false, ok, err
	}
	if enc, _ := doc["encryption"].(map[string]any); enc != nil {
		epoch = 1
		if f, ok := enc["epoch"].(float64); ok {
			epoch = int(f)
		}
	}
	return targetAccess(lv, doc), epoch, docNonce(doc), true, nil
}

// checkAccess checks every target against its source's access level
// (§G.5.1) and decides how missing targets are created.
func (im *importer) checkAccess(ctx context.Context) error {
	im.create, im.sealedT, im.bump = map[string]any{}, map[string]bool{}, map[string]int{}
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
	nonces := map[string]bool{} // targets that require nonces (nonce.go)
	for _, tns := range names {
		tg := targets[tns]
		src := im.h.AccessOf(tg.src)
		have, epoch, nonce, ok, err := im.existing(ctx, tns)
		if err != nil {
			return fmt.Errorf("import: target namespace %s: %w", tns, err)
		}
		if src == AccessE2E {
			// Ciphertext, verbatim (§G.5.1): only an e2e target of the
			// same name can take it. No override: it can't work otherwise.
			lo, hi, err := im.e2eEpochs(tg.src)
			switch {
			case err != nil:
				problems = append(problems, fmt.Sprintf("e2e namespace %s: %v", tg.src, err))
			case snapshots[tg.src]:
				problems = append(problems, fmt.Sprintf("e2e namespace %s has snapshot documents, which only a client holding its keys can import (§G.5.1)", tg.src))
			case tns != tg.src:
				problems = append(problems, fmt.Sprintf("e2e namespace %s can only be imported under its own name, not as %s: its sealed patch sets bind pl.ns (§E.3.1); "+
					"importing it under another name is a merge that re-encrypts, by a client holding both sets of keys (§F.8, §G.5.1)", tg.src, tns))
			case ok && have != AccessE2E:
				problems = append(problems, fmt.Sprintf("e2e namespace %s can only go into an e2e target, and %s is %s (§G.5.1)", tg.src, tns, have))
			case ok && hi > epoch:
				problems = append(problems, fmt.Sprintf("e2e namespace %s: the bundle is sealed under epochs up to %d, and the target's encryption.epoch is %d; "+
					"its key holders rotate it first (§E.3.2)", tg.src, hi, epoch))
			case !ok:
				im.create[tns] = map[string]any{"read": "grant", "encryption": map[string]any{"level": "e2e", "epoch": float64(lo)}}
				if hi > lo {
					im.bump[tns] = hi
				}
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
			have, nonce = docAccess(doc), docNonce(doc)
		}
		im.sealedT[tns] = have == AccessSealed
		nonces[tns] = nonce
		switch {
		case have == AccessE2E:
			problems = append(problems, fmt.Sprintf("%s is e2e: importing plaintext into it means sealing each patch set with its keys in a client (§G.5.1), which this importer doesn't do", tns))
		case (src == AccessPrivate || src == AccessSealed) && have == AccessPublic:
			msg := fmt.Sprintf("%s is public, less protected than its source %s (%s): a private or sealed namespace's content goes only into a private or sealed one (§G.5.1)", tns, tg.src, src)
			if !im.opt.AllowLessProtected {
				problems = append(problems, msg+"; override explicitly to import it anyway")
				continue
			}
			im.rep.Notes = append(im.rep.Notes, msg+"; imported anyway, as the operator overrode it")
		}
	}
	// The upstream namespaces of the snapshot documents a partial import
	// holds (partial.go) aren't targets, but their chains are compared as
	// a target's are: without the $nonce a sealed or nonce-requiring one
	// gives each patch set.
	for _, k := range im.heldKeys {
		u := im.upstreamNS(im.docs[k].ns)
		if _, ok := targets[u]; ok {
			continue
		}
		have, _, nonce, ok, err := im.existing(ctx, u)
		if err != nil {
			return fmt.Errorf("import: upstream namespace %s: %w", u, err)
		}
		if ok && (have == AccessSealed || nonce) {
			im.sealedT[u] = true
		}
	}
	np, err := im.requireNonces(ctx, nonces)
	if err != nil {
		return err
	}
	problems = append(problems, np...)
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

// bumpEpochs moves a new e2e target's epoch up one at a time to the
// highest its lines are sealed under (§E.2.1: an epoch only moves by one),
// so every epoch of the bundle is one the target has (§E.3.1).
func (im *importer) bumpEpochs(ctx context.Context, ns, config string) error {
	doc := im.create[ns].(map[string]any)
	lo := int(doc["encryption"].(map[string]any)["epoch"].(float64))
	for e := lo + 1; e <= im.bump[ns]; e++ {
		r, err := im.c.PatchConfig(ctx, ns, config, []any{map[string]any{"op": "replace", "path": "/encryption/epoch", "value": float64(e)}})
		if err != nil {
			return fmt.Errorf("import: moving %s to epoch %d: %w", ns, e, err)
		}
		config = r.Config
	}
	return nil
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
