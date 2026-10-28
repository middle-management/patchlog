package core

// Sealed for delivery (Addendum E, level E2).
//
// A sealed namespace keeps encryption at rest (E1) and additionally serves
// everything that carries content as a JWE (package seal): documents, log
// entries, namespace documents, namespace log ranges and event payloads.
//
// Keys (§E.2.1). Each (namespace, epoch) has a 256-bit random epoch key
// K_e, kid "{ns}#{e}", wrapped by the KeyStore and stored in epoch_keys. It
// is created by the config write that begins the epoch: the namespace's
// creation or the write that makes it sealed (epoch 1, or the epoch a new
// namespace or branch names), and every write that increments
// encryption.epoch (by exactly one). The epoch's start is that write's
// created time. A branch has its own epoch keys, whatever epoch number its
// copied document names.
//
// What seals what. Resource content (documents at /rev/{id}, log entries)
// is sealed under the per-resource key K_r = HKDF(K_e, ns, name), so a
// per-resource grant's K_r opens exactly that resource's revisions of that
// epoch; namespace documents and ranges are sealed under K_e. The epoch of
// an entry is the one in force when it was written (rev_epochs for
// revisions and tombstones, the config in force at the entry for namespace
// entries). Content without one — read through from a base, or written
// before the namespace became sealed — is sealed under the serving
// namespace's epoch current when it is first sealed.
//
// Stored once, served forever (§E.2.2). Sealed bytes are produced lazily on
// first read and stored in the sealed table per serving namespace; a
// concurrent first reader's INSERT (ON CONFLICT DO NOTHING) loses and
// serves the stored value, so every reader sees identical bytes. Namespace log ranges depend
// on (since, id) and are stored too; at most maxSealedRanges per namespace
// are kept (oldest dropped, and resealed on demand with fresh bytes). Purges
// delete a resource's sealed rows, a namespace purge also its epoch keys,
// and a prune the rows of what it pruned.

import (
	"context"
	"crypto/ecdh"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/middle-management/patchlog/internal/grant"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/seal"
)

// RotateAuthor is the author of epoch rotations made by the server itself
// (Options.RotateEpochs, Options.RotateOnRevoke).
const RotateAuthor = "system:rotate"

// maxSealedRanges bounds the stored namespace log ranges per namespace.
const maxSealedRanges = 4096

const (
	sealDoc    = "doc"
	sealEntry  = "entry"
	sealConfig = "config"
	sealRange  = "range"
	sealGrant  = "grant"
)

type epochRef struct {
	ns    int64
	epoch int
}

// epochKeyCache keeps unwrapped epoch keys.
type epochKeyCache struct {
	mu sync.Mutex
	m  map[epochRef][]byte
}

func (c *epochKeyCache) get(r epochRef) []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.m[r]
}

func (c *epochKeyCache) put(r epochRef, k []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m == nil || len(c.m) > 4096 {
		c.m = map[epochRef][]byte{}
	}
	c.m[r] = k
}

func (c *epochKeyCache) flush() {
	c.mu.Lock()
	c.m = nil
	c.mu.Unlock()
}

func epochAAD(ns int64, epoch int) []byte {
	return append(append([]byte("patchlog-epoch-v1\x00"), be64(ns)...), be64(int64(epoch))...)
}

// cachePublic reports whether a namespace's responses use the public cache
// classes of §9. Sealed and e2e namespaces are cached by their read mode
// like any other (§E.2.5): a public one publicly, its ciphertext opening
// only to key holders; one with read "grant" privately, with edge
// lifetimes only on a read its verifying edge verified. Edge copies that
// versions before v0.73, which cached every sealed and e2e namespace
// publicly, left of those with read "grant" are purged once on upgrade
// (migration 009_purge_grant_caches, RH-44).
func (t *tx) cachePublic(n *nsRow) bool { return t.config(n.configSeq).cachePublic() }

// cachePublic reports whether a namespace with this document uses the
// public cache classes (see tx.cachePublic).
func (c *Config) cachePublic() bool { return c.Read == "public" }

// isSealedNS reports whether n serves sealed content.
func (t *tx) isSealedNS(n *nsRow) bool { return t.config(n.configSeq).level == levelSealed }

// --- epoch keys -----------------------------------------------------------

// sealedConfigWritten runs after a namespace document of n was written: a
// sealed document beginning a new epoch gets its epoch key, and with
// -rotate-on-revoke a change that revokes access (a new revocation, a key
// removed or changed) queues a rotation.
//
// The rotation is recorded as due (rotations_due) in the same transaction
// as the revocation, for n and the sealed branches it reaches (§C.4), so
// a rotation that fails after the commit, or a crash before it, is retried
// (RetryRotations): a revoked reader mustn't keep the current epoch key
// (§E.2.4). A new epoch, whoever begins it (a rotation, or an operator's
// config write), is the rotation that was due.
func (t *tx) sealedConfigWritten(n *nsRow, old, cfg *Config) {
	t.e2eConfigWritten(n, old, cfg)
	if cfg.level != levelSealed {
		return
	}
	if old == nil || old.level != levelSealed || old.Epoch != cfg.Epoch {
		t.createEpochKey(n.id, cfg.Epoch)
		_, err := t.Exec(`DELETE FROM rotations_due WHERE ns = ?`, n.id)
		t.must(err)
		return
	}
	if revokesAccess(old, cfg) {
		if t.e.opt.RotateOnRevoke {
			t.markRotationDue(n)
		}
		t.rotate = append(t.rotate, n.name)
	}
}

// markRotationDue records that n, and every sealed branch below it, needs
// a rotation after a revocation (sealedConfigWritten).
func (t *tx) markRotationDue(n *nsRow) {
	if t.isSealedNS(n) {
		_, err := t.Exec(`INSERT INTO rotations_due (ns, since) VALUES (?, ?) ON CONFLICT (ns) DO NOTHING`, n.id, t.now.UnixMilli())
		t.must(err)
	}
	for _, b := range t.allBranchesOf(n) {
		t.markRotationDue(b)
	}
}

// revokesAccess reports a config change that adds a revocation, or removes
// or changes a key.
func revokesAccess(old, cfg *Config) bool {
	for r := range cfg.Revoked {
		if !old.Revoked[r] {
			return true
		}
	}
	keyEntries := func(c *Config) map[string]any {
		out := map[string]any{}
		arr, _ := c.Doc["keys"].([]any)
		for _, k := range arr {
			if m, ok := k.(map[string]any); ok {
				if kid, ok := m["kid"].(string); ok {
					out[kid] = m
				}
			}
		}
		return out
	}
	nk := keyEntries(cfg)
	for kid, e := range keyEntries(old) {
		if x, ok := nk[kid]; !ok || !jsonv.Equal(x, e) {
			return true
		}
	}
	return false
}

// createEpochKey creates the epoch key of (ns, epoch) if it doesn't exist.
func (t *tx) createEpochKey(ns int64, epoch int) {
	var exists bool
	t.must(t.QueryRow(`SELECT EXISTS (SELECT 1 FROM epoch_keys WHERE ns = ? AND epoch = ?)`, ns, epoch).Scan(&exists))
	if exists {
		return
	}
	ks := t.e.opt.KeyStore
	if ks == nil {
		panic(errNoKeyStore)
	}
	k := seal.NewKey()
	w, err := ks.Wrap(t.context(), k, epochAAD(ns, epoch))
	if err != nil {
		panic(encUnavailable(fmt.Sprintf("wrapping an epoch key with key store %s: %v", ks.Name(), err)))
	}
	_, err = t.Exec(`INSERT INTO epoch_keys (ns, epoch, wrapped, keystore, created) VALUES (?,?,?,?,?)`, ns, epoch, w, ks.Name(), t.now.UnixMilli())
	t.must(err)
	if t.newEpochKeys == nil {
		t.newEpochKeys = map[epochRef][]byte{}
	}
	t.newEpochKeys[epochRef{ns, epoch}] = k
}

// storeEpochKey stores key as the epoch key of (ns, epoch), which began at
// created, if none is stored: a remote branch's shadow keeps the keys its
// source gave of the epochs before its raise to e2e (fetchPreRaiseKeys).
func (t *tx) storeEpochKey(ns int64, epoch int, key []byte, created time.Time) {
	if t.hasEpochKey(ns, epoch) {
		return
	}
	ks := t.e.opt.KeyStore
	if ks == nil {
		panic(errNoKeyStore)
	}
	w, err := ks.Wrap(t.context(), key, epochAAD(ns, epoch))
	if err != nil {
		panic(encUnavailable(fmt.Sprintf("wrapping an epoch key with key store %s: %v", ks.Name(), err)))
	}
	_, err = t.Exec(`INSERT INTO epoch_keys (ns, epoch, wrapped, keystore, created) VALUES (?,?,?,?,?)`, ns, epoch, w, ks.Name(), created.UnixMilli())
	t.must(err)
}

// epochKey returns the epoch key of (ns, epoch), panicking with a 500 when
// it can't be had.
func (t *tx) epochKey(ns int64, epoch int) []byte {
	r := epochRef{ns, epoch}
	if k, ok := t.newEpochKeys[r]; ok {
		return k
	}
	if k := t.e.ekeys.get(r); k != nil {
		return k
	}
	ks := t.e.opt.KeyStore
	if ks == nil {
		panic(errNoKeyStore)
	}
	var wrapped []byte
	var name string
	err := t.QueryRow(`SELECT wrapped, keystore FROM epoch_keys WHERE ns = ? AND epoch = ?`, ns, epoch).Scan(&wrapped, &name)
	if errors.Is(err, sql.ErrNoRows) {
		panic(encUnavailable(fmt.Sprintf("the key of epoch %d is missing", epoch)))
	}
	t.must(err)
	k, err := ks.Unwrap(t.context(), wrapped, epochAAD(ns, epoch))
	if err != nil {
		panic(unwrapErr(ks, name, err))
	}
	t.e.ekeys.put(r, k)
	return k
}

// deleteEpochKeys destroys a namespace's epoch keys (namespace purge).
func (t *tx) deleteEpochKeys(ns int64) {
	_, err := t.Exec(`DELETE FROM epoch_keys WHERE ns = ?`, ns)
	t.must(err)
	t.flushEpochKeys = true
}

// deleteSealed deletes stored sealed bytes matching where.
func (t *tx) deleteSealed(where string, args ...any) {
	_, err := t.Exec(`DELETE FROM sealed WHERE `+where, args...)
	t.must(err)
}

// deletePrunedSealed deletes the sealed documents and entries of res's
// revisions below the horizon hseq, except kept documents.
func (t *tx) deletePrunedSealed(res, hseq int64, keep map[int64]*revRow) {
	rows, err := t.Query(`SELECT seq FROM revisions WHERE res = ? AND seq < ? AND kind = ?`, res, hseq, kindRev)
	t.must(err)
	var seqs []int64
	for rows.Next() {
		var s int64
		t.must(rows.Scan(&s))
		seqs = append(seqs, s)
	}
	rows.Close()
	for _, s := range seqs {
		if _, kept := keep[s]; kept {
			t.deleteSealed(`rev_seq = ? AND kind = ?`, s, sealEntry)
		} else {
			t.deleteSealed(`rev_seq = ?`, s)
		}
	}
}

// --- epochs of content ------------------------------------------------------

// revEpoch is the epoch that seals a revision or tombstone row as served by
// n: the epoch it was written in, if it is n's own; otherwise n's current.
func (t *tx) revEpoch(n *nsRow, r *revRow) int {
	var ns int64
	t.must(t.QueryRow(`SELECT ns FROM resources WHERE res = ?`, r.res).Scan(&ns))
	if ns == n.id {
		var e int
		if err := t.QueryRow(`SELECT epoch FROM rev_epochs WHERE seq = ?`, r.seq).Scan(&e); err == nil {
			return e
		}
	}
	// Content without an epoch of its own keeps the one its first stored
	// sealing fixed, whichever form that was (§E.2.2, §E.2.5).
	var prefix string
	err := t.QueryRow(`SELECT substr(jwe, 1, 4096) FROM sealed WHERE ns = ? AND rev_seq = ? AND kind IN ('doc', 'entry') ORDER BY created LIMIT 1`, n.id, r.seq).Scan(&prefix)
	if err == nil {
		if e, ok := jweEpoch(prefix); ok {
			return e
		}
	} else if !errors.Is(err, sql.ErrNoRows) {
		t.must(err)
	}
	return t.config(n.configSeq).Epoch
}

// entryEpoch is the epoch that seals n's namespace entry seq: the one in
// force after it, if n was sealed then; otherwise n's current.
func (t *tx) entryEpoch(n *nsRow, seq int64) int {
	var cseq int64
	t.must(t.QueryRow(`SELECT config_seq FROM ns_log WHERE seq = ?`, seq).Scan(&cseq))
	if c := t.config(cseq); c.level == levelSealed {
		return c.Epoch
	}
	return t.config(n.configSeq).Epoch
}

// --- sealing ------------------------------------------------------------------

// sealJob is one sealed value to serve.
type sealJob struct {
	kind, key string
	name      string // resource, for doc and entry
	revSeq    int64
	kid       string
	k         []byte
	pl        seal.PL
	plain     []byte
	pad       bool   // the namespace pads (§E.2.2)
	jwe       string // the stored value once known
	fresh     bool   // jwe was sealed by sealNow and isn't stored yet
}

// sealNow seals a job not stored yet, so the length of what will be
// served is known before finishSeal stores it (a sealed resource log
// page's logPageBytes, ResourceLog).
func (j *sealJob) sealNow() error {
	if j.jwe != "" {
		return nil
	}
	s, err := seal.SealMaybePadded(j.k, j.kid, j.pl, j.plain, j.pad)
	if err != nil {
		return err
	}
	j.jwe, j.fresh = s, true
	return nil
}

// stored looks a job up in the sealed table.
func (t *tx) stored(n *nsRow, j *sealJob) bool {
	err := t.QueryRow(`SELECT jwe FROM sealed WHERE ns = ? AND kind = ? AND key = ?`, n.id, j.kind, j.key).Scan(&j.jwe)
	if errors.Is(err, sql.ErrNoRows) {
		return false
	}
	t.must(err)
	return true
}

// resJob prepares the sealing of a resource document (kind doc) or log
// entry (kind entry) of row, served by n under name. plain is called only
// if the value isn't stored yet.
func (t *tx) resJob(n *nsRow, name string, row *revRow, kind string, plain func() []byte) *sealJob {
	j := &sealJob{kind: kind, key: name + "/" + row.id.String(), name: name, revSeq: row.seq}
	if t.stored(n, j) {
		return j
	}
	plKind := seal.KindDoc
	if kind == sealEntry {
		plKind = seal.KindRev
		if row.kind == kindTombstone {
			plKind = seal.KindTombstone
		}
	}
	e := t.revEpoch(n, row)
	kr, err := seal.ResourceKey(t.epochKey(n.id, e), n.name, name)
	t.must(err)
	j.kid, j.k, j.pl, j.plain = seal.Kid(n.name, e), kr, seal.ResourcePL(n.name, name, row.id.String(), plKind), plain()
	j.pad = t.config(n.configSeq).Pad
	return j
}

// configJob prepares the sealing of n's namespace document at ns_log seq.
func (t *tx) configJob(n *nsRow, seq int64, nsID string, doc []byte) *sealJob {
	j := &sealJob{kind: sealConfig, key: nsID}
	if t.stored(n, j) {
		return j
	}
	e := t.entryEpoch(n, seq)
	j.kid, j.k, j.pl, j.plain = seal.Kid(n.name, e), t.epochKey(n.id, e), seal.NamespaceDocPL(n.name, nsID), doc
	j.pad = t.config(n.configSeq).Pad
	return j
}

// rangeJob prepares the sealing of n's namespace log range (since, to],
// where to is ns_log seq toSeq with id toID: a range, long-poll answer or
// namespace event is sealed under K_e of the current epoch (§E.2.2), not
// that of its last entry. A stored range keeps its bytes; one evicted is
// sealed again under the epoch current then.
func (t *tx) rangeJob(n *nsRow, since string, toSeq int64, toID string, plain func() []byte) *sealJob {
	j := &sealJob{kind: sealRange, key: since + ":" + toID}
	if t.stored(n, j) {
		return j
	}
	e := t.config(n.configSeq).Epoch
	j.kid, j.k, j.pl, j.plain = seal.Kid(n.name, e), t.epochKey(n.id, e), seal.RangePL(n.name, since, toID), plain()
	j.pad = t.config(n.configSeq).Pad
	return j
}

// finishSeal seals the jobs not stored yet and stores them (INSERT ON
// CONFLICT DO NOTHING, then re-read, so concurrent first readers agree). Nothing is
// stored for a namespace or resource purged since the read. In a namespace
// with encryption.pad, each JWE is padded as a whole and never compressed
// (§E.2.2); the setting as of sealing counts, and stored bytes never change.
func (e *Engine) finishSeal(ctx context.Context, ns int64, jobs []*sealJob) error {
	var todo []*sealJob
	for _, j := range jobs {
		if j == nil || j.jwe != "" && !j.fresh {
			continue
		}
		if err := j.sealNow(); err != nil {
			return err
		}
		todo = append(todo, j)
	}
	if len(todo) == 0 {
		return nil
	}
	return e.update(ctx, func(t *tx) error {
		// Shared: purges, which delete sealed rows, lock exclusively.
		t.lockNS(ns, lockShared)
		var purged bool
		if err := t.QueryRow(`SELECT purged FROM namespaces WHERE ns = ?`, ns).Scan(&purged); err != nil || purged {
			return nil
		}
		ranges := false
		for _, j := range todo {
			if j.name != "" {
				var st int
				if err := t.QueryRow(`SELECT state FROM resources WHERE ns = ? AND name = ?`, ns, j.name).Scan(&st); err == nil && st == statePurged {
					continue
				}
			}
			var rev any
			if j.revSeq != 0 {
				rev = j.revSeq
			}
			var name any
			if j.name != "" {
				name = j.name
			}
			_, err := t.Exec(`INSERT INTO sealed (ns, kind, key, name, rev_seq, jwe, created) VALUES (?,?,?,?,?,?,?) ON CONFLICT DO NOTHING`,
				ns, j.kind, j.key, name, rev, j.jwe, t.now.UnixMilli())
			t.must(err)
			t.must(t.QueryRow(`SELECT jwe FROM sealed WHERE ns = ? AND kind = ? AND key = ?`, ns, j.kind, j.key).Scan(&j.jwe))
			ranges = ranges || j.kind == sealRange
		}
		if ranges {
			var cnt int
			t.must(t.QueryRow(`SELECT COUNT(*) FROM sealed WHERE ns = ? AND kind = ?`, ns, sealRange).Scan(&cnt))
			if cnt > maxSealedRanges {
				_, err := t.Exec(`DELETE FROM sealed WHERE ns = ? AND kind = ? AND key IN (SELECT key FROM sealed WHERE ns = ? AND kind = ? ORDER BY created, key LIMIT ?)`,
					ns, sealRange, ns, sealRange, cnt-maxSealedRanges*3/4)
				t.must(err)
			}
		}
		return nil
	})
}

// --- POST /ns/{ns}/keys (§E.2.3) --------------------------------------------

// KeysRequest is the body of POST /ns/{ns}/keys. Nil Epochs means every
// epoch the grant may have. Resources name the resources a per-resource
// grant wants keys for; other grants get epoch keys and Resources is
// ignored.
type KeysRequest struct {
	Epochs    []int
	Resources []string
}

// KeysAnswer is what POST /ns/{ns}/keys answers (§E.2.3): the keys, and
// the current epoch, the level ("sealed" or "e2e") and pad, which a writer
// limited to some resources needs to seal (§E.3.1) and can't read in the
// namespace document (§C.5).
type KeysAnswer struct {
	Keys  []map[string]any
	Epoch int
	Level string
	Pad   bool
}

// Keys answers POST /ns/{ns}/keys (§E.2.3). It needs a verified grant
// with read on the namespace (with authentication disabled, anyone gets
// the raw key of the current epoch, as a grant without nbf would). At E2 a grant whose rules fix /resource (§2.1) gets
// K_r for the names asked, by default every name it fixes, and is 403 for
// a name it doesn't fix or may not read; any other gets K_e if it reads
// the namespace unrestricted, and is 403 otherwise (keysScope). Epochs are
// those of the §E.2.3 window (grantEpochsOf), narrowed to those asked.
// Keys are HPKE-wrapped to the root block's enc if it has one, and raw
// base64url otherwise. At E3 any grant with read, whatever its rules, gets
// the keyring entries wrapped to its enc (§E.3.2). A namespace that isn't
// sealed is 404 not_offered, once the read check passes: there is nothing
// to seal (§E.2.3). A request answered with keys draws one token from the
// principal's exchangeRate bucket, as /edge-grants does (§6.6).
func (e *Engine) Keys(ctx context.Context, ns string, cred Credentials, kr KeysRequest) (*KeysAnswer, error) {
	var out []map[string]any
	var ans *KeysAnswer
	err := e.read(ctx, func(t *tx) error {
		n := t.nsByName(ns)
		if n == nil {
			return t.absentNS(ns, cred)
		}
		cfg := t.config(n.configSeq)
		// Refused as /principal is, in a public namespace too (§7): 401
		// without a usable grant, 403 for one that doesn't name the
		// namespace or that its key's scope refuses (§C.2 item 1), and 403
		// for one that has no read (§E.2.3).
		a, aerr := t.keysReader(n, cred, func(a *actor) bool {
			return t.e.opt.AuthDisabled || a != nil && a.verified.Can["read"]
		})
		if aerr != nil {
			return aerr
		}
		if cfg.level == levelE2E {
			// The server only relays the keyring entries a key holder
			// wrapped to the grant's enc (§E.3.2), so a grant that reads
			// the namespace gets its own, unrestricted or limited to some
			// resources: such a writer needs them, and the epoch and pad,
			// to seal (§E.2.3, §E.3.1). Per-resource keys don't exist at
			// E3. A grant whose rules refuse every read reads nothing:
			// 403, as any other verified grant /keys refuses (§7).
			if _, refused := t.keysReadScope(a); refused {
				return forbidden("the grant's rules refuse every read in " + ns)
			}
			// 410 once the read check passes, as every URL of a
			// purged namespace (§8.5).
			if n.purged {
				return t.purgedNS(n)
			}
			keys, err := t.keysE2E(n, cfg, a, kr)
			if err != nil {
				return err
			}
			ans = &KeysAnswer{Keys: keys, Epoch: cfg.Epoch, Level: levelNames[cfg.level], Pad: cfg.Pad}
			return nil
		}
		// §E.2.3's test is part of the read check, so it comes before a
		// purged namespace's 410 and not_offered (§8.5).
		names, perResource, serr := t.keysScope(a, kr)
		if serr != nil {
			return serr
		}
		if n.purged {
			return t.purgedNS(n)
		}
		if cfg.level != levelSealed {
			return apiErr(404, "not_offered", "message", "the namespace is not sealed: there are no keys, and nothing to seal (§E.2.3)")
		}
		if err := t.drawExchange(a); err != nil {
			return err
		}
		epochs := selectEpochs(t.grantEpochs(n, cfg, a), kr.Epochs)
		var enc = recipientOf(a)
		emit := func(kid, resource string, key []byte) error {
			if enc != nil {
				w, err := seal.WrapKey(enc, kid, resource, key)
				if err != nil {
					return err
				}
				out = append(out, w.Value())
				return nil
			}
			m := map[string]any{"kid": kid, "key": base64.RawURLEncoding.EncodeToString(key)}
			if resource != "" {
				m["name"] = resource
			}
			out = append(out, m)
			return nil
		}
		out = []map[string]any{}
		for _, ep := range epochs {
			kid := seal.Kid(n.name, ep)
			ke := t.epochKey(n.id, ep)
			if !perResource {
				if err := emit(kid, "", ke); err != nil {
					return err
				}
				continue
			}
			for _, r := range names {
				k, err := seal.ResourceKey(ke, n.name, r)
				if err != nil {
					return err
				}
				if err := emit(kid, r, k); err != nil {
					return err
				}
			}
		}
		ans = &KeysAnswer{Keys: out, Epoch: cfg.Epoch, Level: levelNames[cfg.level], Pad: cfg.Pad}
		return nil
	})
	return ans, err
}

// drawExchange draws the one token a /keys request takes from the
// principal's exchangeRate bucket (§E.2.3, §6.6): 429 naming exchangeRate
// when it is empty.
func (t *tx) drawExchange(a *actor) *Error {
	if a == nil || a.bucketKey == "" {
		return nil
	}
	return t.admit([]draw{{"e\x00" + a.bucketKey, t.e.opt.Maximums.ExchangeRate, 1, "exchangeRate"}})
}

// selectEpochs keeps the epochs of window that asked names, all of them
// if asked is nil (§E.2.3: by default all).
func selectEpochs(window, asked []int) []int {
	if asked == nil {
		return window
	}
	want := map[int]bool{}
	for _, x := range asked {
		want[x] = true
	}
	var keep []int
	for _, x := range window {
		if want[x] {
			keep = append(keep, x)
		}
	}
	return keep
}

// keysScope decides what a grant gets from /keys at E2 (§E.2.3): a grant
// whose rules fix /resource (§2.1, fixedNames) gets K_r for the names
// asked, by default every name its rules fix, each of which they must fix
// and the grant may read (403 otherwise), sorted; any other grant gets K_e
// if it reads the namespace unrestricted (§2.1), and is 403 otherwise, the
// names asked being ignored. With authentication disabled, every request
// gets K_e.
func (t *tx) keysScope(a *actor, kr KeysRequest) (names []string, perResource bool, err *Error) {
	if a == nil || a.verified == nil {
		return nil, false, nil
	}
	fixed, fixes := fixedNames(a)
	if !fixes {
		if !t.readsUnrestricted(a) {
			return nil, false, forbidden("epoch keys need unrestricted read on the namespace (§2.1, §E.2.3)")
		}
		return nil, false, nil
	}
	in := make(map[string]bool, len(fixed))
	for _, n := range fixed {
		in[n] = true
	}
	want := kr.Resources
	if want == nil {
		want = fixed
	}
	seen := map[string]bool{}
	names = []string{}
	for _, r := range want {
		if seen[r] {
			continue
		}
		seen[r] = true
		if !in[r] {
			return nil, false, forbidden(fmt.Sprintf("the grant's rules don't fix /resource to %q, so it gets no key of it (§2.1, §E.2.3)", r))
		}
		if t.grantRules(a, "read", nil, t.basicEnvelope("read", r, a), false) != nil {
			return nil, false, forbidden(fmt.Sprintf("the grant may not read %q, so it gets no key of it (§E.2.3)", r))
		}
		names = append(names, r)
	}
	sort.Strings(names)
	return names, true, nil
}

// readsUnrestricted reports whether a reads the namespace unrestricted
// (§2.1): it may read, neither its key's scope nor its rules refer to
// /resource, and, with roles, a read role without such rules passes its
// rules against a read envelope.
func (t *tx) readsUnrestricted(a *actor) bool {
	roles, ok := a.unrestrictedRoles()
	return ok && t.grantRules(a, "read", roles, t.basicEnvelope("read", "", a), false) == nil
}

// fixedNames returns the names a's rules fix /resource to (§2.1): a rule
// of its blocks or its key's scope, at top level or nested only in alls,
// that tests /resource against one name, or a finite set (fixesResource),
// each such rule narrowing the names to those all of them allow. It
// reports false when none fixes it, the set left is empty, or a literal of
// a fixing rule isn't a valid name (§3.6), even one the intersection
// drops. Rules that refer to /resource otherwise don't fix it, and are
// left to the read check per name.
func fixedNames(a *actor) ([]string, bool) {
	var names []string
	fixed, bad := false, false
	var walk func(rs []any)
	walk = func(rs []any) {
		for _, rv := range rs {
			if m, ok := rv.(map[string]any); ok && len(m) == 1 {
				if all, ok := m["all"].([]any); ok {
					walk(all)
					continue
				}
			}
			if _, ok := grant.ResourceLiterals(rv); !ok {
				continue
			}
			set, ok := fixesResource(rv)
			if !ok {
				bad = true
				continue
			}
			if !fixed {
				names, fixed = set, true
				continue
			}
			in := make(map[string]bool, len(set))
			for _, n := range set {
				in[n] = true
			}
			names = slices.DeleteFunc(names, func(n string) bool { return !in[n] })
		}
	}
	walk(a.verified.KeyRules)
	walk(a.verified.BlockRules)
	if bad || !fixed || len(names) == 0 {
		return nil, false
	}
	return names, true
}

// keysReadScope classifies a grant for /keys at E3 (§C.5, §E.2.3). K_e only
// through rules none of which refers to /resource. Roles are
// alternatives: if the unrestricted ones fail, a read role that refers to
// /resource may still pass per resource (perResource); without one, the
// grant doesn't read the namespace unrestricted (refused).
func (t *tx) keysReadScope(a *actor) (perResource, refused bool) {
	if a == nil || a.verified == nil {
		return false, false
	}
	roles, ok := a.unrestrictedRoles()
	if ok && t.grantRules(a, "read", roles, t.basicEnvelope("read", "", a), false) != nil {
		if _, all := a.verified.Allows("read"); len(roles) == len(all) {
			return false, true
		}
		ok = false
	}
	return !ok, false
}

func recipientOf(a *actor) *ecdh.PublicKey {
	if a == nil || a.grant == nil {
		return nil
	}
	return a.grant.Blocks[0].Enc
}

// grantEpochs lists the epochs a grant may have keys for, ascending.
func (t *tx) grantEpochs(n *nsRow, cfg *Config, a *actor) []int {
	return t.grantEpochsOf(t.epochStarts(`epoch_keys`, n.id, cfg.Epoch), cfg, a)
}

// epochStart is an epoch and when it began.
type epochStart struct {
	e       int
	created time.Time
}

// epochStarts lists the epochs of ns up to max from table (epoch_keys, or
// e2e_epochs for e2e namespaces), ascending.
func (t *tx) epochStarts(table string, ns int64, max int) []epochStart {
	rows, err := t.Query(`SELECT epoch, created FROM `+table+` WHERE ns = ? AND epoch <= ? ORDER BY epoch`, ns, max)
	t.must(err)
	defer rows.Close()
	var all []epochStart
	for rows.Next() {
		var x epochStart
		var ms int64
		t.must(rows.Scan(&x.e, &ms))
		x.created = time.UnixMilli(ms)
		all = append(all, x)
	}
	return all
}

// latestNbf is the latest nbf among a's blocks (§E.2.3), nil if no block
// has one or there is no grant.
func latestNbf(a *actor) *time.Time {
	if a == nil || a.grant == nil {
		return nil
	}
	var nbf *time.Time
	for _, b := range a.grant.Blocks {
		if b.Nbf != nil && (nbf == nil || b.Nbf.After(*nbf)) {
			nbf = b.Nbf
		}
	}
	return nbf
}

// grantEpochsOf applies the §E.2.3 window to all, a namespace's epochs and
// when each began, ascending, up to the current one: from the epoch in
// force at the last namespace entry created at or before the latest nbf
// among the grant's blocks, or the first where there is none (the
// namespace wasn't sealed then); with no nbf in any block, the current
// epoch alone; and with encryption.historyEpochs h, no more than the
// current one and the h before it. An epoch begins with the config write,
// a batch's config change included, that sets it, at that entry's time,
// so the epoch in force at the last entry at or before nbf is the latest
// that began at or before it. Epochs that began after the grant's exp are
// not left out (v0.63). Without a grant (authentication disabled), as
// for a grant without nbf: the current epoch alone (§E.2.3).
func (t *tx) grantEpochsOf(all []epochStart, cfg *Config, a *actor) []int {
	if len(all) == 0 {
		return nil
	}
	first := all[0].e
	if nbf := latestNbf(a); nbf == nil {
		first = cfg.Epoch
	} else {
		for _, x := range all {
			if !x.created.After(*nbf) {
				first = x.e
			}
		}
	}
	if h := cfg.HistoryEpochs; cfg.HistoryCapped && cfg.Epoch-h > first {
		first = cfg.Epoch - h
	}
	var out []int
	for _, x := range all {
		if x.e >= first {
			out = append(out, x.e)
		}
	}
	return out
}

// --- rotation (§E.2.1, §E.2.4) ----------------------------------------------

// RotateEpoch increments a sealed namespace's encryption.epoch with a config
// write made by the server itself as author (a system principal, like
// retention's): a new epoch key is created and content written from then on
// is sealed under it. It returns the new epoch.
func (e *Engine) RotateEpoch(ctx context.Context, ns, author string) (int, error) {
	epoch, _, err := e.rotateEpoch(ctx, ns, author, false)
	return epoch, err
}

// rotateEpoch is RotateEpoch; with ifDue, it rotates only while ns has a
// rotation due (rotations_due), checked under the namespace's lock, so the
// rotation after a revocation and its retry never both rotate. rotated
// reports whether it did.
func (e *Engine) rotateEpoch(ctx context.Context, ns, author string, ifDue bool) (epoch int, rotated bool, err error) {
	err = e.update(ctx, func(t *tx) error {
		n := t.nsForWrite(ns)
		if n == nil {
			return notFound()
		}
		if n.purged {
			return t.purgedNS(n)
		}
		if ifDue {
			var due int
			t.must(t.QueryRow(`SELECT COUNT(*) FROM rotations_due WHERE ns = ?`, n.id).Scan(&due))
			if due == 0 {
				return nil
			}
		}
		cur := t.config(n.configSeq)
		if cur.level != levelSealed {
			return invalid("the namespace is not sealed")
		}
		a := &actor{principal: grant.Principal{ID: author}, star: true, bucketKey: author}
		patches := []any{map[string]any{"op": "add", "path": "/encryption/epoch", "value": float64(cur.Epoch + 1)}}
		cc := &ConfigChange{IfMatch: t.configID(n.configSeq).String(), Patches: patches}
		p, err := t.planConfig(n, cur, a, cc, false)
		if err != nil {
			return err
		}
		aid := t.authorID(author)
		seq := t.insertConfig(n, p, aid)
		t.appendNS(n, map[string]any{"kind": "config", "target": p.id.String()}, nil, &seq, seq, aid)
		// The new epoch clears a rotation that was due
		// (sealedConfigWritten).
		epoch, rotated = p.cfg.Epoch, true
		return nil
	})
	return epoch, rotated, err
}

// rotateAfterRevoke rotates each namespace a committed config write revoked
// access in, and its sealed branches (revocations reach them, §C.4), while
// their rotation is due. The revoking write recorded it as due
// (sealedConfigWritten), so one that fails here is retried until a
// rotation succeeds (RetryRotations), and a revoked reader doesn't keep the
// current epoch key with nothing but a log line (§E.2.4).
func (e *Engine) rotateAfterRevoke(names []string) {
	ctx := context.Background()
	seen := map[string]bool{}
	for len(names) > 0 {
		ns := names[0]
		names = names[1:]
		if seen[ns] {
			continue
		}
		seen[ns] = true
		if _, _, err := e.rotateEpoch(ctx, ns, RotateAuthor, true); err != nil {
			log.Printf("rotate-on-revoke %s: %v (retried until a rotation succeeds)", ns, err)
		}
		_ = e.read(ctx, func(t *tx) error {
			if n := t.nsByName(ns); n != nil {
				for _, b := range t.allBranchesOf(n) {
					if t.isSealedNS(b) {
						names = append(names, b.name)
					}
				}
			}
			return nil
		})
	}
}

// RotationsDue lists the namespaces whose rotation after a revocation is
// due: recorded with the revocation, and no new epoch begun since.
func (e *Engine) RotationsDue(ctx context.Context) ([]string, error) {
	var out []string
	err := e.read(ctx, func(t *tx) error {
		rows, err := t.Query(`SELECT n.name FROM rotations_due d JOIN namespaces n ON n.ns = d.ns ORDER BY n.name`)
		t.must(err)
		defer rows.Close()
		for rows.Next() {
			var name string
			t.must(rows.Scan(&name))
			out = append(out, name)
		}
		return nil
	})
	return out, err
}

// RetryRotations retries the rotations RotationsDue lists and returns the
// namespaces rotated. One whose namespace was purged, or is no longer
// sealed, is dropped: nothing is left to rotate.
func (e *Engine) RetryRotations(ctx context.Context) ([]string, error) {
	due, err := e.RotationsDue(ctx)
	if err != nil {
		return nil, err
	}
	var done []string
	for _, ns := range due {
		if err := e.jobStep(ctx); err != nil {
			return done, err
		}
		var drop bool
		if err := e.read(ctx, func(t *tx) error {
			n := t.nsByName(ns)
			drop = n == nil || n.purged || t.config(n.configSeq).level != levelSealed
			return nil
		}); err != nil {
			return done, err
		}
		if drop {
			if err := e.update(ctx, func(t *tx) error {
				_, err := t.Exec(`DELETE FROM rotations_due WHERE ns IN (SELECT ns FROM namespaces WHERE name = ?)`, ns)
				t.must(err)
				return nil
			}); err != nil {
				return done, err
			}
			continue
		}
		_, rotated, err := e.rotateEpoch(ctx, ns, RotateAuthor, true)
		if err != nil {
			log.Printf("rotate-on-revoke %s: retry: %v", ns, err)
			continue
		}
		if rotated {
			done = append(done, ns)
		}
	}
	return done, nil
}

// rotateRetryLoop retries failed rotations (RetryRotations) every minute
// until Close.
func (e *Engine) rotateRetryLoop() {
	defer e.bg.Done()
	tk := time.NewTicker(time.Minute)
	defer tk.Stop()
	for {
		select {
		case <-e.stop:
			return
		case <-tk.C:
			if !e.leader(context.Background()) {
				continue // another instance retries (pglock.go)
			}
			if done, err := e.RetryRotations(leaderJob(context.Background())); err != nil {
				log.Printf("rotate-on-revoke: retrying: %v", err)
			} else if len(done) > 0 {
				log.Printf("rotate-on-revoke: rotated %v on retry", done)
			}
		}
	}
}

// RotateDue rotates every sealed, unpurged, unfrozen namespace whose current
// epoch started at least maxAge ago, and returns their names.
func (e *Engine) RotateDue(ctx context.Context, maxAge time.Duration) ([]string, error) {
	var due []string
	err := e.read(ctx, func(t *tx) error {
		rows, err := t.Query(`SELECT ` + nsCols + ` FROM namespaces WHERE purged = 0 AND name NOT LIKE '~%' ORDER BY name`)
		t.must(err)
		var all []*nsRow
		for rows.Next() {
			n, err := scanNS(rows)
			t.must(err)
			all = append(all, n)
		}
		rows.Close()
		cutoff := t.now.Add(-maxAge).UnixMilli()
		for _, n := range all {
			cfg := t.config(n.configSeq)
			if cfg.level != levelSealed || cfg.Frozen {
				continue
			}
			var created int64
			if err := t.QueryRow(`SELECT created FROM epoch_keys WHERE ns = ? AND epoch = ?`, n.id, cfg.Epoch).Scan(&created); err == nil && created <= cutoff {
				due = append(due, n.name)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	var done []string
	for _, ns := range due {
		if err := e.jobStep(ctx); err != nil {
			return done, err
		}
		if _, err := e.RotateEpoch(ctx, ns, RotateAuthor); err != nil {
			log.Printf("rotate-epochs %s: %v", ns, err)
			continue
		}
		done = append(done, ns)
	}
	return done, nil
}

// rotateLoop rotates due epochs until Close.
func (e *Engine) rotateLoop(maxAge time.Duration) {
	defer e.bg.Done()
	every := time.Minute
	if maxAge < every {
		every = maxAge
	}
	tk := time.NewTicker(every)
	defer tk.Stop()
	for {
		select {
		case <-e.stop:
			return
		case <-tk.C:
			if !e.leader(context.Background()) {
				continue // another instance rotates (pglock.go)
			}
			if done, err := e.RotateDue(leaderJob(context.Background()), maxAge); err != nil {
				log.Printf("rotate-epochs: %v", err)
			} else if len(done) > 0 {
				log.Printf("rotate-epochs: rotated %v", done)
			}
		}
	}
}

// checkNonces enforces §E.2.5 on an item of a sealed namespace: every
// patch set must set a fresh $nonce (seal.HasFreshNonce: the last op on
// /$nonce adds or replaces it with 128 random bits in base32), different
// from the nonce of the document it applies to. A restore with an empty
// patch set is exempt: its id is the hash of the tombstone id and "[]", both
// public, so it reveals nothing about the document it brings back, which
// was itself written with a nonce. It runs at gate step 3 once the patch
// set has applied, as checkRequiredNonces does, and answers 422 nonce as
// it does, so a missing nonce gets one code either way (§C.7).
func checkNonces(s *itemState) *Error {
	for _, st := range s.steps {
		if st.del {
			continue
		}
		if st.action == "restore" && string(st.canon) == "[]" {
			continue
		}
		if !seal.HasFreshNonce(st.raw) {
			return apiErr(422, "nonce", "message", "sealed namespaces need a fresh $nonce in every patch set: add /$nonce with 128 random bits as 26 base32 characters (§C.7, §E.2.5)")
		}
		m, _ := st.doc.(map[string]any)
		if n, _ := m["$nonce"].(string); n == "" || n == st.prevNonce {
			return apiErr(422, "nonce", "message", "the $nonce was used before; sealed namespaces need a fresh one in every patch set (§E.2.5)")
		}
	}
	return nil
}

// checkEpochKeys runs at Open when no data key exists: one stored epoch key
// must unwrap with the configured key store (Addendum E.2).
func (e *Engine) checkEpochKeys(ctx context.Context) error {
	var ns int64
	var epoch int
	var wrapped []byte
	var name string
	err := e.db.QueryRowContext(ctx, `SELECT ns, epoch, wrapped, keystore FROM epoch_keys LIMIT 1`).Scan(&ns, &epoch, &wrapped, &name)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	ks := e.opt.KeyStore
	if ks == nil {
		log.Printf("warning: the database holds sealed namespaces (Addendum E.2) but no key store is configured; their content will answer 500")
		return nil
	}
	if _, err := ks.Unwrap(ctx, wrapped, epochAAD(ns, epoch)); err != nil {
		return fmt.Errorf("sealed namespaces: %s", unwrapErr(ks, name, err).Body["message"])
	}
	return nil
}
