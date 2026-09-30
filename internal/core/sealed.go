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
// concurrent first reader's INSERT OR IGNORE loses and serves the stored
// value, so every reader sees identical bytes. Namespace log ranges depend
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
// classes of §9: public namespaces, and sealed ones whatever their read
// mode (§E.2.5).
func (t *tx) cachePublic(n *nsRow) bool {
	cfg := t.config(n.configSeq)
	return cfg.Read == "public" || cfg.level == levelSealed
}

// isSealedNS reports whether n serves sealed content.
func (t *tx) isSealedNS(n *nsRow) bool { return t.config(n.configSeq).level == levelSealed }

// --- epoch keys -----------------------------------------------------------

// sealedConfigWritten runs after a namespace document of n was written: a
// sealed document beginning a new epoch gets its epoch key, and with
// -rotate-on-revoke a change that revokes access (a new revocation, a key
// removed or changed) queues a rotation.
func (t *tx) sealedConfigWritten(n *nsRow, old, cfg *Config) {
	if cfg.level != levelSealed {
		return
	}
	if old == nil || old.level != levelSealed || old.Epoch != cfg.Epoch {
		t.createEpochKey(n.id, cfg.Epoch)
		return
	}
	if revokesAccess(old, cfg) {
		t.rotate = append(t.rotate, n.name)
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
	jwe       string // the stored value once known
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
	return j
}

// rangeJob prepares the sealing of n's namespace log range (since, to],
// where to is ns_log seq toSeq with id toID.
func (t *tx) rangeJob(n *nsRow, since string, toSeq int64, toID string, plain func() []byte) *sealJob {
	j := &sealJob{kind: sealRange, key: since + ":" + toID}
	if t.stored(n, j) {
		return j
	}
	e := t.entryEpoch(n, toSeq)
	j.kid, j.k, j.pl, j.plain = seal.Kid(n.name, e), t.epochKey(n.id, e), seal.RangePL(n.name, since, toID), plain()
	return j
}

// finishSeal seals the jobs not stored yet and stores them (INSERT OR
// IGNORE, then re-read, so concurrent first readers agree). Nothing is
// stored for a namespace or resource purged since the read.
func (e *Engine) finishSeal(ctx context.Context, ns int64, jobs []*sealJob) error {
	var todo []*sealJob
	for _, j := range jobs {
		if j == nil || j.jwe != "" {
			continue
		}
		s, err := seal.Seal(j.k, j.kid, j.pl, j.plain)
		if err != nil {
			return err
		}
		j.jwe = s
		todo = append(todo, j)
	}
	if len(todo) == 0 {
		return nil
	}
	return e.update(ctx, func(t *tx) error {
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
			_, err := t.Exec(`INSERT OR IGNORE INTO sealed (ns, kind, key, name, rev_seq, jwe, created) VALUES (?,?,?,?,?,?,?)`,
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

// Keys answers POST /ns/{ns}/keys. It needs a verified grant with read on
// the namespace (with authentication disabled, anyone gets raw epoch keys).
// A grant restricted to resources (rules on /resource, or a key with
// readScope "resource") gets K_r for each requested resource it may read;
// any other gets K_e. Epochs run from the one in force at the root block's
// nbf (without nbf: the first, capped to the last historyEpochs) to the
// current one, and never include an epoch that started at or after the
// grant's effective exp. Keys are HPKE-wrapped to the root block's enc if
// it has one, and raw base64url otherwise.
func (e *Engine) Keys(ctx context.Context, ns string, cred Credentials, kr KeysRequest) ([]map[string]any, error) {
	var out []map[string]any
	err := e.read(ctx, func(t *tx) error {
		n := t.nsByName(ns)
		if n == nil || n.purged {
			return notFound()
		}
		cfg := t.config(n.configSeq)
		var a *actor
		if t.e.opt.AuthDisabled {
			a, _ = t.authenticate(n.name, n, cfg, cred, nil)
		} else {
			if cred.Bearer == "" {
				return apiErr(401, "unauthenticated", "message", "missing grant")
			}
			var aerr *Error
			a, aerr = t.authenticate(n.name, n, cfg, cred, nil)
			if aerr != nil {
				if aerr.Status == 401 || aerr.Status == 413 {
					return aerr
				}
				return notFound()
			}
			if !a.verified.Can["read"] {
				return notFound()
			}
		}
		perResource := !a.unrestrictedRead()
		if !perResource && t.grantRules(a, "read", nil, t.basicEnvelope("read", "", a), false) != nil {
			return notFound()
		}
		if cfg.level != levelSealed {
			return invalid("the namespace is not sealed")
		}
		epochs := t.grantEpochs(n, cfg, a)
		if kr.Epochs != nil {
			want := map[int]bool{}
			for _, x := range kr.Epochs {
				want[x] = true
			}
			var keep []int
			for _, x := range epochs {
				if want[x] {
					keep = append(keep, x)
				}
			}
			epochs = keep
		}
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
				m["resource"] = resource
			}
			out = append(out, m)
			return nil
		}
		var names []string
		if perResource {
			seen := map[string]bool{}
			for _, r := range kr.Resources {
				if !ValidResourceName(r) || seen[r] {
					continue
				}
				seen[r] = true
				if t.grantRules(a, "read", nil, t.basicEnvelope("read", r, a), false) == nil {
					names = append(names, r)
				}
			}
			sort.Strings(names)
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
		return nil
	})
	return out, err
}

func recipientOf(a *actor) *ecdh.PublicKey {
	if a == nil || a.grant == nil {
		return nil
	}
	return a.grant.Blocks[0].Enc
}

// grantEpochs lists the epochs a grant may have keys for, ascending.
func (t *tx) grantEpochs(n *nsRow, cfg *Config, a *actor) []int {
	type ep struct {
		e       int
		created time.Time
	}
	rows, err := t.Query(`SELECT epoch, created FROM epoch_keys WHERE ns = ? AND epoch <= ? ORDER BY epoch`, n.id, cfg.Epoch)
	t.must(err)
	var all []ep
	for rows.Next() {
		var x ep
		var ms int64
		t.must(rows.Scan(&x.e, &ms))
		x.created = time.UnixMilli(ms)
		all = append(all, x)
	}
	rows.Close()
	if len(all) == 0 {
		return nil
	}
	first := all[0].e
	var exp *time.Time
	if a != nil && a.grant != nil {
		root := a.grant.Blocks[0]
		if root.Nbf != nil {
			for _, x := range all {
				if !x.created.After(*root.Nbf) {
					first = x.e
				}
			}
		}
		for _, b := range a.grant.Blocks {
			if b.Exp != nil && (exp == nil || b.Exp.Before(*exp)) {
				exp = b.Exp
			}
		}
	}
	if h := cfg.HistoryEpochs; h > 0 && cfg.Epoch-h+1 > first {
		first = cfg.Epoch - h + 1
	}
	var out []int
	for _, x := range all {
		if x.e < first || (exp != nil && !x.created.Before(*exp)) {
			continue
		}
		out = append(out, x.e)
	}
	return out
}

// --- rotation (§E.2.1, §E.2.4) ----------------------------------------------

// RotateEpoch increments a sealed namespace's encryption.epoch with a config
// write made by the server itself as author (a system principal, like
// retention's): a new epoch key is created and content written from then on
// is sealed under it. It returns the new epoch.
func (e *Engine) RotateEpoch(ctx context.Context, ns, author string) (int, error) {
	var epoch int
	err := e.update(ctx, func(t *tx) error {
		n := t.nsByName(ns)
		if n == nil {
			return notFound()
		}
		if n.purged {
			return gone()
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
		epoch = p.cfg.Epoch
		return nil
	})
	return epoch, err
}

// rotateAfterRevoke rotates each namespace a committed config write revoked
// access in, and its sealed branches (revocations reach them, §C.4).
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
		if _, err := e.RotateEpoch(ctx, ns, RotateAuthor); err != nil {
			log.Printf("rotate-on-revoke %s: %v", ns, err)
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
			if done, err := e.RotateDue(context.Background(), maxAge); err != nil {
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
// was itself written with a nonce.
func checkNonces(s *itemState) *Error {
	for _, st := range s.steps {
		if st.del {
			continue
		}
		if st.action == "restore" && string(st.canon) == "[]" {
			continue
		}
		if !seal.HasFreshNonce(st.raw) {
			return invalid("sealed namespaces need a fresh $nonce in every patch set: add /$nonce with 128 random bits as 26 base32 characters (§C.7, §E.2.5)")
		}
		m, _ := st.doc.(map[string]any)
		if n, _ := m["$nonce"].(string); n == "" || n == st.prevNonce {
			return invalid("the $nonce was used before; sealed namespaces need a fresh one in every patch set (§E.2.5)")
		}
	}
	return nil
}

// registeredRemote reports unexpired remote branch registrations of n
// (§G.3), which a sealed namespace can't have on this server.
func (t *tx) registeredRemote(n *nsRow) bool { return len(t.liveRegistrations(n)) > 0 }

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
