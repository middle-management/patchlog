package core

// Sealed namespaces on DynamoDB (Addendum E.2). The sealing is core's own
// code on the gate (resJob, configJob, rangeJob, grantJob, finishSeal,
// Keys), over the table's reads: epoch keys (EPOCHKEY# items, written by
// the commit that begins each epoch, wrapped by the key store with an aad
// binding them to their namespace's name and epoch), each revision's
// epoch (REV epoch), the epoch of an entry from the configuration in
// force at it, and the stored sealings (SEALED# items, ddb/sealed.go).
// Rotation, on schedule or on revoke, is a config change made as the
// server.

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/middle-management/patchlog/internal/ddb"
	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/seal"
)

// ddbEpochAAD binds a wrapped epoch key to its namespace and epoch.
func ddbEpochAAD(ns string, epoch int) []byte {
	out := []byte("patchlog-epoch-v1-ddb\x00" + ns + "\x00")
	return binary.BigEndian.AppendUint64(out, uint64(epoch))
}

// epochKeyFor unwraps ns's key of epoch.
func (b *ddbBackend) epochKeyFor(ctx context.Context, ns string, epoch int) ([]byte, error) {
	id := "E\x00" + ns + "\x00" + strconv.Itoa(epoch)
	if k := b.keys.get(id); k != nil {
		return k, nil
	}
	ks := b.e.opt.KeyStore
	if ks == nil {
		return nil, errNoKeyStore
	}
	w, err := b.store.EpochKeyOf(ctx, ns, epoch)
	if err != nil {
		return nil, err
	}
	if w == nil {
		return nil, encUnavailable(fmt.Sprintf("the key of epoch %d is missing", epoch))
	}
	k, err := ks.Unwrap(ctx, w.Wrapped, ddbEpochAAD(ns, epoch))
	if err != nil {
		return nil, unwrapErr(ks, w.KeyStore, err)
	}
	b.keys.put(id, k)
	return k, nil
}

// beginsEpoch is the key of the epoch a namespace document cfg of ns
// begins (sealedConfigWritten of sealed.go), old being the one before
// (nil for a new namespace): nil if it begins none.
func (b *ddbBackend) beginsEpoch(ctx context.Context, ns string, old, cfg *Config) (*ddb.EpochKey, error) {
	if cfg.level != levelSealed || old != nil && old.level == levelSealed && old.Epoch == cfg.Epoch {
		return nil, nil
	}
	ks := b.e.opt.KeyStore
	if ks == nil {
		return nil, errNoKeyStore
	}
	k := seal.NewKey()
	w, err := ks.Wrap(ctx, k, ddbEpochAAD(ns, cfg.Epoch))
	if err != nil {
		return nil, encUnavailable(fmt.Sprintf("wrapping an epoch key with key store %s: %v", ks.Name(), err))
	}
	return &ddb.EpochKey{Epoch: cfg.Epoch, Wrapped: w, KeyStore: ks.Name()}, nil
}

// revokes reports a sealed config change that revokes access, which with
// -rotate-on-revoke rotates the epoch after it commits.
func (b *ddbBackend) revokes(old, cfg *Config) bool {
	return b.e.opt.RotateOnRevoke && old != nil && cfg.level == levelSealed && old.level == levelSealed &&
		old.Epoch == cfg.Epoch && revokesAccess(old, cfg)
}

// --- reads ---

func (r *ddbReads) epochKey(ns int64, epoch int) []byte {
	k, err := r.b.epochKeyFor(r.ctx, r.nsName(ns), epoch)
	r.must(err)
	return k
}

// entryEpoch: the epoch in force after n's entry seq, if n was sealed
// then; otherwise n's current (entryEpoch of sealed.go).
func (r *ddbReads) entryEpoch(n *nsRow, seq int64) int {
	cseq, _ := r.entryConfig(seq)
	if c := r.config(cseq); c.level == levelSealed {
		return c.Epoch
	}
	return r.config(n.configSeq).Epoch
}

func (r *ddbReads) stored(n *nsRow, j *sealJob) bool {
	jwe, _, err := r.s.Sealed(r.ctx, r.nsName(n.id), j.kind, j.key)
	r.must(err)
	j.jwe = jwe
	return jwe != ""
}

// revEpoch is the epoch sealing a revision as n serves it: the one it was
// written in, if n's own; else that of its first stored sealing; else n's
// current (revEpoch of sealed.go).
func (r *ddbReads) revEpoch(n *nsRow, name string, row *revRow) int {
	ns := r.nsName(n.id)
	k := r.revs[row.seq].key
	if k.ns == ns {
		ri, err := r.s.RevAt(r.ctx, k.ns, k.name, k.pos)
		r.must(err)
		if ri != nil && ri.Epoch > 0 {
			return ri.Epoch
		}
	}
	first, firstAt := 0, int64(0)
	for _, kind := range []string{sealDoc, sealEntry} {
		jwe, created, err := r.s.Sealed(r.ctx, ns, kind, name+"/"+row.id.String())
		r.must(err)
		if e, ok := jweEpoch(jwe); ok && jwe != "" && (first == 0 || created < firstAt) {
			first, firstAt = e, created
		}
	}
	if first > 0 {
		return first
	}
	return r.config(n.configSeq).Epoch
}

func (r *ddbReads) resJob(n *nsRow, name string, row *revRow, kind string, plain func() []byte) *sealJob {
	j := &sealJob{kind: kind, key: name + "/" + row.id.String(), name: name, revSeq: row.seq}
	if k := r.revs[row.seq].key; k.ns == r.nsName(n.id) {
		j.revPos = k.pos
	}
	if r.stored(n, j) {
		return j
	}
	plKind := seal.KindDoc
	if kind == sealEntry {
		plKind = seal.KindRev
		if row.kind == kindTombstone {
			plKind = seal.KindTombstone
		}
	}
	e := r.revEpoch(n, name, row)
	kr, err := seal.ResourceKey(r.epochKey(n.id, e), n.name, name)
	r.must(err)
	j.kid, j.k, j.pl, j.plain = seal.Kid(n.name, e), kr, seal.ResourcePL(n.name, name, row.id.String(), plKind), plain()
	j.pad = r.config(n.configSeq).Pad
	return j
}

// grantJob: sealed under the epoch of the first entry of n recording the
// grant (its marker's), else n's current (grantJob of grants.go).
func (r *ddbReads) grantJob(n *nsRow, id ids.ID, plain func() []byte) *sealJob {
	j := &sealJob{kind: sealGrant, key: id.String()}
	if r.stored(n, j) {
		return j
	}
	ns := r.nsName(n.id)
	e := r.config(n.configSeq).Epoch
	pos, err := r.s.GrantFirstPos(r.ctx, ns, id.String())
	r.must(err)
	if pos > 0 {
		e = r.entryEpoch(n, r.logHandle(ns, pos))
	}
	j.kid, j.k, j.pl, j.plain = seal.Kid(n.name, e), r.epochKey(n.id, e), seal.GrantPL(n.name, id.String()), plain()
	j.pad = r.config(n.configSeq).Pad
	return j
}

// epochStarts: n's epoch keys, which record when each epoch began.
func (r *ddbReads) epochStarts(table string, ns int64, max int) []epochStart {
	if table != `epoch_keys` {
		panic(ddbUnsupported("e2e namespaces"))
	}
	ks, err := r.s.EpochKeys(r.ctx, r.nsName(ns))
	r.must(err)
	var out []epochStart
	for _, k := range ks {
		if k.Epoch <= max {
			out = append(out, epochStart{e: k.Epoch, created: time.UnixMilli(k.Created)})
		}
	}
	return out
}

func (r *ddbReads) keysE2E(n *nsRow, cfg *Config, a *actor, kr KeysRequest) ([]map[string]any, error) {
	panic(ddbUnsupported("e2e namespaces"))
}

// --- writes ---

// storeSealed is finishSeal's storing on the table: put-if-absent, then
// the one stored; nothing for a namespace or resource purged since.
func (b *ddbBackend) storeSealed(ctx context.Context, ns string, jobs []*sealJob) error {
	n, err := b.store.Namespace(ctx, ns)
	if err != nil || n == nil || n.Purged {
		return asErrOrNil(err)
	}
	now := b.e.now().UnixMilli()
	for _, j := range jobs {
		if j.name != "" {
			rr, err := b.store.Resource(ctx, ns, j.name)
			if err != nil {
				return ddbAsErr(err)
			}
			if rr != nil && rr.Purged {
				continue
			}
		}
		jwe, err := b.store.PutSealed(ctx, ns, ddb.SealedValue{Kind: j.kind, Key: j.key, Name: j.name, RevPos: j.revPos, JWE: j.jwe}, now)
		if err != nil {
			return ddbAsErr(err)
		}
		j.jwe = jwe
	}
	return nil
}

// rotateEpoch is RotateEpoch on the table: planRotation's config change,
// committed with its epoch's key.
func (b *ddbBackend) rotateEpoch(ctx context.Context, ns, author string) (int, error) {
	for attempt := 0; attempt < ddbAttempts; attempt++ {
		r := newDDBReads(b, ctx)
		g := &gate{checkReads: r, checkState: &checkState{e: b.e, now: b.e.now(), write: true}}
		type planned struct {
			n   *nsRow
			cur *Config
			p   *configPlan
			err error
		}
		out, perr := ddbCheck(func() planned {
			n, _, p, err := g.planRotation(ns, author)
			if err != nil {
				return planned{err: err}
			}
			return planned{n, g.config(n.configSeq), p, nil}
		})
		switch {
		case perr != nil:
			return 0, perr
		case out.err != nil:
			return 0, out.err
		}
		ek, err := b.beginsEpoch(ctx, ns, out.cur, out.p.cfg)
		if err != nil {
			return 0, asErrOrNil(err)
		}
		p := out.p
		c := &ddb.Commit{NS: ns, Author: author, Created: g.now.UnixMilli(),
			CfgPos: r.cfgs[out.n.configSeq].pos, CfgID: r.cfgRow(out.n.configSeq).ID,
			Config: &ddb.CommitConfig{ID: p.id.String(), Patches: string(p.canon), Doc: string(jsonv.Canonical(p.doc)), Frozen: p.cfg.Frozen},
			Entry:  map[string]any{"kind": "config", "target": p.id.String()}, Kind: "config",
			EpochKey: ek, Pins: r.configPins(ns)}
		_, err = b.commit(ctx, c)
		if errors.Is(err, ddb.ErrStale) {
			continue
		}
		if err != nil {
			return 0, ddbAsErr(err)
		}
		return p.cfg.Epoch, nil
	}
	return 0, apiErr(409, "conflict", "detail", "the namespace's configuration kept moving")
}

// checkEpochKeys is checkEpochKeys of sealed.go on the table: one stored
// epoch key must unwrap.
func (b *ddbBackend) checkEpochKeys(ctx context.Context) error {
	ks := b.e.opt.KeyStore
	if ks == nil {
		return nil
	}
	ns, k, err := b.store.AnyEpochKey(ctx)
	if err != nil || k == nil {
		return err
	}
	if _, err := ks.Unwrap(ctx, k.Wrapped, ddbEpochAAD(ns, k.Epoch)); err != nil {
		return fmt.Errorf("sealed namespaces: %s", unwrapErr(ks, k.KeyStore, err).Body["message"])
	}
	return nil
}
