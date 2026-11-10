package core

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"sort"
	"strconv"
	"sync"
)

// The message bound (§E.2.1). IVs are 96 random bits, so no key seals 2³²
// values or more: the origin counts its sealings per key (seal_counts,
// migration 016), K_n of a namespace's epoch under name "" and each K_r
// under its resource's name, reserving what may still be sealed under an
// epoch after it ends (§E.2.2: a revision's document and log entry, and a
// namespace entry's range, are sealed when first read). A request that
// would need a sealing past Options.SealBound is 503 behind with
// Retry-After, and nothing is sealed; a key of the current epoch reaching
// Options.SealRotateAt makes the namespace's rotation due, which the
// leader makes as RotateAuthor (rotations_due, reason "bound"), frozen
// namespaces included (§7.4 exempts *-key config writes). Views count
// toward nothing (§E.2.6), and the server seals nothing at E3.
//
// Every sealing is counted before it is encrypted: in a write transaction
// in it (countIn), otherwise from blocks of Options.SealBlock counts an
// instance takes per key in a short transaction of its own and hands out
// from memory (sealCounter.take), an unused remainder staying counted. On
// SQLite a block is never taken inside a held transaction.

// sealKey names a key the origin seals under: K_n (name "") or K_r of
// resource name, of epoch epoch of namespace ns.
type sealKey struct {
	ns    int64
	epoch int
	name  string
}

// sealCounter holds the blocks this instance took.
type sealCounter struct {
	mu   sync.Mutex
	left map[sealKey]int64
}

func (e *Engine) sealBound() int64 {
	if e.opt.SealBound > 0 {
		return e.opt.SealBound
	}
	return 1 << 32
}

func (e *Engine) sealRotateAt() int64 {
	if e.opt.SealRotateAt > 0 {
		return e.opt.SealRotateAt
	}
	return 1 << 31
}

func (e *Engine) sealBlock() int64 {
	if e.opt.SealBlock > 0 {
		return e.opt.SealBlock
	}
	return 256
}

// errBehind is the 503 of a sealing past the bound (§12.1 behind).
func errBehind() *Error {
	err := apiErr(503, "behind", "message", "a key of this namespace has sealed as many values as it may (§E.2.1): retry once its epoch is rotated")
	err.Header = http.Header{"Retry-After": []string{"60"}}
	return err
}

// countSeals counts one sealing under each of keys, before they are made,
// outside any transaction, from this instance's blocks (sealCounter.take).
// It returns errBehind where a key has no room left.
func (e *Engine) countSeals(ctx context.Context, keys []sealKey) error {
	for _, k := range keys {
		if err := e.takeSeal(ctx, k); err != nil {
			return err
		}
	}
	return nil
}

func (e *Engine) takeSeal(ctx context.Context, k sealKey) error {
	c := &e.seals
	c.mu.Lock()
	if c.left == nil {
		c.left = map[sealKey]int64{}
	}
	if c.left[k] > 0 {
		c.left[k]--
		c.mu.Unlock()
		return nil
	}
	c.mu.Unlock()
	var got int64
	err := e.update(ctx, func(t *tx) error {
		n, err := t.allocSeals(k, e.sealBlock(), false)
		got = n
		return err
	})
	if err != nil {
		return err
	}
	if got == 0 {
		return errBehind()
	}
	c.mu.Lock()
	c.left[k] += got - 1
	c.mu.Unlock()
	return nil
}

// countIn counts n sealings under k in this write transaction, the
// sealing to be stored with it (storeSeal), or reserves n for later
// (reserve); a key with less room is errBehind, panicked so the write
// rolls back.
func (t *tx) countIn(k sealKey, n int64, reserve bool) {
	got, err := t.allocSeals(k, n, reserve)
	t.must(err)
	if got < n {
		panic(errBehind())
	}
}

// allocSeals adds up to want sealings (or reservations) to k's count, as
// many as fit under the bound, at least one or none: the block a key
// still has room for, clamped to it (§E.2.1). Each statement is atomic, so
// instances sharing a database never take the same room. Reaching
// SealRotateAt with a key of the namespace's current epoch makes its
// rotation due.
func (t *tx) allocSeals(k sealKey, want int64, reserve bool) (int64, error) {
	bound := t.e.sealBound()
	col := "sealed"
	if reserve {
		col = "reserved"
	}
	_, err := t.Exec(`INSERT INTO seal_counts (ns, epoch, name, sealed, reserved) VALUES (?,?,?,0,0) ON CONFLICT (ns, epoch, name) DO NOTHING`, k.ns, k.epoch, k.name)
	if err != nil {
		return 0, err
	}
	var sealed, reserved int64
	if err := t.QueryRow(`SELECT sealed, reserved FROM seal_counts WHERE ns = ? AND epoch = ? AND name = ?`, k.ns, k.epoch, k.name).Scan(&sealed, &reserved); err != nil {
		return 0, err
	}
	n := min(want, bound-sealed-reserved)
	if n <= 0 {
		return 0, nil
	}
	var total int64
	err = t.QueryRow(`UPDATE seal_counts SET `+col+` = `+col+` + ? WHERE ns = ? AND epoch = ? AND name = ? AND sealed + reserved + ? <= ? RETURNING sealed + reserved`,
		n, k.ns, k.epoch, k.name, n, bound).Scan(&total)
	if errors.Is(err, sql.ErrNoRows) {
		// Another instance took the room meanwhile.
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	if total >= t.e.sealRotateAt() {
		t.boundRotationDue(k)
	}
	return n, nil
}

// sealedFromReserve moves one count of k from reserved to sealed, for a
// value whose sealing a write reserved (§E.2.2), and reports whether k
// had one reserved.
func (t *tx) sealedFromReserve(k sealKey) bool {
	res, err := t.Exec(`UPDATE seal_counts SET sealed = sealed + 1, reserved = reserved - 1 WHERE ns = ? AND epoch = ? AND name = ? AND reserved > 0`, k.ns, k.epoch, k.name)
	t.must(err)
	n, err := res.RowsAffected()
	t.must(err)
	return n > 0
}

// boundRotationDue makes k's namespace's rotation due where k is of its
// current epoch (§E.2.1: a *-key holder rotates before any key of the
// current epoch reaches the bound; here the origin as RotateAuthor).
func (t *tx) boundRotationDue(k sealKey) {
	n := t.nsByID(k.ns)
	if n == nil || n.purged || t.config(n.configSeq).Epoch != k.epoch {
		return
	}
	_, err := t.Exec(`INSERT INTO rotations_due (ns, since, reason) VALUES (?,?,'bound') ON CONFLICT (ns) DO NOTHING`, k.ns, t.now.UnixMilli())
	t.must(err)
}

// reserveWrite reserves, in a write transaction, the sealings what it
// appends to sealed namespace n under epoch e may still need (§E.2.2): two
// on K_r of each resource name for each revision or tombstone (its
// document and its log entry), one on K_n for each namespace entry (its
// range). Keys are taken in sorted order, so concurrent writers on
// Postgres lock their rows alike.
func (t *tx) reserveWrite(n *nsRow, e int, revs map[string]int64, entries int64) {
	names := make([]string, 0, len(revs))
	for name := range revs {
		names = append(names, name)
	}
	sort.Strings(names)
	if entries > 0 {
		t.countIn(sealKey{n.id, e, ""}, entries, true)
	}
	for _, name := range names {
		t.countIn(sealKey{n.id, e, name}, 2*revs[name], true)
	}
}

// reserveEntries reserves, for k entries appended to n's log under
// configuration configSeq, the sealing of each one's range under K_n of
// that configuration's epoch, where it is sealed (§E.2.2).
func (t *tx) reserveEntries(n *nsRow, configSeq int64, k int64) {
	if c := t.config(configSeq); c.level == levelSealed && k > 0 && !n.isShadow() {
		t.countIn(sealKey{n.id, c.Epoch, ""}, k, true)
	}
}

// deleteSealCounts deletes namespace ns's counts (its purge, with its
// epoch keys, deleteEpochKeys).
func (t *tx) deleteSealCounts(ns int64) {
	_, err := t.Exec(`DELETE FROM seal_counts WHERE ns = ?`, ns)
	t.must(err)
}

// jobSealKey is the key j seals under in namespace ns: K_n of its kid's
// epoch for namespace content (kind config, range, grant, or an event),
// else K_r of j's resource.
func jobSealKey(ns int64, j *sealJob) sealKey {
	e := 0
	if i := lastHash(j.kid); i >= 0 {
		e, _ = strconv.Atoi(j.kid[i+1:])
	}
	name := j.name
	if j.kind == sealConfig || j.kind == sealRange || j.kind == sealGrant {
		name = ""
	}
	return sealKey{ns, e, name}
}

func lastHash(s string) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == '#' {
			return i
		}
	}
	return -1
}
