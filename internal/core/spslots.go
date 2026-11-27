package core

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	mrand "math/rand/v2"
	"sync"
	"time"
)

// On Spanner each instance holds one of spSlots slots, leased in id_slots,
// and puts it in every id it takes (seqGen): so no two instances take the
// same id, and revisions_by_seq, the index of revisions by seq alone, needs
// no uniqueness checked at each commit.
//
// An instance takes a free slot (expired, or never taken) when it opens,
// renews it every slotRenew, and gives it up when it closes. It takes ids
// only while its last renewal is younger than slotValid: half the lease,
// so an instance whose renewals fail stops taking ids well before another
// may take its slot (slotTTL after the last renewal it made, by the other's
// clock: clocks must agree to well within slotTTL-slotValid, as for the
// leader's lease). A renewal that finds the slot taken takes another.
const (
	slotTTL   = 60 * time.Second
	slotValid = slotTTL / 2
	slotRenew = slotTTL / 6
)

// errSlotLapsed refuses an id while the slot's lease isn't known renewed.
var errSlotLapsed = errors.New("this instance's id slot lease lapsed (id_slots): ids are refused until it is renewed")

// slotLease is an engine's lease of its slot.
type slotLease struct {
	db     *sql.DB
	holder string
	gen    *seqGen
	mu     sync.Mutex
	// renewed is when the last renewal that succeeded started.
	renewed time.Time
}

// check reports whether ids may be taken now. A nil lease always may (ids
// tested without a database).
func (l *slotLease) check() error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if time.Since(l.renewed) > slotValid {
		return errSlotLapsed
	}
	return nil
}

// openSlotLease takes a slot for g, which it then hands out ids in.
func openSlotLease(ctx context.Context, db *sql.DB, holder string, g *seqGen) (*slotLease, error) {
	l := &slotLease{db: db, holder: holder, gen: g}
	if err := l.take(ctx); err != nil {
		return nil, err
	}
	g.mu.Lock()
	g.lease = l
	g.mu.Unlock()
	return l, nil
}

// take takes a free slot, trying them from a random one.
func (l *slotLease) take(ctx context.Context) error {
	held := map[int64]bool{}
	start := time.Now()
	now := start.UnixMilli()
	rows, err := l.db.QueryContext(ctx, `SELECT slot FROM id_slots WHERE expires >= $1 AND holder <> $2`, now, l.holder)
	if err != nil {
		return fmt.Errorf("reading id_slots: %w", err)
	}
	for rows.Next() {
		var s int64
		if err := rows.Scan(&s); err != nil {
			rows.Close()
			return err
		}
		held[s] = true
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	first := mrand.Int64N(spSlots)
	for i := range int64(spSlots) {
		s := (first + i) % spSlots
		if held[s] {
			continue
		}
		ok, err := l.claim(ctx, s, now)
		if err != nil {
			return err
		}
		if ok {
			l.gen.mu.Lock()
			if l.gen.slot != s {
				l.gen.slot, l.gen.last = s, 0
			}
			l.gen.mu.Unlock()
			l.mu.Lock()
			l.renewed = start
			l.mu.Unlock()
			return nil
		}
	}
	return fmt.Errorf("no free id slot: all %d of id_slots are leased (an instance more than that, or ones that died within %v)", spSlots, slotTTL)
}

// claim takes slot s if it is free or already this instance's.
func (l *slotLease) claim(ctx context.Context, s, now int64) (bool, error) {
	exp := now + slotTTL.Milliseconds()
	if _, err := l.db.ExecContext(ctx, `INSERT INTO id_slots (slot, holder, expires) VALUES ($1, $2, $3) ON CONFLICT (slot) DO NOTHING`, s, l.holder, exp); err != nil {
		return false, fmt.Errorf("taking id slot %d: %w", s, err)
	}
	r, err := l.db.ExecContext(ctx, `UPDATE id_slots SET holder = $1, expires = $2 WHERE slot = $3 AND (holder = $4 OR expires < $5)`, l.holder, exp, s, l.holder, now)
	if err != nil {
		return false, fmt.Errorf("taking id slot %d: %w", s, err)
	}
	n, err := r.RowsAffected()
	return err == nil && n == 1, err
}

// renew extends the lease, or takes another slot if this one is lost.
func (l *slotLease) renew(ctx context.Context) {
	start := time.Now()
	now := start.UnixMilli()
	l.gen.mu.Lock()
	s := l.gen.slot
	l.gen.mu.Unlock()
	r, err := l.db.ExecContext(ctx, `UPDATE id_slots SET expires = $1 WHERE slot = $2 AND holder = $3 AND expires >= $4`,
		now+slotTTL.Milliseconds(), s, l.holder, now)
	if err != nil {
		log.Printf("renewing id slot %d: %v", s, err)
		return
	}
	if n, err := r.RowsAffected(); err == nil && n == 1 {
		l.mu.Lock()
		l.renewed = start
		l.mu.Unlock()
		return
	}
	// Expired, and maybe another's now: ids were refused since slotValid,
	// so none of this slot's can meet that instance's.
	if err := l.take(ctx); err != nil {
		log.Printf("id slot %d lost, and no other: %v", s, err)
	}
}

// loop renews the lease until stop is closed.
func (l *slotLease) loop(stop <-chan struct{}) {
	t := time.NewTicker(slotRenew)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			ctx, cancel := context.WithTimeout(context.Background(), slotRenew)
			l.renew(ctx)
			cancel()
		}
	}
}

// release gives the slot up (Close).
func (l *slotLease) release() {
	if l == nil {
		return
	}
	l.gen.mu.Lock()
	s := l.gen.slot
	l.gen.mu.Unlock()
	l.db.ExecContext(context.Background(), `UPDATE id_slots SET expires = 0 WHERE slot = $1 AND holder = $2`, s, l.holder)
}
