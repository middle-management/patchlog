package server

import (
	"crypto/sha256"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/middle-management/patchlog/internal/core"
)

// EXPERIMENTAL, not in the spec (docs/SPEC-FEEDBACK.md, v0.82 Open 91):
// a retry key for single resource writes, after the idempotent producers
// of the Durable Streams protocol. Off unless the core runs with
// ExperimentalRebase.
//
// A PATCH may carry X-Experimental-Producer: {id};{epoch};{seq}. Per
// resource, caller and producer id the server remembers the epoch, the
// last sequence number it wrote and the revision that write made:
//
//   - a lower epoch is 403; a higher one must start at seq 0 and replaces
//     the state (a producer that restarted);
//   - in the same epoch, the last seq again is answered 200 with that
//     write's ETag and nothing is written; an older seq is 204;
//   - seq = last + 1 is written, and remembered if it succeeds;
//   - a later seq is 409 with the seq expected.
//
// So a rebased write (core/rebase.go) that is repeated after a lost answer
// isn't applied again, which §7.2's retry rule, by parent and patch set,
// can't tell for a write whose parent the server chose. Writes of one
// producer to one resource are served one at a time.
//
// The state is in memory: it is lost at a restart and not shared between
// instances. A real form would store it with the write.
type producers struct {
	mu sync.Mutex
	m  map[[32]byte]*producerState
}

type producerState struct {
	mu     sync.Mutex
	seen   bool
	epoch  int64
	seq    int64
	lastID string
}

const producerHeader = "X-Experimental-Producer"

// producerOf parses the header, or reports ok false without one.
func producerOf(r *http.Request) (id string, epoch, seq int64, ok bool, err error) {
	h := r.Header.Get(producerHeader)
	if h == "" {
		return "", 0, 0, false, nil
	}
	parts := strings.Split(h, ";")
	bad := badInput(producerHeader + " is {id};{epoch};{seq}, with a non-empty id of at most 128 bytes and non-negative integers")
	if len(parts) != 3 || parts[0] == "" || len(parts[0]) > 128 {
		return "", 0, 0, false, bad
	}
	e, err1 := strconv.ParseInt(parts[1], 10, 64)
	q, err2 := strconv.ParseInt(parts[2], 10, 64)
	if err1 != nil || err2 != nil || e < 0 || q < 0 {
		return "", 0, 0, false, bad
	}
	return parts[0], e, q, true, nil
}

// begin locks the state of the request's producer for ns/name and judges
// its epoch and seq. With dup, the write was made before: lastID is its
// revision ("" for one older than the last). With err, it is refused. In
// both cases nothing is locked; otherwise the caller writes and calls end.
func (p *producers) begin(r *http.Request, ns, name, id string, epoch, seq int64) (st *producerState, dup bool, lastID string, err error) {
	sum := sha256.Sum256([]byte(ns + "\x00" + name + "\x00" + r.Header.Get("Authorization") + "\x00" + r.Header.Get("X-Author") + "\x00" + id))
	p.mu.Lock()
	if p.m == nil {
		p.m = map[[32]byte]*producerState{}
	}
	st = p.m[sum]
	if st == nil {
		st = &producerState{}
		p.m[sum] = st
	}
	p.mu.Unlock()
	st.mu.Lock()
	refuse := func(e error) (*producerState, bool, string, error) {
		st.mu.Unlock()
		return nil, false, "", e
	}
	switch {
	case !st.seen || epoch > st.epoch:
		if seq != 0 {
			return refuse(badInput("a producer's first write of an epoch has seq 0"))
		}
	case epoch < st.epoch:
		return refuse(&core.Error{Status: 403, Body: map[string]any{"code": "producer_epoch", "message": "a later epoch of this producer has written", "epoch": st.epoch}})
	case seq <= st.seq:
		last := ""
		if seq == st.seq {
			last = st.lastID
		}
		st.mu.Unlock()
		return nil, true, last, nil
	case seq > st.seq+1:
		return refuse(&core.Error{Status: 409, Body: map[string]any{"code": "producer_gap", "message": "a write of this producer is missing", "expected": st.seq + 1, "received": seq}})
	}
	return st, false, "", nil
}

// end records the write if it was made, and unlocks.
func (st *producerState) end(epoch, seq int64, id string, written bool) {
	if written {
		st.seen, st.epoch, st.seq, st.lastID = true, epoch, seq, id
	}
	st.mu.Unlock()
}
