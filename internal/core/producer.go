package core

import (
	"database/sql"
	"errors"
)

// EXPERIMENTAL, with rebase.go (docs/SPEC-FEEDBACK.md, v0.82 Open 91): a
// retry key for single resource writes, after the idempotent producers of
// the Durable Streams protocol. Acted on only with
// Options.ExperimentalRebase.
//
// A write may name a producer: an id its client chose, an epoch and a
// sequence number. Per resource, author and producer id the last epoch
// and seq written are stored with the revision that write made
// (write_producers), in the write's own transaction, so every instance
// of a deployment judges a repeat alike and a restart forgets nothing:
//
//   - a lower epoch is 403; a higher one must start at seq 0 and replaces
//     the state (a producer that lost its count);
//   - in the same epoch, the last seq again is answered 200 with that
//     write's entry and nothing is written; an older seq is 204;
//   - seq = last + 1 is written, and recorded with it;
//   - a later seq is 409 with the seq expected.
//
// A refused write records nothing, so its seq is used again. Two requests
// with the same new seq can't both be written: the record is replaced only
// where it is still the one the check read, and the one that finds it
// moved runs again and is then answered as the repeat it is.
type Producer struct {
	ID         string
	Epoch, Seq int64
}

// producerPrev is the record a write's check read: none, or its epoch and
// seq.
type producerPrev struct {
	had        bool
	epoch, seq int64
}

type producerKey struct {
	res, author int64
	id          string
}

// producerState is a record as a deferring transaction holds it
// (deferred.go): what it will write, and what the database held.
type producerState struct {
	epoch, seq, lastSeq int64
	prev                producerPrev
	dirty               bool // not written yet
}

var upsertProducers = bulkStmt{
	pg: `WITH v AS (SELECT * FROM unnest($1::bigint[], $2::bigint[], $3::text[], $4::bigint[], $5::bigint[], $6::bigint[], $7::bigint[], $8::bigint[])
			AS v(res, author, producer, epoch, seq, last_seq, pe, ps))
		INSERT INTO write_producers (res, author, producer, epoch, seq, last_seq)
		SELECT res, author, producer, epoch, seq, last_seq FROM v
		ON CONFLICT (res, author, producer) DO UPDATE SET epoch = excluded.epoch, seq = excluded.seq, last_seq = excluded.last_seq
		WHERE EXISTS (SELECT 1 FROM v WHERE v.res = write_producers.res AND v.author = write_producers.author AND v.producer = write_producers.producer
			AND v.pe = write_producers.epoch AND v.ps = write_producers.seq)`,
	lite: `INSERT INTO write_producers (res, author, producer, epoch, seq, last_seq) VALUES (?,?,?,?,?,?)
		ON CONFLICT (res, author, producer) DO UPDATE SET epoch = excluded.epoch, seq = excluded.seq, last_seq = excluded.last_seq
		WHERE ?7 = write_producers.epoch AND ?8 = write_producers.seq`,
	types: []string{"bigint", "bigint", "text", "bigint", "bigint", "bigint", "bigint", "bigint"},
}

// producerRead returns the record of key: from the rows this transaction
// holds back, else the database's.
func (t *tx) producerRead(k producerKey) (epoch, seq, lastSeq int64, prev producerPrev) {
	if t.def != nil {
		if s, ok := t.def.producers[k]; ok {
			return s.epoch, s.seq, s.lastSeq, producerPrev{true, s.epoch, s.seq}
		}
		// A record held back would have been found: the rows held back
		// don't change what the database answers for any other.
		was := t.def.flushing
		t.def.flushing = true
		defer func() { t.def.flushing = was }()
	}
	err := t.QueryRow(`SELECT epoch, seq, last_seq FROM write_producers WHERE res = ? AND author = ? AND producer = ?`, k.res, k.author, k.id).Scan(&epoch, &seq, &lastSeq)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, 0, 0, producerPrev{}
	}
	t.must(err)
	return epoch, seq, lastSeq, producerPrev{true, epoch, seq}
}

// producerCheck judges a write's producer key (step 2, after the retry
// lookup of §7.2). It returns the answer of a repeat, or a refusal, or
// neither: the write goes on, and s.prodPrev is what producerRecord must
// still find.
func (t *tx) producerCheck(n *nsRow, a *actor, s *itemState) (*WriteResult, *Error) {
	p := s.Producer
	if p.ID == "" || len(p.ID) > 128 || p.Epoch < 0 || p.Seq < 0 {
		return nil, badInput("a producer is a non-empty id of at most 128 bytes, an epoch and a seq, neither negative")
	}
	own := t.resource(n.id, s.Resource)
	if own == nil {
		return nil, nil // a create: If-None-Match already makes it safe to repeat
	}
	k := producerKey{own.id, t.actorID(a), p.ID}
	epoch, seq, lastSeq, prev := t.producerRead(k)
	s.prodKey, s.prodPrev = &k, prev
	switch {
	case !prev.had || p.Epoch > epoch:
		if p.Seq != 0 {
			return nil, badInput("a producer's first write of an epoch has seq 0")
		}
	case p.Epoch < epoch:
		return nil, apiErr(403, "producer_epoch", "message", "a later epoch of this producer has written", "epoch", epoch)
	case p.Seq == seq:
		row := t.rev(lastSeq)
		le := t.logEntry(row)
		return &WriteResult{Status: 200, Replayed: true, Entry: &le, Items: []ItemResult{{Resource: s.Resource, IDs: []string{row.id.String()}}}}, nil
	case p.Seq < seq:
		return &WriteResult{Status: 204, Replayed: true}, nil
	case p.Seq > seq+1:
		return nil, apiErr(409, "producer_gap", "message", "a write of this producer is missing", "expected", seq+1, "received", p.Seq)
	}
	return nil, nil
}

// producerRecord stores the write's producer key with the revision it
// made, where the record is still the one producerCheck read.
func (t *tx) producerRecord(s *itemState, author, lastSeq int64) {
	if s.prodKey == nil {
		return
	}
	k, p := *s.prodKey, s.Producer
	// The author's id as the insert knows it: a check in a read
	// transaction has none yet for an author who never wrote (and then
	// read no record either).
	k.author = author
	if t.deferring() {
		// Held back with the group's rows (deferred.go).
		if t.def.producers == nil {
			t.def.producers = map[producerKey]*producerState{}
		}
		if st, ok := t.def.producers[k]; ok {
			st.epoch, st.seq, st.lastSeq, st.dirty = p.Epoch, p.Seq, lastSeq, true
		} else {
			t.def.producers[k] = &producerState{p.Epoch, p.Seq, lastSeq, s.prodPrev, true}
		}
		t.def.producersDirty = true
		return
	}
	t.producerWrite([][]any{producerRow(k, p.Epoch, p.Seq, lastSeq, s.prodPrev)})
}

func producerRow(k producerKey, epoch, seq, lastSeq int64, prev producerPrev) []any {
	pe, ps := int64(-1), int64(-1) // no record: matches none
	if prev.had {
		pe, ps = prev.epoch, prev.seq
	}
	return []any{k.res, k.author, k.id, epoch, seq, lastSeq, pe, ps}
}

// producerWrite writes records; one that is no longer what its write's
// check read lost a race to another write of the same producer, which
// rolls the transaction back to run again (errChainRace).
func (t *tx) producerWrite(rows [][]any) {
	if t.bulkExec(upsertProducers, rows) != int64(len(rows)) {
		panic(errChainRace)
	}
}
