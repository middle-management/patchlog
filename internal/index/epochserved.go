package index

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/derived"
)

// judgeServed judges, once, the epoch of each of docs, documents of the
// sealed (E2) namespace ns whose head's epoch is pending (docs.epoch 0: a
// revision indexed in the clear before the namespace was raised to
// sealed, which has no kid), by reading the head again and taking the
// epoch of the kid the origin serves it under (§E.2.6 Per-entry sealing:
// "kid naming the epoch the revision it derives from is served under";
// §E.2.2: the origin fixes a revision's epoch when it first seals it;
// v0.85, v0.82 Open 17). It is never the epoch in force here, which a
// rotation since the origin's sealing would make another. The epoch read
// is written to docs.epoch for that head unless another answer judged it
// first, whose epoch then stands; every later answer reads it back.
//
// A document whose row holds another head now, or whose head can't be
// read for good (gone, or sealed under an epoch the service gets no key
// for), is left out: it isn't judged, and nothing derived from it is
// sealed (errUnjudged). A read that may yet succeed is errEpochKey: 503
// behind, with Retry-After (§E.2.6: "while it may yet judge it, answers
// 503").
func (ix *Index) judgeServed(ctx context.Context, ns string, docs []docHead) (map[int64]int, error) {
	out := map[int64]int{}
	for _, d := range docs {
		var resource string
		var e int
		switch err := ix.db.QueryRowContext(ctx, `SELECT resource, coalesce(epoch, 0) FROM docs WHERE docid = ? AND head = ?`, d.docid, d.head).Scan(&resource, &e); {
		case errors.Is(err, sql.ErrNoRows):
			continue
		case err != nil:
			return nil, err
		}
		if e == 0 {
			doc, err := ix.keys.FetchDoc(ctx, ns, resource, d.head, nil)
			switch {
			case err != nil && (ctx.Err() != nil || client.Transient(err)):
				ix.opt.Logf("index: reading %s/%s@%s again for its epoch: %v", ns, resource, d.head, err)
				return nil, fmt.Errorf("%w (%s)", errEpochKey, ns)
			case err != nil:
				ix.opt.Logf("index: %s/%s@%s can't be read again for its epoch; nothing derived from it is sealed: %v", ns, resource, d.head, err)
				continue
			}
			served := derived.EpochOf(ns, doc.Kid)
			if served < 1 {
				// Served in the clear, or under another namespace's kid:
				// not as a sealed namespace serves it.
				ix.opt.Logf("index: %s/%s@%s is served under kid %q, no epoch of %s; nothing derived from it is sealed", ns, resource, d.head, doc.Kid, ns)
				continue
			}
			if _, err := ix.db.ExecContext(ctx, `UPDATE docs SET epoch = ? WHERE docid = ? AND head = ? AND coalesce(epoch, 0) = 0`, served, d.docid, d.head); err != nil {
				return nil, err
			}
			switch err := ix.db.QueryRowContext(ctx, `SELECT coalesce(epoch, 0) FROM docs WHERE docid = ? AND head = ?`, d.docid, d.head).Scan(&e); {
			case errors.Is(err, sql.ErrNoRows):
				continue
			case err != nil:
				return nil, err
			}
		}
		if e > 0 {
			out[d.docid] = e
		}
	}
	return out, nil
}

// epochIsServed reports whether a pending head's epoch in a namespace
// with encryption in is the origin's to tell (judgeServed): at E2. At E3
// a head without an own kid is a base's op read through, judged as the
// epoch in force (judgeEpochs; §E.3.1).
func epochIsServed(in derived.Info) bool { return in.Level != derived.LevelE2E }
