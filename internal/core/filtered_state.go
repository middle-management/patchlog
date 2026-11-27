package core

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/jsonv"
)

// fcp is a filtered answer's checkpoint (§7.9 URLs): at is the ns_id
// text of an entry of {ns}, and seq its ns_log seq. It is immutable.
type fcp struct {
	at  string
	seq int64
}

// filteredCurrent is fs's checkpoint now, in the read snapshot: {ns} at
// its head (a purged {ns} at its purge-ns entry).
func (t *tx) filteredCurrent(fs *fscope) *fcp {
	seq := fs.n.headSeq.Int64
	return &fcp{at: t.nsLogID(seq).String(), seq: seq}
}

// filteredAt is fs's checkpoint named at: an entry of {ns}'s chain. ok is
// false otherwise: the caller answers 302 to the current at.
func (t *tx) filteredAt(fs *fscope, at string) (*fcp, bool) {
	id, err := ids.Parse(at)
	if err != nil {
		return nil, false
	}
	seq, ok := t.nsLogSeq(fs.n.id, id)
	if !ok {
		return nil, false
	}
	return &fcp{at: at, seq: seq}, true
}

// viewRecord is a filtered_views row (§7.9 view): what a view stands
// for, from which cookies for it are judged, never from a grant the
// request doesn't carry.
type viewRecord struct {
	view     string
	ns       string
	subjects []string
	// kid, roles (the grant's effective roles that list read), blockRules,
	// readScope and principal are the inputs of digest (ScopeDigest).
	kid string
	// pub is the pub member of kid's key entry as the grant was verified
	// against it: a cookie is accepted only while the key with that kid
	// has the same pub (§7.9 view, §C.4). "" (a row from before it was
	// kept) never matches.
	pub        string
	roles      []string
	blockRules []any
	readScope  bool
	principal  map[string]any
	digest     string
	// entry is EntryDigest (viewEntryDigest) over kid's whole key entry and
	// the whole definition of each of roles, as {ns}'s document had them
	// at the exchange: a cookie is accepted only while it is the same
	// (§7.9 view, "gone or changes in any member"). "" never holds.
	// conf is the ns_config seq of that document, of the exchange's read
	// snapshot: a cookie is held to every document of {ns} after it up to
	// the one at the answer's checkpoint (§7.9 view, v0.86: "Once an
	// entry after its exchange changes one of them, the cookie is 403
	// from that entry on, even where a later entry undoes the change";
	// viewHeldSince). 0 never holds.
	//
	// Both are a cookie's own: filteredAdmit reads them from the
	// filtered_view_exps row of the cookie's exp (loadViewSlot). The
	// filtered_views row keeps those of its latest exchange.
	entry  string
	conf   int64
	filter string // grantcheck.ReadFilter.Encode
	// exp, Unix seconds: for an exchange, the latest its cookie may
	// expire, which recordFilteredView sets to the second it took; in a
	// filtered_views row, the latest expiry of its cookies.
	exp int64
}

// errNoSecond is the 503 of an exchange whose cookie must differ in exp
// from those minted for its prefix and has no whole second left to do so
// before it would expire (§C.5.2 Answer, SERVICES §A.4 view, §12.1 behind).
func errNoSecond() *Error {
	err := apiErr(503, "behind", "message", "no second is left before this edge grant would expire to tell it from those already minted: exchange a grant that lasts longer (§C.5.2)")
	err.Header = http.Header{"Retry-After": []string{"1"}}
	return err
}

// recordFilteredView records r in filtered_views and takes the second its
// cookie expires at, which it sets r.exp to, in a short write transaction
// of its own; it sweeps rows past their exp and those of purged
// namespaces (§7.9 view). Rows are per (ns, view): a view names no
// namespace, so one grant's view can be the same in two covered
// namespaces, and each keeps its own kid and rules.
//
// Readers who share a view share its row, and a cookie carries its prefix
// and expiry alone (§C.5.3): the cookies of a view that expire at the same
// second are one cookie. Each has a filtered_view_exps row, with the entry
// digest and the document (conf) its exchanges recorded, from which a
// read under it is judged (filteredAdmit). An exchange shares the row of
// the second its cookie would expire at only where that changes no
// verdict: the same entry digest, and the record holding under every
// document of {ns} between the row's and its own (viewShares). Otherwise
// its cookie must be told apart from that one, and it takes whole seconds
// off, down to the first second that is free or that it can share
// (§C.5.2: "less any whole seconds a minter MAY take off so that cookies
// for one prefix that it must tell apart differ in exp"). errNoSecond
// where none is left after now: nothing is recorded.
//
// So a cookie a change ended stays ended whoever exchanges since, the
// same reader or another, with whatever grant: no exchange writes to its
// row. A change made and undone gives the entry digest it had, and the
// exchange after the undo still takes another second, since a document
// between the two doesn't hold. And a reader who exchanges again always
// gets a cookie that reads, while a second is left, also under a grant
// that ends within the quarter of an hour and with the grant she held
// before. (Before, cookies were told apart by "expires no later than the
// replaced row's", which such a grant's cookie never passed.)
//
// A shared row keeps the greater conf: every document between the two
// holds, so each cookie's verdict at any checkpoint is the same from
// either, and an exchange that read {ns} earlier and records later moves
// nothing back. An exchange that read before a change and records after
// it can't share the row of one made after the change: it takes its own
// second, with the document it read, and is ended by the change.
//
// Readers of one view record one entry at one document: its scope: subject
// digests their kid, pub and read roles by name (grantcheck.ScopeDigest),
// which are what the entry digest is over.
func (e *Engine) recordFilteredView(ctx context.Context, r *viewRecord) error {
	subjects := make([]any, len(r.subjects))
	for i, s := range r.subjects {
		subjects[i] = s
	}
	roles := make([]any, len(r.roles))
	for i, s := range r.roles {
		roles[i] = s
	}
	enc := func(v any) string { return string(jsonv.Canonical(jsonv.FromGo(v))) }
	q := `INSERT INTO filtered_views (view, ns, subjects, kid, pub, roles, block_rules, read_scope, principal, digest, entry, conf, filter, exp)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (ns, view) DO UPDATE SET subjects = excluded.subjects,
			kid = excluded.kid, pub = excluded.pub, roles = excluded.roles, block_rules = excluded.block_rules, read_scope = excluded.read_scope,
			principal = excluded.principal, digest = excluded.digest, entry = excluded.entry, conf = excluded.conf, filter = excluded.filter,
			exp = GRT(filtered_views.exp, excluded.exp)`
	raise := `UPDATE filtered_view_exps SET conf = GRT(conf, ?) WHERE ns = ? AND view = ? AND exp = ?`
	grt := "max("
	if e.pg {
		grt = "GREATEST("
	}
	q, raise = strings.ReplaceAll(q, "GRT(", grt), strings.ReplaceAll(raise, "GRT(", grt)
	taken := r.exp
	err := e.update(ctx, func(t *tx) error {
		now := t.now.Unix()
		// Rows are swept a while after their exp: instances sharing the
		// database each go by their own clock, and a row swept at its
		// second by one that is ahead would leave that second free for
		// an exchange at one that is behind, whose row an ended cookie
		// of the same exp would then read under until it expires.
		for _, sweep := range []string{
			`DELETE FROM filtered_views WHERE exp <= ? OR ns IN (SELECT name FROM namespaces WHERE purged <> 0)`,
			`DELETE FROM filtered_view_exps WHERE exp <= ? OR ns IN (SELECT name FROM namespaces WHERE purged <> 0)`,
		} {
			if _, err := t.Exec(sweep, now-int64(viewSweepMargin/time.Second)); err != nil {
				return err
			}
		}
		// {ns}'s documents are read without its lock: they only append.
		t.noLock++
		n := t.nsByName(r.ns)
		t.noLock--
		if n != nil && n.purged {
			// Purged since the exchange read it (§8.5).
			pe := t.purgedNS(n)
			pe.Body["ns"] = n.name
			return pe
		}
		shares := t.viewShares(n, r)
		// The latest second at or before r.exp that is free, or whose
		// row this exchange can share. Another instance may take a free
		// one first: then the seconds are read again.
		for taken = 0; taken == 0; {
			slots := map[int64]viewSlot{}
			rows, err := t.Query(`SELECT exp, entry, conf FROM filtered_view_exps WHERE ns = ? AND view = ? AND exp > ? AND exp <= ?`, r.ns, r.view, now, r.exp)
			if err != nil {
				return err
			}
			for rows.Next() {
				var exp int64
				var s viewSlot
				if err := rows.Scan(&exp, &s.entry, &s.conf); err != nil {
					rows.Close()
					return err
				}
				slots[exp] = s
			}
			if err := rows.Err(); err != nil {
				return err
			}
			rows.Close()
			lost := false
			for exp := r.exp; exp > now && taken == 0 && !lost; exp-- {
				s, held := slots[exp]
				switch {
				case !held:
					res, err := t.Exec(`INSERT INTO filtered_view_exps (ns, view, exp, entry, conf) VALUES (?, ?, ?, ?, ?) ON CONFLICT (ns, view, exp) DO NOTHING`, r.ns, r.view, exp, r.entry, r.conf)
					if err != nil {
						return err
					}
					if c, err := res.RowsAffected(); err != nil {
						return err
					} else if c == 0 {
						lost = true
						continue
					}
					taken = exp
				case shares(s):
					res, err := t.Exec(raise, r.conf, r.ns, r.view, exp)
					if err != nil {
						return err
					}
					if c, err := res.RowsAffected(); err != nil {
						return err
					} else if c == 0 {
						// Swept since it was read: without its row the
						// cookie would be 403. The seconds are read again.
						lost = true
						continue
					}
					taken = exp
				}
			}
			if taken == 0 && !lost {
				return errNoSecond()
			}
		}
		_, err := t.Exec(q, r.view, r.ns, enc(subjects), r.kid, r.pub, enc(roles), enc(nonNilRules(r.blockRules)),
			boolInt(r.readScope), enc(r.principal), r.digest, r.entry, r.conf, r.filter, taken)
		return err
	})
	if err == nil {
		r.exp = taken
	}
	return err
}

// viewSweepMargin is how long past their exp filtered_views and
// filtered_view_exps rows are kept (recordFilteredView): more than the
// clocks of instances sharing a database differ by.
const viewSweepMargin = time.Minute

// viewSlot is a filtered_view_exps row: the entry digest and document the
// exchanges of the cookies of one view expiring at one second recorded.
type viewSlot struct {
	entry string
	conf  int64
}

// loadViewSlot is the filtered_view_exps row of the cookies of view in ns that
// expire at exp, as the read snapshot has it; ok is false for none.
func (t *tx) loadViewSlot(ns, view string, exp int64) (s viewSlot, ok bool) {
	err := t.QueryRow(`SELECT entry, conf FROM filtered_view_exps WHERE ns = ? AND view = ? AND exp = ?`, ns, view, exp).Scan(&s.entry, &s.conf)
	if errors.Is(err, sql.ErrNoRows) {
		return s, false
	}
	t.must(err)
	return s, true
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func nonNilRules(rs []any) []any {
	if rs == nil {
		return []any{}
	}
	return rs
}

// loadView is view's filtered_views row in ns as the read snapshot has it, nil
// if there is none or it has expired. It is read from the database each
// time, so every instance sharing it judges a cookie alike, and a row
// swept or deleted with its namespace is a miss at once.
func (t *tx) loadView(ns, view string) *viewRecord {
	r := &viewRecord{view: view}
	var subjects, roles, blockRules, principal string
	var readScope int64
	err := t.QueryRow(`SELECT ns, subjects, kid, pub, roles, block_rules, read_scope, principal, digest, entry, conf, filter, exp FROM filtered_views WHERE ns = ? AND view = ?`, ns, view).
		Scan(&r.ns, &subjects, &r.kid, &r.pub, &roles, &blockRules, &readScope, &principal, &r.digest, &r.entry, &r.conf, &r.filter, &r.exp)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	t.must(err)
	if r.exp <= t.now.Unix() {
		return nil
	}
	r.readScope = readScope != 0
	strs := func(s string) ([]string, bool) {
		v, err := jsonv.Parse([]byte(s))
		arr, ok := v.([]any)
		if err != nil || !ok {
			return nil, false
		}
		out := make([]string, 0, len(arr))
		for _, x := range arr {
			str, ok := x.(string)
			if !ok {
				return nil, false
			}
			out = append(out, str)
		}
		return out, true
	}
	var ok1, ok2 bool
	r.subjects, ok1 = strs(subjects)
	r.roles, ok2 = strs(roles)
	br, err1 := jsonv.Parse([]byte(blockRules))
	pr, err2 := jsonv.Parse([]byte(principal))
	r.blockRules, _ = br.([]any)
	r.principal, _ = pr.(map[string]any)
	if !ok1 || !ok2 || err1 != nil || err2 != nil || r.principal == nil {
		return nil // unreadable: as a miss
	}
	return r
}
