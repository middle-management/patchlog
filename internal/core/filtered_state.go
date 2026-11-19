package core

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/middle-management/patchlog/internal/catvis"
	"github.com/middle-management/patchlog/internal/grantcheck"
	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/jsonv"
)

// fcp is a filtered answer's combined checkpoint (§B.11.9 URLs, §B.5): at
// is grantcheck.CombinedAt over ids, the ns_id text of each member, and
// seqs the members' ns_log seqs. Each namespace is listed once, at its
// head (§B.11.9 URLs, "one ns_id per namespace as in §A.4 Answers"). The
// members are
//
//   - {ns} at its head (a purged {ns} stays, at its purge-ns entry);
//   - each trusted catalog that isn't dark (e2e, purged or a branch,
//     local or remote) at
//     its head (for catalog kind, {ns} itself);
//   - each local, unpurged member of those catalogs' catalog.trust at its
//     head, whose roles and keys visibility reads.
//
// Taking more members is safe and fewer is a leak. cats are the catalogs
// that decide visibility at the checkpoint, read from {ns}'s document as
// of its seq (none dark, all members).
type fcp struct {
	at   string
	seqs map[string]int64
	ids  map[string]string
	cats []fsCat
}

// nsID is ns's ns_id text in cp ("" if it isn't a member), which answers
// at cp carry as X-Namespace-Revision for {ns} (§B.11.9 Log ranges).
func (cp *fcp) nsID(ns string) string { return cp.ids[ns] }

// others are cp's members but ns, sorted, whose ns:{x} Cache-Tags answers
// at cp carry (§B.11.9 URLs).
func (cp *fcp) others(ns string) []string {
	var out []string
	for m := range cp.ids {
		if m != ns {
			out = append(out, m)
		}
	}
	sort.Strings(out)
	return out
}

// filteredCurrent is fs's checkpoint now, in the read snapshot. It isn't
// recorded: a URL naming its at needs recordFilteredAt first (§B.11.9 at).
func (t *tx) filteredCurrent(fs *fscope) *fcp {
	cp := &fcp{seqs: map[string]int64{}, ids: map[string]string{}}
	add := func(m *nsRow, seq int64) {
		if _, ok := cp.seqs[m.name]; ok {
			return
		}
		cp.seqs[m.name], cp.ids[m.name] = seq, t.nsLogID(seq).String()
	}
	add(fs.n, fs.n.headSeq.Int64)
	for _, c := range fs.cats {
		if c.dark() {
			continue
		}
		cp.cats = append(cp.cats, c)
		add(c.n, c.n.headSeq.Int64)
		for _, name := range t.config(c.n.configSeq).CatalogTrust {
			if m := t.fsLocal(name); m != nil && !m.purged {
				add(m, m.headSeq.Int64)
			}
		}
	}
	cp.at = grantcheck.CombinedAt(cp.ids)
	return cp
}

// filteredAt is fs's checkpoint named at: the current one, or one
// recorded in filtered_ats whose members all still exist, are unpurged
// ({ns} excepted) and have the recorded ns_id in their chains, and whose
// deciding catalogs are all members. A catalog that is dark now, a
// branch, local or remote, among them, decides nothing there even where
// an at recorded before v0.78 lists it (§B.11.9 Where). The answer at it is recomputed
// from history, which for an append-only log is as if stored (§B.11.9
// at). ok is false otherwise: the caller answers 302 to the current at.
func (t *tx) filteredAt(fs *fscope, at string) (*fcp, bool) {
	cur := t.filteredCurrent(fs)
	if at == cur.at {
		return cur, true
	}
	var raw string
	err := t.QueryRow(`SELECT cps FROM filtered_ats WHERE at = ?`, at).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false
	}
	t.must(err)
	v, err := jsonv.Parse([]byte(raw))
	m, _ := v.(map[string]any)
	if err != nil || m == nil {
		return nil, false
	}
	cp := &fcp{seqs: map[string]int64{}, ids: map[string]string{}}
	rows := map[string]*nsRow{}
	for name, x := range m {
		s, _ := x.(string)
		id, err := ids.Parse(s)
		if err != nil {
			return nil, false
		}
		var r *nsRow
		if name == fs.n.name {
			r = fs.n
		} else if r = t.fsLocal(name); r == nil || r.purged {
			return nil, false
		}
		seq, ok := t.nsLogSeq(r.id, id)
		if !ok {
			return nil, false
		}
		rows[name] = r
		cp.seqs[name], cp.ids[name] = seq, s
	}
	if _, ok := cp.seqs[fs.n.name]; !ok || grantcheck.CombinedAt(cp.ids) != at {
		return nil, false
	}
	cp.at = at
	if fs.kind == fsCatalog {
		cp.cats = []fsCat{{n: fs.n}}
		return cp, true
	}
	// The catalogs root trusts as of its seq, with their documents as of
	// theirs: each must be a member, unless it was e2e then or is a branch.
	missing := false
	trusts := catvis.TrustedCatalogs(fs.root.name, t.fconfigAt(cp.seqs[fs.root.name]).Doc, func(cat string) map[string]any {
		r := rows[cat]
		if r == nil {
			if c := t.fsLocal(cat); c != nil && !c.purged && !c.isBranch() && t.nsLevel(c) != levelE2E {
				missing = true
			}
			return nil
		}
		return t.fconfigAt(cp.seqs[cat]).Doc
	})
	if missing {
		return nil, false
	}
	for _, tr := range trusts {
		c := rows[tr.Catalog]
		if c.isBranch() || t.fconfigAt(cp.seqs[tr.Catalog]).level == levelE2E {
			continue
		}
		cp.cats = append(cp.cats, fsCat{n: c, kids: tr.Kids})
	}
	return cp, true
}

// filteredAtsTTL is how long filtered_ats rows are kept (§B.11.9 at).
const filteredAtsTTL = 7 * 24 * time.Hour

// recordFilteredAt records cp in filtered_ats, in a short write
// transaction of its own after the read that minted it and before any URL
// naming its at is answered, so every instance sharing the database
// answers it (§B.11.9 at). Rows older than filteredAtsTTL are swept.
func (e *Engine) recordFilteredAt(ctx context.Context, cp *fcp) error {
	cps := make(map[string]any, len(cp.ids))
	for ns, id := range cp.ids {
		cps[ns] = id
	}
	body := string(jsonv.Canonical(cps))
	return e.update(ctx, func(t *tx) error {
		now := t.now.UnixMilli()
		if _, err := t.Exec(`DELETE FROM filtered_ats WHERE created < ?`, now-filteredAtsTTL.Milliseconds()); err != nil {
			return err
		}
		_, err := t.Exec(`INSERT INTO filtered_ats (at, cps, created) VALUES (?, ?, ?)
			ON CONFLICT (at) DO UPDATE SET created = excluded.created`, cp.at, body, now)
		return err
	})
}

// gsRecord is a filtered_gs row (§B.11.9 gs): what a subject set stands
// for, from which cookies for it are judged, never from a grant the
// request doesn't carry.
type gsRecord struct {
	gs       string
	ns       string
	subjects []string
	partial  bool
	// kid, roles (the grant's effective roles that list read), blockRules,
	// readScope and principal are the inputs of digest (ScopeDigest).
	kid string
	// pub is the pub member of kid's key entry as the grant was verified
	// against it: a cookie is accepted only while the key with that kid
	// has the same pub (§B.11.9 gs, §C.4). "" (a row from before it was
	// kept) never matches.
	pub        string
	roles      []string
	blockRules []any
	readScope  bool
	principal  map[string]any
	digest     string
	// entry is EntryDigest (gsEntryDigest) over kid's whole key entry and
	// the whole definition of each of roles, as {ns}'s document had them
	// at the exchange: a cookie is accepted only while it is the same
	// (§B.11.9 gs, "gone or changes in any member"). "" never holds.
	// conf is the ns_config seq of that document, of the exchange's read
	// snapshot: a cookie is held to every document of {ns} after it up to
	// the one at the answer's checkpoint (§B.11.9 gs, v0.86: "Once an
	// entry after its exchange changes one of them, the cookie is 403
	// from that entry on, even where a later entry undoes the change";
	// gsHeldSince). 0 never holds.
	//
	// Both are a cookie's own: filteredAdmit reads them from the
	// filtered_gs_exps row of the cookie's exp (loadGSSlot). The
	// filtered_gs row keeps those of its latest exchange.
	entry  string
	conf   int64
	filter string // grantcheck.ReadFilter.Encode
	// exp, Unix seconds: for an exchange, the latest its cookie may
	// expire, which recordFilteredGS sets to the second it took; in a
	// filtered_gs row, the latest expiry of its cookies.
	exp int64
}

// errNoSecond is the 503 of an exchange whose cookie must differ in exp
// from those minted for its prefix and has no whole second left to do so
// before it would expire (§C.5.2 Answer, SERVICES §A.4 gs, §12.1 behind).
func errNoSecond() *Error {
	err := apiErr(503, "behind", "message", "no second is left before this edge grant would expire to tell it from those already minted: exchange a grant that lasts longer (§C.5.2)")
	err.Header = http.Header{"Retry-After": []string{"1"}}
	return err
}

// recordFilteredGS records r in filtered_gs and takes the second its
// cookie expires at, which it sets r.exp to, in a short write transaction
// of its own; it sweeps rows past their exp and those of purged
// namespaces (§B.11.9 gs). Rows are per (ns, gs): a gs names no
// namespace, so one grant's gs can be the same in two covered
// namespaces, and each keeps its own kid and rules.
//
// Readers who share a gs share its row, and a cookie carries its prefix
// and expiry alone (§C.5.3): the cookies of a gs that expire at the same
// second are one cookie. Each has a filtered_gs_exps row, with the entry
// digest and the document (conf) its exchanges recorded, from which a
// read under it is judged (filteredAdmit). An exchange shares the row of
// the second its cookie would expire at only where that changes no
// verdict: the same entry digest, and the record holding under every
// document of {ns} between the row's and its own (gsShares). Otherwise
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
// Readers of one gs record one entry at one document: its scope: subject
// digests their kid, pub and read roles by name (grantcheck.ScopeDigest),
// which are what the entry digest is over.
func (e *Engine) recordFilteredGS(ctx context.Context, r *gsRecord) error {
	subjects := make([]any, len(r.subjects))
	for i, s := range r.subjects {
		subjects[i] = s
	}
	roles := make([]any, len(r.roles))
	for i, s := range r.roles {
		roles[i] = s
	}
	enc := func(v any) string { return string(jsonv.Canonical(jsonv.FromGo(v))) }
	q := `INSERT INTO filtered_gs (gs, ns, subjects, partial, kid, pub, roles, block_rules, read_scope, principal, digest, entry, conf, filter, exp)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (ns, gs) DO UPDATE SET subjects = excluded.subjects, partial = excluded.partial,
			kid = excluded.kid, pub = excluded.pub, roles = excluded.roles, block_rules = excluded.block_rules, read_scope = excluded.read_scope,
			principal = excluded.principal, digest = excluded.digest, entry = excluded.entry, conf = excluded.conf, filter = excluded.filter,
			exp = GRT(filtered_gs.exp, excluded.exp)`
	raise := `UPDATE filtered_gs_exps SET conf = GRT(conf, ?) WHERE ns = ? AND gs = ? AND exp = ?`
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
			`DELETE FROM filtered_gs WHERE exp <= ? OR ns IN (SELECT name FROM namespaces WHERE purged <> 0)`,
			`DELETE FROM filtered_gs_exps WHERE exp <= ? OR ns IN (SELECT name FROM namespaces WHERE purged <> 0)`,
		} {
			if _, err := t.Exec(sweep, now-int64(gsSweepMargin/time.Second)); err != nil {
				return err
			}
		}
		// {ns}'s documents are read without its lock: they only append.
		t.noLock++
		n := t.nsByName(r.ns)
		t.noLock--
		shares := t.gsShares(n, r)
		// The latest second at or before r.exp that is free, or whose
		// row this exchange can share. Another instance may take a free
		// one first: then the seconds are read again.
		for taken = 0; taken == 0; {
			slots := map[int64]gsSlot{}
			rows, err := t.Query(`SELECT exp, entry, conf FROM filtered_gs_exps WHERE ns = ? AND gs = ? AND exp > ? AND exp <= ?`, r.ns, r.gs, now, r.exp)
			if err != nil {
				return err
			}
			for rows.Next() {
				var exp int64
				var s gsSlot
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
					res, err := t.Exec(`INSERT INTO filtered_gs_exps (ns, gs, exp, entry, conf) VALUES (?, ?, ?, ?, ?) ON CONFLICT (ns, gs, exp) DO NOTHING`, r.ns, r.gs, exp, r.entry, r.conf)
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
					res, err := t.Exec(raise, r.conf, r.ns, r.gs, exp)
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
		_, err := t.Exec(q, r.gs, r.ns, enc(subjects), boolInt(r.partial), r.kid, r.pub, enc(roles), enc(nonNilRules(r.blockRules)),
			boolInt(r.readScope), enc(r.principal), r.digest, r.entry, r.conf, r.filter, taken)
		return err
	})
	if err == nil {
		r.exp = taken
	}
	return err
}

// gsSweepMargin is how long past their exp filtered_gs and
// filtered_gs_exps rows are kept (recordFilteredGS): more than the
// clocks of instances sharing a database differ by.
const gsSweepMargin = time.Minute

// gsSlot is a filtered_gs_exps row: the entry digest and document the
// exchanges of the cookies of one gs expiring at one second recorded.
type gsSlot struct {
	entry string
	conf  int64
}

// loadGSSlot is the filtered_gs_exps row of the cookies of gs in ns that
// expire at exp, as the read snapshot has it; ok is false for none.
func (t *tx) loadGSSlot(ns, gs string, exp int64) (s gsSlot, ok bool) {
	err := t.QueryRow(`SELECT entry, conf FROM filtered_gs_exps WHERE ns = ? AND gs = ? AND exp = ?`, ns, gs, exp).Scan(&s.entry, &s.conf)
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

// loadGS is gs's filtered_gs row in ns as the read snapshot has it, nil
// if there is none or it has expired. It is read from the database each
// time, so every instance sharing it judges a cookie alike, and a row
// swept or deleted with its namespace is a miss at once.
func (t *tx) loadGS(ns, gs string) *gsRecord {
	r := &gsRecord{gs: gs}
	var subjects, roles, blockRules, principal string
	var partial, readScope int64
	err := t.QueryRow(`SELECT ns, subjects, partial, kid, pub, roles, block_rules, read_scope, principal, digest, entry, conf, filter, exp FROM filtered_gs WHERE ns = ? AND gs = ?`, ns, gs).
		Scan(&r.ns, &subjects, &partial, &r.kid, &r.pub, &roles, &blockRules, &readScope, &principal, &r.digest, &r.entry, &r.conf, &r.filter, &r.exp)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	t.must(err)
	if r.exp <= t.now.Unix() {
		return nil
	}
	r.partial, r.readScope = partial != 0, readScope != 0
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
