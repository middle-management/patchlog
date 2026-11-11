package core

import (
	"context"
	"database/sql"
	"errors"
	"sort"
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
	// (§B.11.9 gs, "gone or changes in any member"). "" (a row from
	// before it was kept) never holds.
	entry  string
	filter string // grantcheck.ReadFilter.Encode
	exp    int64  // Unix seconds: the latest expiry of its cookies
}

// recordFilteredGS records r in filtered_gs, in a short write transaction
// of its own, keeping the later exp of a row already there; it sweeps rows
// past their exp and those of purged namespaces (§B.11.9 gs). Rows are per
// (ns, gs): a gs names no namespace, so one grant's gs can be the same in
// two covered namespaces, and each keeps its own kid and rules.
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
	q := `INSERT INTO filtered_gs (gs, ns, subjects, partial, kid, pub, roles, block_rules, read_scope, principal, digest, entry, filter, exp)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (ns, gs) DO UPDATE SET subjects = excluded.subjects, partial = excluded.partial,
			kid = excluded.kid, pub = excluded.pub, roles = excluded.roles, block_rules = excluded.block_rules, read_scope = excluded.read_scope,
			principal = excluded.principal, digest = excluded.digest, entry = excluded.entry, filter = excluded.filter, exp = `
	if e.pg {
		q += `GREATEST(filtered_gs.exp, excluded.exp)`
	} else {
		q += `max(filtered_gs.exp, excluded.exp)`
	}
	return e.update(ctx, func(t *tx) error {
		if _, err := t.Exec(`DELETE FROM filtered_gs WHERE exp <= ? OR ns IN (SELECT name FROM namespaces WHERE purged <> 0)`, t.now.Unix()); err != nil {
			return err
		}
		_, err := t.Exec(q, r.gs, r.ns, enc(subjects), boolInt(r.partial), r.kid, r.pub, enc(roles), enc(nonNilRules(r.blockRules)),
			boolInt(r.readScope), enc(r.principal), r.digest, r.entry, r.filter, r.exp)
		return err
	})
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
	err := t.QueryRow(`SELECT ns, subjects, partial, kid, pub, roles, block_rules, read_scope, principal, digest, entry, filter, exp FROM filtered_gs WHERE ns = ? AND gs = ?`, ns, gs).
		Scan(&r.ns, &subjects, &partial, &r.kid, &r.pub, &roles, &blockRules, &readScope, &principal, &r.digest, &r.entry, &r.filter, &r.exp)
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
