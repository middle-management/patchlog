package index

import (
	"bytes"
	"cmp"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/middle-management/patchlog/internal/catvis"
	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/edge"
	"github.com/middle-management/patchlog/internal/grant"
	"github.com/middle-management/patchlog/internal/grantcheck"
	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/svcedge"
	"github.com/middle-management/patchlog/internal/telemetry"
)

// The service's own edge grants (§A.4: a gs and its URLs are served as in
// §B.11.5; §C.5), with Options.EdgeGrants.
//
// Results read with a grant in Authorization are never cached at the edge
// (§9): the grant is one reader's. A private result depends on the
// reader's subject set alone (its markers, Index.access), so an edge may
// cache it for every reader of that subject set, given a cookie it can
// verify that says so. The service mints such cookies itself, with a key
// and kid of its own that the origin never holds, for the prefixes of a
// subject set's URLs: /{ns}/g/{gs} for a private namespace's results, gs
// over the reader's marker there, and /_refs/g/{gs} for the answers
// across namespaces, gs over its markers in every namespace it may see
// that the service has reached (refsReader). The default format is the
// core's (edge.Cookies), so an edge in front of the service makes the
// same six checks with the service's kid, which vouches only for those
// prefixes. A namespace named r or ns gets no cookie for its results,
// whose prefix would lie under the core's.
//
//	POST   /edge-grants              exchange grants for cookies, as the
//	                                 core's issuance (§C.5.2)
//	DELETE /edge-grants?prefix=…     withdraw them (§C.5.4)
//
// A cookie carries only kid, p and exp. A read under one is the subject
// set's, so the service keeps the markers behind each gs it minted a
// cookie for (svcedge.Store: edge_subjects), and, for a marker
// reads:{ns}:scope:{digest}, what its digest covers, the rules that limit
// the reads and the /principal values they refer to (edge_filters,
// markerRec), from which it filters hits per resource as for any grant
// with that marker, for a marker reads:{ns}:g:{gs} (§B.11.9) also its
// subjects (edge_gs), and for every marker, reads:{ns} included, every
// key a cookie of it was minted under, its kid, the role names its grant
// read through, its kid's pub and the digest of its whole entry and of
// those roles' whole definitions (edge_gs_keys, gsKey, entryDigest),
// each until that cookie expires: a cookie is 403 once one of the keys
// or roles it came from is gone or changes in any member (§A.4 gs: "its
// key being the one that verified the grant in {ns}, reads:{ns} markers
// included", §B.11.9 gs; readsKeysHold, scopeKeysHold, storedFview), and
// no later exchange vouches for it again: one whose keys or entries
// differ mints a cookie with another exp (recordCookies). They
// are kept across restarts and -rebuild until the last such cookie
// expires; a gs or marker the service doesn't know, minted by another
// instance with its own database, is 401, and the reader exchanges again.
// Instances on one database share them, and share the exchangeRate
// buckets too (§B.11.5). A reader of a whole namespace at issue
// (reads:{ns}) reads it whole under the cookie until it expires or its
// key or a role it read through changes; a revocation since doesn't end
// it: for that the cookie's lifetime is the latency (§C.5).

// markerRec is what a marker of a cookie stands for: for
// reads:{ns}:scope:{digest}, the read filter of the rules its digest
// covers (grantcheck.ReadFilter: its key's scope, its blocks and, if it
// carries roles, each effective role that lists read, and its
// /principal), from which hits are filtered per resource as for any grant
// with that marker; for reads:{ns}:g:{gs} (§B.11.9), also its subjects,
// from which item 1 is judged; and for either, from an exchange, the key
// its grant came from (gsKey), recorded for its cookie (recordCookies;
// keysHold and storedFview judge each key of a cookie). A rule
// referring to /now gives no marker, so the filter judges a read as the
// grant's read check does, without a clock.
type markerRec struct {
	f        *grantcheck.ReadFilter // nil for reads:{ns}, which reads whole
	subjects []string               // g: markers only
	key      gsKey                  // from an exchange only
	// also are the keys the other grants of one exchange got the same
	// marker through, recorded beside key (issueEdgeGrants).
	also []gsKey
}

// gsKey is a key a g: or scope marker's cookies came from: its kid and
// the names of its grant's read roles, whose rules as of a checkpoint
// must still digest to the marker's scope subject (g:) or its digest
// (scope:), and the pub its kid had, which the key with that kid must
// still have (§B.11.9 gs, §C.4, §A.4; storedFview, scopeKeysHold). A g:
// marker's gs digests the key too (catvis.KeySubject), but readers whose
// grants come from different keys, or from one key before and after its
// entry changes, may share a marker, and a cookie says only its prefix
// and exp: the gsKeys of each cookie are kept by its marker and exp
// (edge_gs_keys), the same for every exchange that minted it
// (recordCookies), and each must still hold.
//
// entry is EntryDigest (entryDigest) of the key's whole entry and of each
// of roles' whole definitions, as the document the marker is judged by
// gave them at the exchange (§B.11.9 gs, v0.82: a cookie is 403 where
// "the key its key: string names, or a key or role they came from, is
// gone or changes in any member"; §A.4 gs: for every marker, reads:{ns}
// included). "" is a key recorded before entries were kept, or one whose
// entry couldn't be told at the exchange: it never holds.
type gsKey struct {
	kid   string
	roles []string
	pub   string // the key's pub member, as its namespace document gives it
	entry string
}

// entryDigest is EntryDigest of §B.11.9 gs as the reference defines it,
// here and at the origin alike:
//
//	text(trunc160(sha256(canonical({ "key": K, "roles": R }))))
//
// in the id text form of §3.2, K being the whole entry of the key that
// verified the grant, as the judged namespace document gives it (for a
// branch, the effective key's source entry, §C.4), and R mapping each
// read role recorded to its whole definition there. "" for no key.
func entryDigest(key map[string]any, roles map[string]any) string {
	if key == nil {
		return ""
	}
	if roles == nil {
		roles = map[string]any{}
	}
	return ids.Of(jsonv.Canonical(map[string]any{"key": key, "roles": roles})).String()
}

// effectiveKey is the key named kid that verifies grants in cfg's
// namespace (§C.4), as the grant checker computes a namespace's keys: its
// own, or for a local branch its base's current key of that kid, which
// wins over the branch's, else the branch's own unless it copied that kid
// from its base at creation and the base has removed it since
// (copiedKids). ok is false for none.
func (ix *Index) effectiveKey(ctx context.Context, cfg *grantcheck.Config, kid string, depth int) (key grant.Key, ok bool, err error) {
	i := slices.IndexFunc(cfg.Keys, func(k grant.Key) bool { return k.Kid == kid })
	if cfg.Base == "" {
		if i < 0 {
			return grant.Key{}, false, nil
		}
		return cfg.Keys[i], true, nil
	}
	if depth >= maxChain {
		return grant.Key{}, false, nil
	}
	base, err := ix.checker.Config(ctx, cfg.Base)
	switch {
	case client.IsPurged(err), client.IsNotFound(err):
		return grant.Key{}, false, nil
	case err != nil:
		return grant.Key{}, false, lacksRead(cfg.Base, fmt.Errorf("the head of %s: %w", cfg.Base, err))
	}
	if key, ok, err := ix.effectiveKey(ctx, base, kid, depth+1); err != nil || ok {
		return key, ok, err
	}
	if i < 0 {
		return grant.Key{}, false, nil
	}
	copied, err := ix.copiedKids(ctx, cfg)
	if err != nil || copied[kid] {
		return grant.Key{}, false, err
	}
	return cfg.Keys[i], true, nil
}

// copiedKids are the kids local branch cfg copied from its base at
// creation: those of the base's document in force at the base's branch
// entry, as the grant checker finds them. It never changes, so it is kept.
func (ix *Index) copiedKids(ctx context.Context, cfg *grantcheck.Config) (map[string]bool, error) {
	k := cfg.NS + "\x00" + cfg.Base + "\x00" + cfg.BaseAt
	if m, ok := ix.copied.Load(k); ok {
		return m.(map[string]bool), nil
	}
	bh, err := ix.c.NSHead(ctx, cfg.Base)
	if err != nil {
		return nil, lacksRead(cfg.Base, fmt.Errorf("the head of %s: %w", cfg.Base, err))
	}
	entries, err := ix.c.NSLog(ctx, cfg.Base, bh.ID, cfg.BaseAt)
	if err != nil {
		return nil, lacksRead(cfg.Base, fmt.Errorf("the log of %s: %w", cfg.Base, err))
	}
	entry := ""
	for _, e := range entries {
		if e.Kind == "branch" && e.Name == cfg.NS && e.Remote == nil {
			entry = e.ID
			break
		}
	}
	if entry == "" {
		return nil, fmt.Errorf("no branch entry for %s in %s", cfg.NS, cfg.Base)
	}
	doc, err := ix.docAt(ctx, cfg.Base, entry)
	if err != nil {
		return nil, err
	}
	m := map[string]bool{}
	keys, _ := doc["keys"].([]any)
	for _, kv := range keys {
		if e, ok := kv.(map[string]any); ok {
			if kid, ok := e["kid"].(string); ok {
				m[kid] = true
			}
		}
	}
	ix.copied.Store(k, m)
	return m, nil
}

// entryOf is the entry digest (entryDigest) of the key named kid and of
// roles in cfg's namespace, with the key (effectiveKey); ok is false, and
// the digest "", where the key or one of the roles is gone.
func (ix *Index) entryOf(ctx context.Context, cfg *grantcheck.Config, kid string, roles []string) (entry string, key grant.Key, ok bool, err error) {
	key, ok, err = ix.effectiveKey(ctx, cfg, kid, 0)
	if err != nil || !ok || key.Raw == nil {
		return "", key, false, err
	}
	defs, _ := cfg.Doc["roles"].(map[string]any)
	rs := make(map[string]any, len(roles))
	for _, r := range roles {
		def, ok := defs[r]
		if !ok {
			return "", key, false, nil
		}
		rs[r] = def
	}
	return entryDigest(key.Raw, rs), key, true, nil
}

// entryHolds reports whether k, a key a cookie came from, is still, in
// the document cfg, the key the exchange recorded: there, listing read,
// with the pub it had, and with its whole entry and each of its roles'
// whole definitions digesting to k.entry (§B.11.9 gs, v0.82: "gone or
// changes in any member"), whether or not a scope digest reads the member
// that changed: a changed sub, groups, attrs, maxTtl, requireAt or can of
// the key, or a role's can or rules. A key recorded without its entry or
// its pub never holds. The key is returned for gsKeyHolds.
func (ix *Index) entryHolds(ctx context.Context, cfg *grantcheck.Config, k gsKey) (grant.Key, bool, error) {
	entry, key, ok, err := ix.entryOf(ctx, cfg, k.kid, k.roles)
	if err != nil || !ok {
		return key, false, err
	}
	return key, k.entry != "" && entry == k.entry && k.pub != "" && keyPub(key) == k.pub && key.Lists("read"), nil
}

// exchangeEntry is the entry digest an exchange records for the key k
// that verified v in ns, whose access is a (gsKey.entry): of the document
// a read under the cookie is judged by, ns's at its head, and for a g:
// marker the one at its checkpoint (storedFview). It is "", which never
// holds, so that the reader exchanges again, where it can't vouch that
// the grant was verified by that very entry: the checker's document moved
// during the exchange (head is the one read before v was verified), the
// key that verified v isn't the entry that document gives, or the
// checkpoint's document gives the key or a role otherwise than the head's,
// the index not having applied a change yet.
func (ix *Index) exchangeEntry(ctx context.Context, ns, head string, a *access, v *grant.Verified, k gsKey) string {
	cfg, err := ix.checker.Config(ctx, ns)
	if err != nil || cfg.Head != head {
		return ""
	}
	entry, key, ok, err := ix.entryOf(ctx, cfg, k.kid, k.roles)
	if err != nil || !ok || !bytes.Equal(jsonv.Canonical(key.Raw), jsonv.Canonical(v.Key.Raw)) {
		return ""
	}
	if a.cov != nil {
		doc, err := ix.docAt(ctx, ns, a.cov.cp.reads[ns])
		if err != nil {
			return ""
		}
		at, err := grantcheck.ParseConfig(ns, "", doc)
		if err != nil {
			return ""
		}
		if e, _, ok, err := ix.entryOf(ctx, at, k.kid, k.roles); err != nil || !ok || e != entry {
			return ""
		}
	}
	return entry
}

// markerRecOf is what a's marker stands for, a's grant being v: its
// filter, the key it came from, for a scope marker as for a g: one (§A.4:
// a cookie is 403 "where a marker's key, rules or roles would end a gs
// cookie"), and a g: marker's subjects.
func markerRecOf(a *access, v *grant.Verified) *markerRec {
	rec := &markerRec{f: a.filter} // nil for reads:{ns}
	rec.key.kid, rec.key.pub = v.Key.Kid, keyPub(*v.Key)
	for r := range grantcheck.ScopeInputOf(v).Roles {
		rec.key.roles = append(rec.key.roles, r)
	}
	slices.Sort(rec.key.roles)
	if a.cov != nil {
		rec.subjects = a.cov.subjects
	}
	return rec
}

// scopeMarker is the marker reads:{ns}:scope:{digest} of a reader of
// uncovered ns whose reads there have grantcheck.ReadsScope digest d,
// through the key with kid and pub (§A.4): its digest covers d and the
// key's key: string (catvis.KeySubject, §B.11.9 gs), so readers through
// two keys with the same rules never share a marker, its gs, its edge
// filter or its cookie prefix. A gs's scope: subject is the same digest
// (§B.11.9 gs: "scope:{digest} of §A.4's marker"), at the origin too.
func scopeMarker(ns, d, kid, pub string) string {
	return "reads:" + ns + ":scope:" + scopeKeyDigest(d, kid, pub)
}

// scopeKeyDigest is scopeMarker's digest: of d and the key's key: string
// (catvis.ScopeKeyDigest).
func scopeKeyDigest(d, kid, pub string) string { return catvis.ScopeKeyDigest(d, kid, pub) }

// keyPub is k's pub member as the namespace document gives it, "" if it
// has none (§B.11.9 gs: "accepted only while the base has it with the
// same pub", §C.4), compared as given.
func keyPub(k grant.Key) string {
	pub, _ := k.Raw["pub"].(string)
	return pub
}

// keptFilter is a markerRec the service holds in memory (Index.filters),
// with the Unix time its last edge grant known here expires.
type keptFilter struct {
	f   *markerRec
	exp int64
}

// cookieRec is one edge grant an exchange is about to mint: what each
// marker of its subject set stands for and the keys this exchange
// vouches for it with (filters), and when it expires, which recordCookies
// may move earlier.
type cookieRec struct {
	filters map[string]*markerRec
	exp     time.Time
}

// errNoSlot is an exchange for which no second is left to tell its cookie
// from those of other exchanges (recordCookies).
var errNoSlot = errors.New("no exp left for an edge grant of its own")

// gsKeyRow is a key as edge_gs_keys keeps it: its roles as a JSON array.
type gsKeyRow struct{ kid, roles, pub, entry string }

// recordCookies records what the markers of the edge grants recs, minted
// at now, stand for (edge_filters, and for g: markers edge_gs), and the
// keys each cookie came from (edge_gs_keys), and drops what the last edge
// grant of has expired, from the database and from memory, as
// svcedge.Store.Record does for subject sets. It sets each rec's exp to
// the one its cookie must carry.
//
// A cookie carries its prefix and exp alone, so cookies of one marker
// that expire at the same second are one cookie, judged by the keys
// recorded for that marker and exp (gsKeysAt), each of which must hold.
// What is recorded there is therefore only ever what every exchange that
// minted that cookie vouched for, the same keys with the same entries
// (§A.4 gs, §B.11.9 gs): a row is never changed once written, and an
// exchange whose keys or entries differ from those recorded for its
// marker and exp, in any of its markers, mints a cookie that expires a
// second earlier, and so on until it finds a second that is free or
// holds exactly its own keys. So a cookie that ended, its key or a role
// having changed, isn't vouched for again by any later exchange, the
// same reader's or another's, whose cookie is another one; a reader who
// "exchanges again" reads under hers whatever an earlier state of the
// rules left behind; and readers through different keys never share a
// cookie, so that one key's change ends only the cookies it minted.
// errNoSlot where no such second is left after now: nothing is recorded.
//
// A document changed and then changed back gives a key the entry it had:
// a cookie minted before holds again, as its grant verifies again.
func (ix *Index) recordCookies(ctx context.Context, recs []*cookieRec, now time.Time) error {
	tx, err := ix.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// The first statement writes: the transaction holds the database's
	// write lock from here, and no other exchange records between the
	// reads of a slot below and the rows written to it.
	for _, q := range []string{`DELETE FROM edge_filters WHERE exp <= ?`, `DELETE FROM edge_gs WHERE exp <= ?`, `DELETE FROM edge_gs_keys WHERE exp <= ?`} {
		if _, err := tx.ExecContext(ctx, q, now.Unix()); err != nil {
			return err
		}
	}
	enc := func(xs []string) string {
		l := make([]any, len(xs))
		for i, x := range xs {
			l[i] = x
		}
		return string(jsonv.Canonical(l))
	}
	// taken is what each marker's cookies that are still live came from,
	// by exp, with what this exchange adds.
	taken := map[string]map[int64][]gsKeyRow{}
	slots := func(m string) (map[int64][]gsKeyRow, error) {
		if by, ok := taken[m]; ok {
			return by, nil
		}
		rows, err := tx.QueryContext(ctx, `SELECT exp, kid, roles, pub, entry FROM edge_gs_keys WHERE marker = ? ORDER BY exp, kid, roles, pub`, m)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		by := map[int64][]gsKeyRow{}
		for rows.Next() {
			var (
				exp int64
				k   gsKeyRow
			)
			if err := rows.Scan(&exp, &k.kid, &k.roles, &k.pub, &k.entry); err != nil {
				return nil, err
			}
			by[exp] = append(by[exp], k)
		}
		taken[m] = by
		return by, rows.Err()
	}
	for _, rec := range recs {
		// What this exchange vouches for, per marker: each key once, in
		// the order of the rows, and without an entry (which never
		// holds) where two of its grants found it with different ones.
		want := map[string][]gsKeyRow{}
		for m, f := range rec.filters {
			var ks []gsKeyRow
			for _, k := range append([]gsKey{f.key}, f.also...) {
				row := gsKeyRow{k.kid, enc(k.roles), k.pub, k.entry}
				i := slices.IndexFunc(ks, func(o gsKeyRow) bool { return o.kid == row.kid && o.roles == row.roles && o.pub == row.pub })
				switch {
				case i < 0:
					ks = append(ks, row)
				case ks[i].entry != row.entry:
					ks[i].entry = ""
				}
			}
			slices.SortFunc(ks, func(a, b gsKeyRow) int {
				return cmp.Or(strings.Compare(a.kid, b.kid), strings.Compare(a.roles, b.roles), strings.Compare(a.pub, b.pub))
			})
			want[m] = ks
		}
		exp := rec.exp.Unix()
	next:
		for ; exp > now.Unix(); exp-- {
			for m, ks := range want {
				by, err := slots(m)
				if err != nil {
					return err
				}
				if had := by[exp]; len(had) > 0 && !slices.Equal(had, ks) {
					continue next
				}
			}
			break
		}
		if exp <= now.Unix() {
			return errNoSlot
		}
		rec.exp = time.Unix(exp, 0)
		for m, f := range rec.filters {
			if f.f != nil {
				if _, err := tx.ExecContext(ctx, `INSERT INTO edge_filters (marker, filter, exp) VALUES (?, ?, ?)
					ON CONFLICT (marker) DO UPDATE SET filter = excluded.filter, exp = max(exp, excluded.exp)`, m, f.f.Encode(), exp); err != nil {
					return err
				}
			}
			if f.subjects != nil {
				// edge_gs's kid, roles and pub (migrations 005, 006) are the
				// latest exchange's, kept only because they are NOT NULL: a
				// cookie is judged by the keys in edge_gs_keys (migrations
				// 007, 011).
				if _, err := tx.ExecContext(ctx, `INSERT INTO edge_gs (marker, subjects, kid, roles, pub, exp) VALUES (?, ?, ?, ?, ?, ?)
				ON CONFLICT (marker) DO UPDATE SET subjects = excluded.subjects, kid = excluded.kid, roles = excluded.roles, pub = excluded.pub, exp = max(exp, excluded.exp)`,
					m, enc(f.subjects), f.key.kid, enc(f.key.roles), f.key.pub, exp); err != nil {
					return err
				}
			}
			// The keys the cookie of m expiring at exp came from
			// (gsKeysAt): written once, and the same ever after.
			if len(taken[m][exp]) > 0 {
				continue
			}
			for _, k := range want[m] {
				if _, err := tx.ExecContext(ctx, `INSERT INTO edge_gs_keys (marker, exp, kid, roles, pub, entry) VALUES (?, ?, ?, ?, ?, ?)`,
					m, exp, k.kid, k.roles, k.pub, k.entry); err != nil {
					return err
				}
			}
			taken[m][exp] = want[m]
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	ix.fmu.Lock()
	for m, k := range ix.filters {
		if k.exp <= now.Unix() {
			delete(ix.filters, m)
		}
	}
	for _, rec := range recs {
		for m, f := range rec.filters {
			if f.f != nil {
				ix.filters[m] = keptFilter{f: f, exp: max(ix.filters[m].exp, rec.exp.Unix())}
			}
		}
	}
	ix.fmu.Unlock()
	return nil
}

// recordFilters records what the markers of one edge grant minted at now
// that expires at exp stand for (recordCookies).
func (ix *Index) recordFilters(ctx context.Context, filters map[string]*markerRec, exp, now time.Time) error {
	return ix.recordCookies(ctx, []*cookieRec{{filters: filters, exp: exp}}, now)
}

// filter is what marker m stands for, recorded when an edge grant for it
// was minted, by this instance or another on the database. A g: marker
// without its subjects is unknown. The keys a g: marker's cookies came
// from are read by gsKeys, never from memory: an exchange at another
// instance adds to them.
func (ix *Index) filter(ctx context.Context, m string) (*markerRec, bool) {
	ix.fmu.Lock()
	k, ok := ix.filters[m]
	ix.fmu.Unlock()
	if ok {
		return k.f, true
	}
	var (
		s        string
		exp      int64
		subjects sql.NullString
	)
	if err := ix.db.QueryRowContext(ctx, `SELECT f.filter, f.exp, g.subjects FROM edge_filters f
		LEFT JOIN edge_gs g ON g.marker = f.marker WHERE f.marker = ?`, m).Scan(&s, &exp, &subjects); err != nil {
		return nil, false
	}
	f, err := grantcheck.DecodeReadFilter(s)
	if err != nil {
		return nil, false
	}
	rec := &markerRec{f: f}
	if subjects.Valid {
		var ok bool
		if rec.subjects, ok = decodeStrings(subjects.String); !ok {
			return nil, false
		}
	} else if isGMarker(m) {
		return nil, false
	}
	ix.fmu.Lock()
	ix.filters[m] = keptFilter{f: rec, exp: exp}
	ix.fmu.Unlock()
	return rec, true
}

// gsKeys is every key the live cookies of marker m came from at now
// (edge_gs_keys), each once, without its entry, recorded by any instance
// on the database.
func (ix *Index) gsKeys(ctx context.Context, m string, now time.Time) ([]gsKey, error) {
	return ix.gsKeyRows(ctx, `SELECT DISTINCT kid, roles, pub, '' FROM edge_gs_keys WHERE marker = ? AND exp > ? ORDER BY kid, roles, pub`, m, now.Unix())
}

// gsKeysAt is every key the cookie of marker m that expires at exp (a
// Unix time, its claim) came from, recorded by any instance on the
// database: every exchange that minted that cookie recorded the same
// (recordCookies), and each must still hold. A cookie minted before migration 011 has none,
// one whose key was recorded without its entry has entry "", and one
// without its pub has pub "", which no key has: readsKeysHold,
// scopeKeysHold and storedFview refuse all three, until the reader
// exchanges again.
func (ix *Index) gsKeysAt(ctx context.Context, m string, exp int64) ([]gsKey, error) {
	return ix.gsKeyRows(ctx, `SELECT kid, roles, pub, entry FROM edge_gs_keys WHERE marker = ? AND exp = ? ORDER BY kid, roles, pub`, m, exp)
}

func (ix *Index) gsKeyRows(ctx context.Context, q, m string, t int64) ([]gsKey, error) {
	rows, err := ix.db.QueryContext(ctx, q, m, t)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []gsKey
	for rows.Next() {
		var (
			k     gsKey
			roles string
		)
		if err := rows.Scan(&k.kid, &roles, &k.pub, &k.entry); err != nil {
			return nil, err
		}
		var ok bool
		if k.roles, ok = decodeStrings(roles); !ok {
			return nil, errors.New("edge_gs_keys: roles of " + m + " aren't a JSON array of strings")
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// decodeStrings reads a JSON array of strings, as recordFilters writes it.
func decodeStrings(s string) ([]string, bool) {
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

// isGMarker reports whether m is a marker reads:{ns}:g:{gs} (§A.4).
func isGMarker(m string) bool {
	rest, ok := strings.CutPrefix(m, "reads:")
	if !ok {
		return false
	}
	_, gs, ok := strings.Cut(rest, ":g:")
	return ok && !strings.Contains(gs, ":")
}

// nsPrefix is the prefix of a subject set's results of ns, refsPrefix of
// its answers across namespaces: every at, and the head pointer under the
// prefix (§B.11.5).
func nsPrefix(ns, gs string) string { return "/" + ns + "/g/" + gs }
func refsPrefix(gs string) string   { return "/_refs/g/" + gs }

// edgeGS parses one of the service's prefixes, /{ns}/g/{gs} or (ns "")
// /_refs/g/{gs}: the only prefixes its key vouches for (§C.5.3). A
// namespace named r or ns has none, since its prefix would lie under the
// core's.
func edgeGS(p string) (ns, gs string, ok bool) {
	segs := strings.Split(p, "/")
	if len(segs) != 4 || segs[0] != "" || segs[2] != "g" {
		return "", "", false
	}
	if _, err := ids.Parse(segs[3]); err != nil {
		return "", "", false
	}
	switch {
	case segs[1] == "_refs":
		return "", segs[3], true
	case validNS(segs[1]) && segs[1] != "r" && segs[1] != "ns":
		return segs[1], segs[3], true
	}
	return "", "", false
}

// edgeClaims is the edge grant the service minted that a GET or HEAD
// without Authorization, not even an empty one (§C.5.3), carries, covering
// its path, if any.
func (ix *Index) edgeClaims(r *http.Request) *edge.Claims {
	if ix.opt.EdgeGrants == nil || len(r.Header.Values("Authorization")) > 0 {
		return nil
	}
	return ix.opt.EdgeGrants.FromRequest(r, ix.opt.Now())
}

// errUnknownSet is a read under an edge grant whose subject set, or the
// filter of one of its markers, the service doesn't know: minted by an
// instance with another database, or forgotten once expired.
var errUnknownSet = &grant.AuthError{Status: 401, Msg: "an edge grant for a subject set this service doesn't know: exchange the grant again"}

// cookieAccess is access to private namespace ns under one of the
// service's edge grants for /{ns}/g/{gs} (ok false without one): the
// marker its gs stands for, read as a grant with that marker would be.
func (ix *Index) cookieAccess(ctx context.Context, ns string, r *http.Request) (*access, bool, error) {
	cl := ix.edgeClaims(r)
	if cl == nil {
		return nil, false, nil
	}
	cns, gs, ok := edgeGS(cl.Prefix)
	if !ok || cns != ns {
		return nil, false, nil
	}
	subs, ok := ix.edge.Subjects(ctx, gs)
	if !ok || len(subs) != 1 {
		return nil, true, errUnknownSet
	}
	a, err := ix.markerAccess(ctx, ns, subs[0], cl.Exp)
	if a != nil {
		a.gs = gs
	}
	return a, true, err
}

// markerAccess is access to private namespace ns of a reader with marker m
// under an edge grant that expires at exp: reads:{ns} reads it whole,
// reads:{ns}:scope:… as its filter allows while ns is still uncovered
// (stillUncovered), reads:{ns}:g:… as its subjects and filter see ns at
// its current checkpoint, which must still be covered (§B.11.9,
// storedFview), each only while every key that cookie came from, and the
// roles its grant read through, are as the exchange recorded them (§A.4
// gs, v0.82: "reads:{ns} markers included"; readsKeysHold, scopeKeysHold,
// storedFview); any other marker reads none of it.
func (ix *Index) markerAccess(ctx context.Context, ns, m string, exp int64) (*access, error) {
	switch {
	case m == "reads:"+ns:
		if err := ix.readsKeysHold(ctx, ns, m, exp); err != nil {
			return nil, err
		}
		return &access{all: true, marker: m, cookie: true}, nil
	case strings.HasPrefix(m, "reads:"+ns+":scope:"):
		f, ok := ix.filter(ctx, m)
		if !ok {
			return nil, errUnknownSet
		}
		if err := ix.stillUncovered(ctx, ns); err != nil {
			return nil, err
		}
		if err := ix.scopeKeysHold(ctx, ns, m, f, exp); err != nil {
			return nil, err
		}
		return &access{marker: m, filter: f.f, allow: f.f.Allows, cookie: true}, nil
	case strings.HasPrefix(m, "reads:"+ns+":g:"):
		f, ok := ix.filter(ctx, m)
		if !ok {
			return nil, errUnknownSet
		}
		a := &access{marker: m, filter: f.f, cookie: true,
			derive: func(ctx context.Context, cp *fcp) (*fview, error) { return ix.storedFview(ctx, cp, m, f, exp) }}
		switch err := ix.cover(ctx, a, ns, ""); {
		case errors.Is(err, errPurgedNS):
			// Answered 410 once past the read check (§8.5), which a
			// cookie that has ended doesn't pass: it reads nothing.
			if err := ix.purgedGKeysHold(ctx, ns, m, f, exp); err != nil {
				return nil, err
			}
			a.derive, a.allow = nil, func(string) bool { return false }
		case err != nil:
			return nil, err
		}
		return a, nil
	}
	return nil, &grant.AuthError{Status: 403, Msg: "the edge grant doesn't read this namespace"}
}

// keysHold checks the cookie of marker m of ns that expires at exp
// against ns's document at its head (its effective keys, §C.4):
// errRulesChanged unless every key that cookie came from (gsKeysAt) is
// still there with the pub it had and lists read, with its whole entry
// and its roles' whole definitions as the exchange recorded them
// (entryHolds; §B.11.9 gs, v0.82: "gone or changes in any member"), and
// passes also, if any. A cookie with no key recorded, minted before
// migration 011, is refused: the reader exchanges again. A document that
// can't be read is an error, never a read.
//
// A purged namespace is judged like any other, by the document it had
// when it was purged, which the core still serves: the 410 and its head
// are for a request that passes the read check (§8.5), and a cookie that
// had ended before the purge doesn't. Where the core answers 410 for the
// document too (a sealed namespace, §8.5), nothing is left to judge the
// keys by: a cookie passes with every key recorded with its entry and
// pub, as a cookie that never held isn't (purgedKeysHold), and so does
// one whose key or role changed after its exchange and before the purge,
// which gets the 410 and its head until it expires.
func (ix *Index) keysHold(ctx context.Context, ns, m string, exp int64, also func(cfg *grantcheck.Config, key grant.Key, k gsKey) bool) error {
	recorded, err := ix.gsKeysAt(ctx, m, exp)
	if err != nil {
		return err
	}
	if len(recorded) == 0 {
		return errRulesChanged
	}
	cfg, err := ix.checker.Config(ctx, ns)
	if client.IsPurged(err) {
		return purgedKeysHold(recorded)
	}
	if err != nil {
		return err
	}
	for _, k := range recorded {
		key, ok, err := ix.entryHolds(ctx, cfg, k)
		if err != nil {
			return err
		}
		if !ok || also != nil && !also(cfg, key, k) {
			return errRulesChanged
		}
	}
	return nil
}

// purgedKeysHold is keysHold where the namespace's document is 410 too
// (§8.5): errRulesChanged for a cookie with no key recorded, or with one
// recorded without its entry or its pub, which never held.
func purgedKeysHold(recorded []gsKey) error {
	if len(recorded) == 0 || slices.ContainsFunc(recorded, func(k gsKey) bool { return k.entry == "" || k.pub == "" }) {
		return errRulesChanged
	}
	return nil
}

// scopeKeysHold checks a cookie for scope marker m of ns, whose record is
// rec, as §B.11.9 gs ends a gs cookie (§A.4: "a cookie is 403 until the
// reader exchanges again ... where a marker's key, rules or roles would
// end a gs cookie"): keysHold, each role a key digested still existing
// and listing read, and the scope digest over the current rules, with
// rec's block rules and principal and the key's key: string, still m's
// (scopeMarker).
func (ix *Index) scopeKeysHold(ctx context.Context, ns, m string, rec *markerRec, exp int64) error {
	return ix.keysHold(ctx, ns, m, exp, func(cfg *grantcheck.Config, key grant.Key, k gsKey) bool {
		return gsKeyHolds(cfg, []grant.Key{key}, rec.f, k, func(d string) bool { return scopeMarker(ns, d, k.kid, k.pub) == m })
	})
}

// readsKeysHold checks a cookie for marker reads:{ns}, m, that expires at
// exp, as scopeKeysHold checks a scope marker's (§A.4 gs, v0.82: a cookie
// is 403 "where a marker's key, rules or roles would end a gs cookie
// (§B.11.9 gs), its key being the one that verified the grant in {ns},
// reads:{ns} markers included"): keysHold. Readers through several keys
// share the marker, never a cookie (recordCookies).
func (ix *Index) readsKeysHold(ctx context.Context, ns, m string, exp int64) error {
	return ix.keysHold(ctx, ns, m, exp, nil)
}

// purgedGKeysHold checks a cookie for g: marker m of purged ns, whose record
// is rec, which has no checkpoint left to be judged at (storedFview): as
// there, by ns's document at its head (keysHold).
func (ix *Index) purgedGKeysHold(ctx context.Context, ns, m string, rec *markerRec, exp int64) error {
	if slices.Contains(rec.subjects, catvis.Partial) {
		return errPartial
	}
	return ix.keysHold(ctx, ns, m, exp, func(cfg *grantcheck.Config, key grant.Key, k gsKey) bool {
		return gsKeyHolds(cfg, []grant.Key{key}, rec.f, k, func(d string) bool {
			return slices.Contains(rec.subjects, catvis.ScopePrefix+scopeKeyDigest(d, k.kid, k.pub))
		})
	})
}

// errCoveredNow refuses a cookie for marker reads:{ns}:scope:… once
// §B.11.9 covers ns: a partial reader's marker there is reads:{ns}:g:{gs},
// its hits filtered by visibility (§A.4), which rules alone don't do.
var errCoveredNow = &grant.AuthError{Status: 403, Msg: "the namespace is read filtered now: exchange the grant again (§B.11.9)"}

// stillUncovered checks that §B.11.9 doesn't cover ns at the index's
// committed checkpoint, as when a scope marker of it was issued: else
// errCoveredNow; and that ns isn't one a partial reader has no marker in
// (catalogShaped): else errNoMarker. Before the index's first checkpoint
// of a namespace that may be covered once it has, its coverage can't be
// told: errNotReached, as for a grant (grantAccess). A purged one passes,
// answered 410 past the read check (§8.5).
func (ix *Index) stillUncovered(ctx context.Context, ns string) error {
	id, purged, err := ix.committed(ctx, ns)
	switch {
	case err != nil:
		return err
	case purged:
		return nil
	case id == "":
		if may, err := ix.mayBeCovered(ctx, ns); err != nil || may {
			return errors.Join(errNotReached, err)
		}
		return nil
	}
	cp, err := ix.checkpoint(ctx, ns, id)
	switch {
	case err != nil:
		return err
	case cp != nil:
		return errCoveredNow
	}
	// One that could be covered by its shape gives a partial reader no
	// marker (§A.4), so no cookie of one reads it.
	if shaped, err := ix.catalogShaped(ctx, ns); err != nil {
		return err
	} else if shaped {
		return errNoMarker
	}
	return nil
}

// refsCookieReader is the reader of /_refs under one of the service's
// edge grants for /_refs/g/{gs} (ok false without one): its subject set,
// whose markers decide which private namespaces it sees and how
// (markerAccess); every public one is seen too. A namespace a marker
// names whose document the service can't read is 502, as one a grant
// names.
func (ix *Index) refsCookieReader(ctx context.Context, r *http.Request, reached map[string]string) (*refsReader, bool, error) {
	cl := ix.edgeClaims(r)
	if cl == nil {
		return nil, false, nil
	}
	cns, gs, ok := edgeGS(cl.Prefix)
	if !ok || cns != "" {
		return nil, false, nil
	}
	subs, ok := ix.edge.Subjects(ctx, gs)
	if !ok {
		return nil, true, errUnknownSet
	}
	rd := &refsReader{gs: gs, public: true, allow: map[string]func(string) bool{}, covs: map[string]*access{}}
	for _, ns := range ix.refsNamespaces() {
		if _, ok := reached[ns]; !ok || ix.keys.Skipped(ns) != "" {
			continue
		}
		i := slices.IndexFunc(subs, func(m string) bool {
			return m == "reads:"+ns || strings.HasPrefix(m, "reads:"+ns+":scope:") || strings.HasPrefix(m, "reads:"+ns+":g:")
		})
		cfg, err := ix.checker.Config(ctx, ns)
		switch {
		case client.IsPurged(err):
			continue
		case err != nil && i >= 0:
			return nil, true, err
		case err != nil:
			continue
		case ix.publicFor(ctx, ns, cfg):
			rd.nss = append(rd.nss, ns)
			rd.pub = append(rd.pub, ns)
			continue
		case i < 0:
			continue
		}
		a, err := ix.markerAccess(ctx, ns, subs[i], cl.Exp)
		if err != nil {
			return nil, true, err
		}
		if !a.all {
			rd.allow[ns] = a.allow
		}
		if a.cov != nil {
			rd.covs[ns] = a
		}
		rd.public = false
		rd.nss = append(rd.nss, ns)
	}
	return rd, true, nil
}

// purgedRead is the read check of a request of purged namespace ns, whose
// document the core answered 410 purged (cfgErr): with a grant, or none,
// the core's (grantcheck.PurgedRead); under one of the service's edge
// grants for ns's subject set, which the service knows, it passes, and
// the head is cfgErr's (§8.5).
func (ix *Index) purgedRead(ctx context.Context, ns string, r *http.Request, cfgErr error) (string, error) {
	if cl := ix.edgeClaims(r); cl != nil {
		if cns, gs, ok := edgeGS(cl.Prefix); ok && cns == ns {
			subs, known := ix.edge.Subjects(ctx, gs)
			if !known || len(subs) != 1 {
				return "", errUnknownSet
			}
			// Its keys can't be judged again (keysHold): a cookie
			// recorded with none, or with one that never held, is 403.
			recorded, err := ix.gsKeysAt(ctx, subs[0], cl.Exp)
			if err == nil {
				err = purgedKeysHold(recorded)
			}
			if err != nil {
				return "", err
			}
			if ae, ok := client.AsAPIError(cfgErr); ok && ae.Head() != "" {
				return ae.Head(), nil
			}
		}
	}
	return ix.checker.PurgedRead(ctx, ns, bearer(r))
}

// serveEdgeGrants is /edge-grants on the service's origin: POST issues,
// DELETE withdraws. Either is no-store. Without EdgeGrants, both are 404
// not_offered.
func (ix *Index) serveEdgeGrants(w http.ResponseWriter, r *http.Request) {
	telemetry.SetRoute(r, "/edge-grants")
	w.Header().Set("Cache-Control", "no-store")
	switch {
	case r.Method != http.MethodPost && r.Method != http.MethodDelete:
		w.Header().Set("Allow", "GET, HEAD, POST, DELETE")
		writeErr(w, http.StatusMethodNotAllowed, "bad_input", "method not allowed")
	case ix.opt.EdgeGrants == nil:
		writeErr(w, http.StatusNotFound, "not_offered", "this service mints no edge grants")
	case r.Method == http.MethodDelete:
		// The core's DELETE /edge-grants takes only core prefixes, so the
		// service withdraws its own (§C.5.3, §C.5.4).
		svcedge.Withdraw(w, r, ix.opt.EdgeGrants, func(p string) bool { _, _, ok := edgeGS(p); return ok },
			"/{ns}/g/{gs} or /_refs/g/{gs} (§A.4, §B.11.5)")
	default:
		ix.issueEdgeGrants(w, r)
	}
}

// maxPrefixes is how many distinct prefixes one exchange may give
// (§C.5.2).
const maxPrefixes = 100

// exchanged is what one grant of an exchange gives: its edge grants, the
// markers behind each gs, what each marker stands for and the key it came
// from (markerRec, for every marker), and the exchangeRate bucket of its
// principal.
type exchanged struct {
	issues   []svcedge.Issue
	subjects map[string][]string
	filters  map[string]*markerRec
	bucket   string
}

// issueEdgeGrants is POST /edge-grants (§A.4, §B.11.5, following §C.5.2's
// issuance): with the grant in Authorization, or 1 to svcedge.MaxGrants
// grants as { "grants": [ … ] } in an application/json body (415
// otherwise, svcedge.Bearers), it answers 200 { prefixes, exp } and one
// Set-Cookie per prefix. Each grant gives, for every private namespace
// the service follows that it names, /{ns}/g/{gs} of the reader's
// marker there (exchangeGrant), and /_refs/g/{gs} of its markers in those
// the service has reached, each lasting until the grant's exp or the
// cookies' TTL (15 minutes at most), whichever is sooner. A prefix
// several grants give gets one cookie, lasting as long as the longest,
// and exp is the earliest. Within a grant each namespace is judged alone,
// one it gets no marker in left out (exchangeGrant, §A.4); across grants
// it answers all or nothing (§C.5.2): a grant over grantSize or
// rulesPerGrant is 413 limit (§C.8); a grant left with no edge grant is
// refused 401 if any such is 401, else 403; else, where a namespace
// document a grant names, or the chain a requireAt key names, can't be
// read, 502 if any such failure is lasting and 503 behind only if every
// one is for now (worseUpstream; §C.4, §C.5.2); once none is, a grant left with
// no edge grant whose only refusals are purges is 410 purged, with ns and
// head naming the first in the order the grants and their root blocks
// list them (§8.5).
// More than maxPrefixes prefixes is 400.
// Once nothing is refused, it draws one token from the exchangeRate
// bucket of each distinct principal among the grants (ExchangeRate,
// §6.6), shared with the instances on its database (svcedge.Store), and
// is 429 (code "rate", limit "exchangeRate", with Retry-After) while any
// is empty. While the core's authentication is disabled (§1), it is 404
// not_offered, before the body is read; it takes no query parameter (400,
// §7). Cookies are Secure, HttpOnly and SameSite as EdgeGrants says.
func (ix *Index) issueEdgeGrants(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	// Whether the core's authentication is on is what its root says now
	// (authOff: read again once CheckerTTL has passed), never what an
	// earlier read said (§B.11.9 Where, v0.82). While the root can't be
	// read the exchange goes on as with authentication on: it mints only
	// for grants that verify, and a namespace whose coverage the root
	// decides answers 503 or 502 for the whole exchange (coverage).
	if off, err := ix.authOff(ctx); err != nil {
		ix.opt.Logf("index: reading the core's root: %v", err)
	} else if off {
		writeErr(w, http.StatusNotFound, "not_offered", "the core runs with authentication disabled: there are no edge grants (§C.5)")
		return
	}
	if r.URL.RawQuery != "" {
		writeErr(w, http.StatusBadRequest, "bad_input", "POST /edge-grants takes no query parameters (§7)")
		return
	}
	bearers, refusal := svcedge.Bearers(r, svcedge.DefaultGrantSize)
	if refusal != nil {
		refusal.Write(w)
		return
	}
	if len(bearers) == 0 {
		w.Header().Set("WWW-Authenticate", "Bearer")
		writeErr(w, http.StatusUnauthorized, "unauthenticated", "missing grant")
		return
	}
	now := ix.opt.Now()
	reached, err := ix.refsCheckpoints(ctx, ix.db, ix.refsNamespaces())
	if err != nil {
		ix.opt.Logf("index: checkpoints for an exchange: %v", err)
		writeErr(w, http.StatusInternalServerError, "internal", "cannot read the checkpoints")
		return
	}
	var (
		exs    []*exchanged
		limit  *grantcheck.LimitError
		denied *grant.AuthError
		upErr  error
		purged *purgedNS
	)
	for _, b := range bearers {
		ex, pn, err := ix.exchangeGrant(ctx, b, reached, now)
		var le *grantcheck.LimitError
		var ae *grant.AuthError
		_, chain := chainErr(err)
		switch {
		case errors.As(err, &le):
			if limit == nil {
				limit = le
			}
		case chain:
			// A requireAt chain the verifier can't read: 503 or 502,
			// never a refusal (§C.4, writeUpstreamErr).
			upErr = worseUpstream(upErr, err)
		case errors.As(err, &ae):
			if denied == nil || ae.Status == http.StatusUnauthorized && denied.Status != http.StatusUnauthorized {
				denied = ae
			}
		case err != nil:
			upErr = worseUpstream(upErr, err)
		case pn != nil:
			if purged == nil {
				purged = pn
			}
		default:
			exs = append(exs, ex)
		}
	}
	switch {
	case limit != nil:
		svcedge.Limit(limit.Limit, limit.Measured, limit.Max).Write(w)
		return
	case denied != nil:
		code := "forbidden"
		if denied.Status == http.StatusUnauthorized {
			code = "unauthenticated"
			w.Header().Set("WWW-Authenticate", "Bearer")
		}
		writeErr(w, denied.Status, code, denied.Msg)
		return
	case upErr != nil:
		ix.writeUpstreamErr(w, "exchange", upErr, "cannot read a namespace configuration")
		return
	case purged != nil:
		purged.write(w)
		return
	}
	var issues []svcedge.Issue
	subjects := map[string][]string{}
	filters := map[string]*markerRec{}
	var keys []string
	for _, ex := range exs {
		issues = append(issues, ex.issues...)
		for gs, subs := range ex.subjects {
			subjects[gs] = subs
		}
		for m, f := range ex.filters {
			if had, ok := filters[m]; ok {
				// Another grant of this exchange got m through its own
				// key: recorded beside the first.
				had.also = append(append(had.also, f.key), f.also...)
				continue
			}
			filters[m] = f
		}
		if !slices.Contains(keys, ex.bucket) {
			keys = append(keys, ex.bucket)
		}
	}
	issues = svcedge.Merge(issues)
	if len(issues) > maxPrefixes {
		writeErr(w, http.StatusBadRequest, "bad_input", "the grants give more than 100 distinct prefixes (§C.5.2)")
		return
	}
	// One token per request, from each distinct principal's bucket,
	// however many grants it carries (§C.5.2).
	switch wait, err := ix.edge.Draw(ctx, now, ix.opt.ExchangeRate, keys); {
	case err != nil:
		ix.opt.Logf("index: drawing from the exchangeRate buckets: %v", err)
		writeErr(w, http.StatusInternalServerError, "internal", "cannot draw from the exchangeRate buckets")
		return
	case wait > 0:
		svcedge.RateLimited(wait).Write(w)
		return
	}
	// What each marker stands for, and the keys it came from, per cookie:
	// recordCookies gives each edge grant the exp that tells it from
	// every cookie minted for other keys or entries, at most the one it
	// was to have, which the subject set, the cookie and the answer then
	// carry.
	recs := make([]*cookieRec, len(issues))
	for i, is := range issues {
		_, gs, _ := edgeGS(is.Prefix)
		recs[i] = &cookieRec{filters: map[string]*markerRec{}, exp: is.Exp}
		for _, m := range subjects[gs] {
			if f, ok := filters[m]; ok {
				recs[i].filters[m] = f
			}
		}
	}
	switch err := ix.recordCookies(ctx, recs, now); {
	case errors.Is(err, errNoSlot):
		// Every second left before its edge grant would expire is
		// another cookie's: where the grant's exp bounds it, only a
		// grant that lasts longer gets one.
		w.Header().Set("Retry-After", "1")
		writeErr(w, http.StatusServiceUnavailable, "behind", "no second is left before this edge grant would expire to tell it from those already minted: exchange a grant that lasts longer")
		return
	case err != nil:
		ix.opt.Logf("index: recording read filters: %v", err)
		writeErr(w, http.StatusInternalServerError, "internal", "cannot record the subject set")
		return
	}
	for i := range issues {
		issues[i].Exp = recs[i].exp
		_, gs, _ := edgeGS(issues[i].Prefix)
		if err := ix.edge.Record(ctx, gs, subjects[gs], issues[i].Exp, now); err != nil {
			ix.opt.Logf("index: recording a subject set: %v", err)
			writeErr(w, http.StatusInternalServerError, "internal", "cannot record the subject set")
			return
		}
	}
	svcedge.Mint(w, ix.opt.EdgeGrants, now, issues)
}

// worseUpstream is the one of cur and err, failures to read upstream
// what an exchange needs, that answers it: the first that is lasting
// (502 upstream), else the first (503 behind), so that an exchange is 503
// only where every such failure is for now, whatever the order of its
// grants and of the namespaces each names (§C.4: "503 (behind) while the
// cause is transient, and 502 (upstream) otherwise"; writeUpstreamErr).
func worseUpstream(cur, err error) error {
	if cur == nil {
		return err
	}
	if _, behind := upstreamBehind(cur); behind {
		if _, behind := upstreamBehind(err); !behind {
			return err
		}
	}
	return cur
}

// purgedNS is a purged namespace an exchange refuses, and the head of its
// purge, its purge-ns entry's ns_id (§8.5).
type purgedNS struct{ ns, head string }

// exchangeGrant is what token gives at an exchange (issueEdgeGrants): for
// every namespace the service follows that the grant names, and whose
// keys the service doesn't lack, the read check of a query of it
// (Index.access, grantAccess): a private one where the grant gets a
// marker gives /{ns}/g/{gs} of the reader's marker there, and the markers
// of those reached and not skipped give /_refs/g/{gs} over them, as
// refsReader computes it. A public namespace needs no edge grant. Each
// namespace is judged alone (§A.4 Across namespaces: "the service's
// exchange refusing only as Coverage says"): one the grant gets no marker
// in (a refusal of its read check, 401 or 403, among them a grant whose
// rules fix /resource and pass for none of the names they fix) is left
// out, with no prefix and no marker in the /_refs set, and only a grant
// left with no edge grant at all is refused: 401 if a refusal was 401,
// else 403 (Coverage: "Only a reader who may see none of the namespaces
// gets 401 or 403"). A namespace whose document the service can't read
// refuses the whole exchange (502, err), the first in the order the
// grant's root block names them (§C.5.2). A purged namespace the grant
// passes the read check of, by the service's own purged state
// (Index.committed, as its queries answer) or the core's 410 of a sealed
// one's document (§8.5), is left out too (Coverage "leaves out ...
// purged ones"); a grant left with no edge grant and no 401 or 403
// refusal is 410 only where every namespace it names is purged and it
// verifies in each (purgedOnly), naming the first; otherwise 403.
func (ix *Index) exchangeGrant(ctx context.Context, token string, reached map[string]string, now time.Time) (*exchanged, *purgedNS, error) {
	g, err := ix.checker.Decode(token)
	if err != nil {
		var le *grantcheck.LimitError
		var ae *grant.AuthError
		if errors.As(err, &le) || errors.As(err, &ae) {
			return nil, nil, err
		}
		return nil, nil, &grant.AuthError{Status: 401, Msg: "the grant can't be decoded"}
	}
	ex := &exchanged{subjects: map[string][]string{}, filters: map[string]*markerRec{}}
	var (
		markers []string
		refsExp time.Time
		upErr   error
		denied  *grant.AuthError
	)
	// deny notes a namespace the grant gets no marker in: left out, the
	// first 401 answering if nothing is left, else the first 403.
	deny := func(err error) bool {
		var ae *grant.AuthError
		if _, chain := chainErr(err); chain || !errors.As(err, &ae) {
			return false
		}
		if denied == nil || ae.Status == http.StatusUnauthorized && denied.Status != http.StatusUnauthorized {
			denied = ae
		}
		return true
	}
	fail := func(err error) {
		if !deny(err) {
			upErr = worseUpstream(upErr, err)
		}
	}
	for _, ns := range namedInOrder(g, ix.refsNamespaces()) {
		if _, lacks := ix.keys.Skip(ns); lacks {
			continue // one the service doesn't follow (§A.4)
		}
		_, purged, err := ix.committed(ctx, ns)
		if err != nil {
			fail(err)
			continue
		}
		cfg, err := ix.checker.Config(ctx, ns)
		if client.IsPurged(err) {
			if _, err = ix.checker.PurgedRead(ctx, ns, token); err != nil {
				fail(err)
			}
			continue
		}
		if err != nil {
			fail(err)
			continue
		}
		public := ix.publicFor(ctx, ns, cfg)
		if public && !purged {
			continue
		}
		v, err := ix.checker.Verify(ctx, ns, token)
		if err != nil {
			fail(err)
			continue
		}
		var a *access
		if !public {
			a, err = ix.grantAccess(ctx, ns, v)
			if errors.Is(err, errNotReached) {
				continue // its coverage, so its marker, can't be told yet
			}
			if err != nil {
				fail(err)
				continue
			}
		}
		if purged {
			// Its queries answer 410 once the read check passes (§8.5):
			// left out, and judged by purgedOnly below.
			continue
		}
		exp := ix.opt.EdgeGrants.Lifetime(now, grantExp(v))
		if ex.bucket == "" {
			// Its principal and kid there, as the core keys write buckets
			// (§C.5.2, §6.6).
			ex.bucket = v.Principal.ID + "\x00" + v.Key.Kid
		}
		// Every marker, reads:{ns} included, records the key that
		// verified the grant here and its entry (§A.4 gs).
		rec := markerRecOf(a, v)
		rec.key.entry = ix.exchangeEntry(ctx, ns, cfg.Head, a, v, rec.key)
		ex.filters[a.marker] = rec
		if _, _, ok := edgeGS(nsPrefix(ns, a.gs)); ok {
			ex.issues = append(ex.issues, svcedge.Issue{Prefix: nsPrefix(ns, a.gs), Exp: exp})
			ex.subjects[a.gs] = []string{a.marker}
		}
		if _, ok := reached[ns]; ok && ix.keys.Skipped(ns) == "" {
			markers = append(markers, a.marker)
			if refsExp.IsZero() || exp.Before(refsExp) {
				refsExp = exp
			}
		}
	}
	if upErr != nil {
		return nil, nil, upErr
	}
	if len(markers) > 0 {
		gs := grantcheck.SubjectSetID(markers)
		slices.Sort(markers)
		ex.issues = append(ex.issues, svcedge.Issue{Prefix: refsPrefix(gs), Exp: refsExp})
		ex.subjects[gs] = markers
	}
	switch {
	case len(ex.issues) > 0:
		return ex, nil, nil
	case denied != nil:
		// A refusal means some namespace it names isn't purged or the
		// grant doesn't verify there: never 410.
		return nil, nil, denied
	}
	if pn := ix.purgedOnly(ctx, token, g); pn != nil {
		return nil, pn, nil
	}
	return nil, nil, &grant.AuthError{Status: 403, Msg: "the grant reads no private namespace this service follows"}
}

// purgedOnly is the purge an exchange, or /_refs, answers 410 for a grant
// left with nothing to read (§A.4 Coverage: "where every namespace its
// grant names is purged and the grant verifies in each, 410 as §C.5.2
// gives it"; §C.5.2: "410 only when every namespace refused is purged and
// the grant verifies in each"), the first in the order its root block
// names them; nil unless every namespace g names is one the service
// follows, whose keys it doesn't lack, that is purged, and whose read
// check token passes (the core's PurgedRead for one whose document is
// 410, else Verify and grantAccess, as its queries' read check). A grant
// naming "*" in every block that names namespaces names no set of them,
// and never qualifies; nor does one naming a namespace the service
// doesn't follow, or one it can't read.
func (ix *Index) purgedOnly(ctx context.Context, token string, g *grant.Grant) *purgedNS {
	var named []string
	for _, b := range g.Blocks {
		if b.HasNS && !slices.Contains(b.NS, "*") {
			named = b.NS
			break
		}
	}
	named = slices.DeleteFunc(slices.Clone(named), func(ns string) bool { return !g.NamesNS(ns) })
	if len(named) == 0 {
		return nil
	}
	followed := ix.refsNamespaces()
	var first *purgedNS
	for _, ns := range named {
		if !slices.Contains(followed, ns) {
			return nil
		}
		if _, lacks := ix.keys.Skip(ns); lacks {
			return nil
		}
		head, purged, err := ix.committed(ctx, ns)
		if err != nil {
			return nil
		}
		_, cerr := ix.checker.Config(ctx, ns)
		switch {
		case client.IsPurged(cerr):
			if head, err = ix.checker.PurgedRead(ctx, ns, token); err != nil {
				return nil
			}
		case cerr != nil, !purged:
			return nil
		default:
			v, err := ix.checker.Verify(ctx, ns, token)
			if err != nil {
				return nil
			}
			if _, err := ix.grantAccess(ctx, ns, v); err != nil {
				return nil
			}
		}
		if first == nil {
			first = &purgedNS{ns: ns, head: head}
		}
	}
	return first
}

func (p *purgedNS) Error() string { return p.ns + " was purged" }

// write answers p: 410 purged, with ns and head (§8.5, §C.5.2).
func (p *purgedNS) write(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusGone, map[string]any{"code": "purged", "message": "namespace purged", "ns": p.ns, "head": p.head})
}

// namedInOrder is those of followed that g names, in the order g's root
// block lists them (§C.5.2); one it reaches only through "*" comes where
// "*" is.
func namedInOrder(g *grant.Grant, followed []string) []string {
	var root []string
	if len(g.Blocks) > 0 {
		root = g.Blocks[0].NS
	}
	pos := func(ns string) int {
		if i := slices.Index(root, ns); i >= 0 {
			return i
		}
		if i := slices.Index(root, "*"); i >= 0 {
			return i
		}
		return len(root)
	}
	var out []string
	for _, ns := range followed {
		if g.NamesNS(ns) {
			out = append(out, ns)
		}
	}
	slices.SortStableFunc(out, func(a, b string) int { return pos(a) - pos(b) })
	return out
}

// readsFixed reports whether a grant whose rules fix /resource (§2.1)
// may read some name they fix, by allow, its read check per resource; a
// grant whose rules fix none is left to that check per resource. Names
// are fixed as the core's issuance fixes them: by each rule of its blocks
// and key scope, at top level or inside all, that tests /resource against
// one literal or a finite set (grant.ResourceLiterals), the names all of
// them allow (§C.5.2: the rules must pass with /resource set to the names
// it fixes).
func readsFixed(v *grant.Verified, allow func(string) bool) bool {
	var names []string
	fixed := false
	var walk func(rs []any)
	walk = func(rs []any) {
		for _, rv := range rs {
			if m, ok := rv.(map[string]any); ok && len(m) == 1 {
				if all, ok := m["all"].([]any); ok {
					walk(all)
					continue
				}
			}
			lits, ok := grant.ResourceLiterals(rv)
			if !ok {
				continue
			}
			var set []string
			for _, l := range lits {
				if name, ok := l.(string); ok && !slices.Contains(set, name) {
					set = append(set, name)
				}
			}
			if !fixed {
				names, fixed = set, true
				continue
			}
			names = slices.DeleteFunc(names, func(n string) bool { return !slices.Contains(set, n) })
		}
	}
	walk(v.KeyRules)
	walk(v.BlockRules)
	return !fixed || slices.ContainsFunc(names, allow)
}

// grantExp is the earliest exp among v's blocks, the zero time for none.
func grantExp(v *grant.Verified) time.Time {
	var exp time.Time
	for _, b := range v.Grant.Blocks {
		if b.Exp != nil && (exp.IsZero() || b.Exp.Before(exp)) {
			exp = *b.Exp
		}
	}
	return exp
}

// initEdge sets up the service's edge grants, with EdgeGrants: its key
// vouches only for its own prefixes (edgeGS), and their state lives in
// the database (svcedge.Store, and edge_filters, migration 004).
func (ix *Index) initEdge(ctx context.Context, db *sql.DB) error {
	ix.filters = map[string]keptFilter{}
	if ix.opt.EdgeGrants == nil {
		return nil
	}
	ix.opt.EdgeGrants.Vouches = func(p string) bool { _, _, ok := edgeGS(p); return ok }
	if ix.opt.ExchangeRate.Rate <= 0 || ix.opt.ExchangeRate.Burst < 1 {
		ix.opt.ExchangeRate = svcedge.DefaultExchangeRate
	}
	var err error
	ix.edge, err = svcedge.NewStore(ctx, db)
	return err
}
