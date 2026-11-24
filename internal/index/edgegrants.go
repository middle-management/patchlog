package index

import (
	"bytes"
	"cmp"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/edge"
	"github.com/middle-management/patchlog/internal/follow"
	"github.com/middle-management/patchlog/internal/grant"
	"github.com/middle-management/patchlog/internal/grantcheck"
	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/telemetry"
)

// The service's own edge grants (§A.4: a view and its URLs are served as in
// §B.11.5; §C.5), with Options.EdgeGrants.
//
// Results read with a grant in Authorization are never cached at the edge
// (§9): the grant is one reader's. A private result depends on the
// reader's view alone (its markers, Index.access), so an edge may
// cache it for every reader of that view, given a cookie it can
// verify that says so. The service mints such cookies itself, with a key
// and kid of its own that the origin never holds, for the prefixes of a
// view's URLs: /{ns}/view/{view} for a private namespace's results, view
// over the reader's marker there, and /_refs/view/{view} for the answers
// across namespaces, view over its markers in every namespace it may see
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
// set's, so the service keeps the markers behind each view it minted a
// cookie for (edgeStore: edge_subjects), and, for a marker
// reads:{ns}:scope:{digest}, what its digest covers, the rules that limit
// the reads and the /principal values they refer to (edge_filters,
// markerRec), from which it filters hits per resource as for any grant
// with that marker, for a marker reads:{ns}:g:{view} (§7.9) also its
// subjects (edge_views), and for every marker, reads:{ns}:{k} included, every
// key a cookie of it was minted under, its kid, the role names its grant
// read through, its kid's pub and the digest of its whole entry and of
// those roles' whole definitions (edge_view_keys, viewKey, entryDigest),
// each until that cookie expires: a cookie is 403 once one of the keys
// or roles it came from is gone or changes in any member (§A.4 view: "its
// key being the one that verified the grant in {ns}, reads:{ns}:{k} markers
// included", §7.9 view; readsKeysHold, scopeKeysHold, storedFview), and
// no later exchange vouches for it again: one whose keys or entries
// differ mints a cookie with another exp (recordCookies). They
// are kept across restarts and -rebuild until the last such cookie
// expires; a view or marker the service doesn't know, minted by another
// instance with its own database, is 401, and the reader exchanges again.
// Instances on one database share them, and share the exchangeRate
// buckets too (§B.11.5). A reader of a whole namespace at issue
// (reads:{ns}:{k}) reads it whole under the cookie until it expires or its
// key or a role it read through changes; a revocation since doesn't end
// it: for that the cookie's lifetime is the latency (§C.5).

// markerRec is what a marker of a cookie stands for: for
// reads:{ns}:scope:{digest}, the read filter of the rules its digest
// covers (grantcheck.ReadFilter: its key's scope, its blocks and, if it
// carries roles, each effective role that lists read, and its
// /principal), from which hits are filtered per resource as for any grant
// with that marker; for reads:{ns}:g:{view} (§7.9), also its subjects,
// from which item 1 is judged; and for either, from an exchange, the key
// its grant came from (viewKey), recorded for its cookie (recordCookies;
// keysHold and storedFview judge each key of a cookie). A rule
// referring to /now gives no marker, so the filter judges a read as the
// grant's read check does, without a clock.
type markerRec struct {
	f        *grantcheck.ReadFilter // nil for reads:{ns}:{k}, which reads whole
	subjects []string               // g: markers only
	key      viewKey                // from an exchange only
	// also are the keys the other grants of one exchange got the same
	// marker through, recorded beside key (issueEdgeGrants).
	also []viewKey
}

// viewKey is a key a g: or scope marker's cookies came from: its kid and
// the names of its grant's read roles, whose rules as of a checkpoint
// must still digest to the marker's scope subject (g:) or its digest
// (scope:), and the pub its kid had, which the key with that kid must
// still have (§7.9 view, §C.4, §A.4; storedFview, scopeKeysHold). A g:
// marker's view digests the key too (grantcheck.KeySubject), but readers whose
// grants come from different keys, or from one key before and after its
// entry changes, may share a marker, and a cookie says only its prefix
// and exp: the viewKeys of each cookie are kept by its marker and exp
// (edge_view_keys), the same for every exchange that minted it
// (recordCookies), and each must still hold.
//
// entry is EntryDigest (entryDigest) of the key's whole entry and of each
// of roles' whole definitions, as the document the marker is judged by
// gave them at the exchange (§7.9 view, v0.82: a cookie is 403 where
// "the key its key: string names, or a key or role they came from, is
// gone or changes in any member"; §A.4 view: for every marker, reads:{ns}
// included). "" is a key recorded before entries were kept, or one whose
// entry couldn't be told at the exchange: it never holds.
type viewKey struct {
	kid   string
	roles []string
	pub   string // the key's pub member, as its namespace document gives it
	entry string
	// conf is, at an exchange, the namespace documents entry was drawn
	// from that the index was found to be behind (exchangeEntry, ahead),
	// by namespace, each as confPos gives it. recordCookies keeps of them
	// those the index still hasn't reached (viewKeyRow.pending). chain are
	// the bases of a local branch entry was drawn through, nearest first
	// (viewKeyRow.chain). Both nil for a key read back from the database.
	conf  map[string]string
	chain []string
}

// confDigest names a namespace document by its content.
func confDigest(doc map[string]any) string {
	if doc == nil {
		doc = map[string]any{}
	}
	return ids.Of(jsonv.Canonical(doc)).String()
}

// confPos is where in a namespace's log an exchange read the document
// cfg: "{ns_id} {digest}", the head the checker read it at and the
// document's digest. The index has reached it once it has applied the
// entry of that ns_id (seen); the digest is kept for reading the table.
func confPos(cfg *grantcheck.Config) string { return cfg.Head + " " + confDigest(cfg.Doc) }

// chainOf are the documents of cfg's chain of bases, nearest first, as
// the checker holds them, where cfg's namespace is a local branch: the
// ones an exchange draws its key from (exchangeEntry), each read once, so
// that the entry it records and the positions it records for it come
// from the same documents. A base it can't read ends the list.
func (ix *Index) chainOf(ctx context.Context, cfg *grantcheck.Config) []*grantcheck.Config {
	var out []*grantcheck.Config
	seen := map[string]bool{cfg.NS: true}
	for cfg.Base != "" && len(out) < maxChain && !seen[cfg.Base] {
		base, err := ix.checker.Config(ctx, cfg.Base)
		if err != nil {
			break
		}
		seen[base.NS] = true
		out = append(out, base)
		cfg = base
	}
	return out
}

// ahead reports whether head, the ns_id the checker read ns's document
// at, is known to lie after the index's checkpoint of ns: the index
// follows ns, hasn't applied the entry (seen), and the origin serves the
// range from its checkpoint up to head, so the checkpoint is in head's
// chain (§7.1 Paging) and the follower will meet the entry. Anything
// else is not ahead: a head the checker read before ns was started from
// a snapshot past it (by another instance on this database: this one's
// batches drop what the checker holds, Observe) is in no batch to come,
// and a cookie recorded as waiting for it would have every later
// document skipped for it. Such a cookie is judged by every document
// instead.
func (ix *Index) ahead(ctx context.Context, ns, head string) bool {
	cur, purged, err := ix.committed(ctx, ns)
	if err != nil || cur == "" || purged || head == "" || cur == head || ix.seen(ctx, ns, head) {
		return false
	}
	cctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	_, _, err = ix.c.NSLogPage(cctx, ns, head, cur)
	return err == nil
}

// encodePending and decodePending are viewKeyRow.pending's form: "" for
// none, else the canonical JSON object of namespace to position
// (confPos).
func encodePending(p map[string]string) string {
	if len(p) == 0 {
		return ""
	}
	m := make(map[string]any, len(p))
	for k, v := range p {
		m[k] = v
	}
	return string(jsonv.Canonical(m))
}

func decodePending(s string) map[string]string {
	out := map[string]string{}
	if s == "" {
		return out
	}
	var m map[string]string
	if json.Unmarshal([]byte(s), &m) == nil {
		out = m
	}
	return out
}

// entryDigest is EntryDigest of §7.9 view as the reference defines it,
// here and at the origin alike:
//
//	text(trunc160(sha256(canonical({ "key": K, "roles": R }))))
//
// in the id text form of §3.2, K being the whole entry of the key that
// verified the grant, as the judged namespace document gives it (for a
// branch, the effective key's source entry, §C.4), and R mapping each
// read role recorded, and every other role that lists read there, to its
// whole definition there (readRoleDefs): a change to any role that lists
// read ends the cookie, as at the origin (§7.9 view, SERVICES §A.4;
// Filtered reads scenario 61). "" for no key.
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
// (copiedKids). ok is false for none. over, if any, gives documents that
// stand in for the checker's of the namespaces it names (cookieEnds: a
// document the index is applying, in the place of the head's).
func (ix *Index) effectiveKey(ctx context.Context, cfg *grantcheck.Config, kid string, depth int, over map[string]*grantcheck.Config) (key grant.Key, ok bool, err error) {
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
	base := over[cfg.Base]
	if base == nil {
		base, err = ix.checker.Config(ctx, cfg.Base)
	}
	switch {
	case client.IsPurged(err), client.IsNotFound(err):
		return grant.Key{}, false, nil
	case err != nil:
		return grant.Key{}, false, lacksRead(cfg.Base, fmt.Errorf("the head of %s: %w", cfg.Base, err))
	}
	if key, ok, err := ix.effectiveKey(ctx, base, kid, depth+1, over); err != nil || ok {
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
		if e.Kind == "branch" && e.Name == cfg.NS {
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
	return ix.entryOfIn(ctx, cfg, kid, roles, nil)
}

// entryOfIn is entryOf with over's documents in the place of the
// checker's (effectiveKey).
func (ix *Index) entryOfIn(ctx context.Context, cfg *grantcheck.Config, kid string, roles []string, over map[string]*grantcheck.Config) (entry string, key grant.Key, ok bool, err error) {
	key, ok, err = ix.effectiveKey(ctx, cfg, kid, 0, over)
	if err != nil || !ok || key.Raw == nil {
		return "", key, false, err
	}
	rs, ok := readRoleDefs(cfg.Doc, roles)
	if !ok {
		return "", key, false, nil
	}
	return entryDigest(key.Raw, rs), key, true, nil
}

// readRoleDefs maps, in a namespace document doc, each role of roles, a
// grant's read roles, and every other role that lists read, to its whole
// definition (entryDigest). ok is false where one of roles is gone.
func readRoleDefs(doc map[string]any, roles []string) (map[string]any, bool) {
	defs, _ := doc["roles"].(map[string]any)
	rs := make(map[string]any, len(roles))
	for _, r := range roles {
		def, ok := defs[r]
		if !ok {
			return nil, false
		}
		rs[r] = def
	}
	for r, def := range defs {
		m, _ := def.(map[string]any)
		can, _ := m["can"].([]any)
		for _, v := range can {
			if v == "read" {
				rs[r] = def
				break
			}
		}
	}
	return rs, true
}

// entryHolds reports whether k, a key a cookie came from, is still, in
// the document cfg, the key the exchange recorded: there, listing read,
// with the pub it had, and with its whole entry and each of its roles'
// whole definitions digesting to k.entry (§7.9 view, v0.82: "gone or
// changes in any member"), whether or not a scope digest reads the member
// that changed: a changed sub, groups, attrs, maxTtl, rate or can of
// the key, or a role's can or rules. A key recorded without its entry or
// its pub never holds. The key is returned for viewKeyHolds.
func (ix *Index) entryHolds(ctx context.Context, cfg *grantcheck.Config, k viewKey) (grant.Key, bool, error) {
	entry, key, ok, err := ix.entryOf(ctx, cfg, k.kid, k.roles)
	if err != nil || !ok {
		return key, false, err
	}
	return key, k.entry != "" && entry == k.entry && k.pub != "" && keyPub(key) == k.pub && key.Lists("read"), nil
}

// exchangeEntry is the entry digest an exchange records for the key k
// that verified v in ns, whose access is a (viewKey.entry): of the document
// a read under the cookie is judged by, ns's at its head, and for a g:
// marker the one at its checkpoint (storedFview). It is "", which never
// holds, so that the reader exchanges again, where it can't vouch that
// the grant was verified by that very entry: the key that verified v
// isn't the entry the head's document gives, or a document can't be
// read. behind reports a cookie that would be 403 at once for a cause
// that passes (§A.4 view, v0.85: "An exchange whose cookie would be 403 at
// once, as a key or role its marker draws on has changed since the
// checkpoint the marker is judged at, answers 503 (behind)"): the
// checkpoint's document gives the key or a role otherwise than the
// head's, the index not having applied a change yet. moved reports that
// the checker's document moved during the exchange (head is the one read
// before v was verified), so that what verified v can't be told from
// what a read is judged by: the exchange tries the namespace again, and
// answers 503 only after exchangeTries (SERVICES §A.4, v0.90: "Other
// moves of the namespace document while an exchange is judged are
// retried"). Before v0.85 either minted a cookie that never held; before
// v0.90 a move was 503 at once.
func (ix *Index) exchangeEntry(ctx context.Context, ns, head string, a *access, v *grant.Verified, k viewKey) (out viewKey, behind, moved bool) {
	out = k
	out.entry = ""
	if testExchangeEntry != nil {
		testExchangeEntry(ns)
	}
	cfg, err := ix.checker.Config(ctx, ns)
	if err != nil {
		return out, false, false
	}
	if cfg.Head != head {
		return out, false, true
	}
	// The chain's documents, read once: the entry and the positions
	// recorded with it are those of the same documents.
	chain := ix.chainOf(ctx, cfg)
	over := make(map[string]*grantcheck.Config, len(chain))
	for _, b := range chain {
		over[b.NS] = b
	}
	entry, key, ok, err := ix.entryOfIn(ctx, cfg, k.kid, k.roles, over)
	if err != nil || !ok || !bytes.Equal(jsonv.Canonical(key.Raw), jsonv.Canonical(v.Key.Raw)) {
		return out, false, false
	}
	if a.cov != nil {
		doc, err := ix.docAt(ctx, ns, a.cov.cp.at)
		if err != nil {
			return out, false, false
		}
		at, err := grantcheck.ParseConfig(ns, "", doc)
		if err != nil {
			return out, false, false
		}
		switch e, _, ok, err := ix.entryOfIn(ctx, at, k.kid, k.roles, over); {
		case err != nil:
			return out, false, false
		case !ok || e != entry:
			return out, true, false
		}
	}
	out.entry = entry
	out.conf = map[string]string{}
	for _, c := range append([]*grantcheck.Config{cfg}, chain...) {
		if c != cfg {
			out.chain = append(out.chain, c.NS)
		}
		if ix.ahead(ctx, c.NS, c.Head) {
			out.conf[c.NS] = confPos(c)
		}
	}
	return out, false, false
}

// testExchangeEntry, if set, is called as exchangeEntry begins (tests move
// the namespace document there).
var testExchangeEntry func(ns string)

// exchangeTries is how many times an exchange judges a namespace whose
// document moves while it is judged before answering 503 (exchangeEntry).
const exchangeTries = 3

// errExchangeBehind is an exchange whose cookie would be 403 at once
// (exchangeEntry): 503 behind, ranked as any failure to read upstream
// for now (upstreamBehind, worseUpstream; §A.4 view, §C.5.2).
var errExchangeBehind = errors.New("the index hasn't applied a change to a key or role the grant reads through")

// markerRecOf is what a's marker stands for, a's grant being v: its
// filter, the key it came from, for a scope marker as for a g: one (§A.4:
// a cookie is 403 "where a marker's key, rules or roles would end a view
// cookie"), and a g: marker's subjects.
func markerRecOf(a *access, v *grant.Verified) *markerRec {
	rec := &markerRec{f: a.filter} // nil for reads:{ns}:{k}
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

// readsMarker is the marker reads:{ns}:{k} of a reader whose grant would
// be issued a namespace-wide edge grant in ns (§A.4 view, v0.85): k is the
// key: string (grantcheck.KeySubject, §7.9 view) of the key that verified
// the grant there, by kid and pub, so reads:{ns}:key:{id}. Readers
// through two keys never share the marker, so neither its view, its
// results nor its cookie prefix, and a change to one key ends only the
// cookies minted through it. Before v0.85 it was reads:{ns}, shared by
// every key's readers; a cookie for that form reads nothing now
// (markerAccess).
func readsMarker(ns, kid, pub string) string {
	return "reads:" + ns + ":" + grantcheck.KeySubject(kid, pub)
}

// readsPrefix is what every reads:{ns}:{k} marker of ns starts with
// (readsMarker): no scope or g: marker of any namespace does.
func readsPrefix(ns string) string { return "reads:" + ns + ":" + grantcheck.KeyPrefix }

// scopeMarker is the marker reads:{ns}:scope:{digest} of a reader of
// uncovered ns whose reads there have grantcheck.ReadsScope digest d,
// through the key with kid and pub (§A.4): its digest covers d and the
// key's key: string (grantcheck.KeySubject, §7.9 view), so readers through
// two keys with the same rules never share a marker, its view, its edge
// filter or its cookie prefix. A view's scope: subject is the same digest
// (§7.9 view: "scope:{digest} of §A.4's marker"), at the origin too.
func scopeMarker(ns, d, kid, pub string) string {
	return "reads:" + ns + ":scope:" + scopeKeyDigest(d, kid, pub)
}

// scopeKeyDigest is scopeMarker's digest: of d and the key's key: string
// (grantcheck.ScopeKeyDigest).
func scopeKeyDigest(d, kid, pub string) string { return grantcheck.ScopeKeyDigest(d, kid, pub) }

// keyPub is k's pub member as the namespace document gives it, "" if it
// has none (§7.9 view: "accepted only while the base has it with the
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
// marker of its view stands for and the keys this exchange
// vouches for it with (filters), and when it expires, which recordCookies
// may move earlier.
type cookieRec struct {
	filters map[string]*markerRec
	exp     time.Time
}

// errNoSlot is an exchange for which no second is left to tell its cookie
// from those of other exchanges (recordCookies).
var errNoSlot = errors.New("no exp left for an edge grant of its own")

// viewKeyRow is a key as edge_view_keys keeps it: its roles as a JSON array,
// and pending, the namespace documents its exchange drew on that the
// index had not applied yet when it was recorded (encodePending), "" for
// none. A cookie minted while the index is behind was verified against
// the document at the head: the documents its backlog still brings, up
// to and including that one, are from before the exchange and end
// nothing of it (cookieEnds, §7.9 view: "Once an entry after its
// exchange changes one of them"). A namespace leaves pending as the
// index applies the document named. Rows from before v0.86's second
// migration have none, and are judged by every document.
//
// chain is the bases of a local branch the row's key was drawn through,
// as a JSON array, "" for none: a document of one of them is judged for
// the row whether or not the checker can say, as it is applied, that the
// branch draws on it.
type viewKeyRow struct{ kid, roles, pub, entry, pending, chain string }

// recordCookies records what the markers of the edge grants recs, minted
// at now, stand for (edge_filters, and for g: markers edge_views), and the
// keys each cookie came from (edge_view_keys), and drops what the last edge
// grant of has expired, from the database and from memory, as
// edgeStore.Record does for views. It sets each rec's exp to
// the one its cookie must carry.
//
// A cookie carries its prefix and exp alone, so cookies of one marker
// that expire at the same second are one cookie, judged by the keys
// recorded for that marker and exp (viewKeysAt), each of which must hold.
// What is recorded there is therefore only ever what every exchange that
// minted that cookie vouched for, the same keys with the same entries
// (§A.4 view, §7.9 view): a row is never changed once written, and an
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
// A document changed and then changed back gives a key the entry it had,
// but a cookie minted before the change doesn't hold again: the index
// ends its rows as it applies the entry that made the change (cookieEnds;
// §7.9 view, v0.86: "the cookie is 403 from that entry on, even where a
// later entry undoes the change").
func (ix *Index) recordCookies(ctx context.Context, recs []*cookieRec, now time.Time) error {
	// With the batches' lock: a batch's transaction reads the rows before
	// it writes (cookieEnds.apply), and one committed here in between
	// would fail its first write on a stale snapshot.
	ix.wmu.Lock()
	defer ix.wmu.Unlock()
	tx, err := ix.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// The first statement writes: the transaction holds the database's
	// write lock from here, and no other exchange records between the
	// reads of a slot below and the rows written to it.
	for _, q := range []string{`DELETE FROM edge_filters WHERE exp <= ?`, `DELETE FROM edge_views WHERE exp <= ?`, `DELETE FROM edge_view_keys WHERE exp <= ?`} {
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
	taken := map[string]map[int64][]viewKeyRow{}
	slots := func(m string) (map[int64][]viewKeyRow, error) {
		if by, ok := taken[m]; ok {
			return by, nil
		}
		rows, err := tx.QueryContext(ctx, `SELECT exp, kid, roles, pub, entry, pending, chain FROM edge_view_keys WHERE marker = ? ORDER BY exp, kid, roles, pub`, m)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		by := map[int64][]viewKeyRow{}
		for rows.Next() {
			var (
				exp int64
				k   viewKeyRow
			)
			if err := rows.Scan(&exp, &k.kid, &k.roles, &k.pub, &k.entry, &k.pending, &k.chain); err != nil {
				return nil, err
			}
			by[exp] = append(by[exp], k)
		}
		taken[m] = by
		return by, rows.Err()
	}
	// pendingOf keeps of conf, the positions the exchange found ahead of
	// the index (ahead), those it still hasn't reached: the entry at that
	// ns_id isn't among those it applied (seen). Read in this
	// transaction, which a batch's can't interleave with: an entry is
	// either applied already, or will be met by the row written here.
	reached := map[string]bool{}
	pendingOf := func(conf map[string]string) (string, error) {
		p := map[string]string{}
		for ns, pos := range conf {
			head, _, _ := strings.Cut(pos, " ")
			k := ns + "\x00" + head
			was, ok := reached[k]
			if !ok {
				var one int
				err := tx.QueryRowContext(ctx, `SELECT 1 FROM seen WHERE ns = ? AND ns_id = ?`, ns, head).Scan(&one)
				if err != nil && !errors.Is(err, sql.ErrNoRows) {
					return "", err
				}
				was = err == nil || head == ""
				reached[k] = was
			}
			if !was {
				p[ns] = pos
			}
		}
		return encodePending(p), nil
	}
	for _, rec := range recs {
		// What this exchange vouches for, per marker: each key once, in
		// the order of the rows, and without an entry (which never
		// holds) where two of its grants found it with different ones.
		want := map[string][]viewKeyRow{}
		for m, f := range rec.filters {
			var ks []viewKeyRow
			for _, k := range append([]viewKey{f.key}, f.also...) {
				pending, err := pendingOf(k.conf)
				if err != nil {
					return err
				}
				row := viewKeyRow{k.kid, enc(k.roles), k.pub, k.entry, pending, ""}
				if len(k.chain) > 0 {
					row.chain = enc(k.chain)
				}
				i := slices.IndexFunc(ks, func(o viewKeyRow) bool { return o.kid == row.kid && o.roles == row.roles && o.pub == row.pub })
				switch {
				case i < 0:
					ks = append(ks, row)
				case ks[i].entry != row.entry:
					ks[i].entry = ""
				case ks[i].pending != row.pending:
					ks[i].pending = ""
				}
			}
			slices.SortFunc(ks, func(a, b viewKeyRow) int {
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
				if had := by[exp]; len(had) > 0 && !slices.Equal(had, ks) && !ix.slotLive(ctx, m, had, ks) {
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
				// edge_views's kid, roles and pub (migrations 005, 006) are the
				// latest exchange's, kept only because they are NOT NULL: a
				// cookie is judged by the keys in edge_view_keys (migrations
				// 007, 011).
				if _, err := tx.ExecContext(ctx, `INSERT INTO edge_views (marker, subjects, kid, roles, pub, exp) VALUES (?, ?, ?, ?, ?, ?)
				ON CONFLICT (marker) DO UPDATE SET subjects = excluded.subjects, kid = excluded.kid, roles = excluded.roles, pub = excluded.pub, exp = max(exp, excluded.exp)`,
					m, enc(f.subjects), f.key.kid, enc(f.key.roles), f.key.pub, exp); err != nil {
					return err
				}
			}
			// The keys the cookie of m expiring at exp came from
			// (viewKeysAt): a row is written once, and the same ever
			// after. A live cookie's second this exchange shares gains
			// the keys it lacks, so that a change to any of them ends
			// both cookies, and none revives (slotLive).
			had := taken[m][exp]
			for _, k := range want[m] {
				if slices.ContainsFunc(had, func(o viewKeyRow) bool { return o.kid == k.kid && o.roles == k.roles && o.pub == k.pub }) {
					continue
				}
				if _, err := tx.ExecContext(ctx, `INSERT INTO edge_view_keys (marker, exp, kid, roles, pub, entry, pending, chain) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
					m, exp, k.kid, k.roles, k.pub, k.entry, k.pending, k.chain); err != nil {
					return err
				}
				had = append(had, k)
			}
			slices.SortFunc(had, func(a, b viewKeyRow) int {
				return cmp.Or(strings.Compare(a.kid, b.kid), strings.Compare(a.roles, b.roles), strings.Compare(a.pub, b.pub))
			})
			taken[m][exp] = had
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

// slotLive reports whether the cookie of marker m whose keys are had, at a
// second an exchange that vouches for ks would take, is live: no key it
// came from has ended (an empty entry, cookieEnds) or differs at the head
// of m's namespace from what its exchange recorded (entryHolds), one
// this exchange vouches for too judged by the entry it found. Such a
// second is shared, the cookies becoming 403 together; only a 403
// cookie's second is skipped (§C.5.2 Answer, §7.9 view, v0.90: "no cookie
// shares its exp with a 403 cookie for the same prefix; live ones may
// share one"). Until v0.90 an exchange skipped every second whose keys
// weren't exactly its own. A document that can't be read now counts as
// 403.
func (ix *Index) slotLive(ctx context.Context, m string, had, ks []viewKeyRow) bool {
	ns, ok := markerNS(m)
	if !ok {
		return false
	}
	var cfg *grantcheck.Config
	for _, r := range had {
		if r.entry == "" {
			return false
		}
		if i := slices.IndexFunc(ks, func(k viewKeyRow) bool { return k.kid == r.kid && k.roles == r.roles && k.pub == r.pub }); i >= 0 {
			if ks[i].entry != r.entry {
				return false
			}
			continue
		}
		roles, ok := decodeStrings(r.roles)
		if !ok {
			return false
		}
		if cfg == nil {
			c, err := ix.checker.Config(ctx, ns)
			if err != nil || ix.basesJudged(ctx, c) != nil {
				return false
			}
			cfg = c
		}
		if _, holds, err := ix.entryHolds(ctx, cfg, viewKey{kid: r.kid, roles: roles, pub: r.pub, entry: r.entry}); err != nil || !holds {
			return false
		}
	}
	return true
}

// recordFilters records what the markers of one edge grant minted at now
// that expires at exp stand for (recordCookies).
func (ix *Index) recordFilters(ctx context.Context, filters map[string]*markerRec, exp, now time.Time) error {
	return ix.recordCookies(ctx, []*cookieRec{{filters: filters, exp: exp}}, now)
}

// filter is what marker m stands for, recorded when an edge grant for it
// was minted, by this instance or another on the database. A g: marker
// without its subjects is unknown. The keys a g: marker's cookies came
// from are read by viewKeys, never from memory: an exchange at another
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
		LEFT JOIN edge_views g ON g.marker = f.marker WHERE f.marker = ?`, m).Scan(&s, &exp, &subjects); err != nil {
		return nil, false
	}
	f, err := grantcheck.DecodeReadFilter(s)
	if err != nil {
		return nil, false
	}
	f.Steps = ix.opt.ValidationSteps // each item's validation steps (§6.6)
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

// viewKeys is every key the live cookies of marker m came from at now
// (edge_view_keys), each once, without its entry, recorded by any instance
// on the database.
func (ix *Index) viewKeys(ctx context.Context, m string, now time.Time) ([]viewKey, error) {
	return ix.viewKeyRows(ctx, `SELECT DISTINCT kid, roles, pub, '' FROM edge_view_keys WHERE marker = ? AND exp > ? ORDER BY kid, roles, pub`, m, now.Unix())
}

// viewKeysAt is every key the cookie of marker m that expires at exp (a
// Unix time, its claim) came from, recorded by any instance on the
// database: every exchange that minted that cookie recorded the same
// (recordCookies), and each must still hold. A cookie minted before migration 011 has none,
// one whose key was recorded without its entry has entry "", and one
// without its pub has pub "", which no key has: readsKeysHold,
// scopeKeysHold and storedFview refuse all three, until the reader
// exchanges again.
func (ix *Index) viewKeysAt(ctx context.Context, m string, exp int64) ([]viewKey, error) {
	return ix.viewKeyRows(ctx, `SELECT kid, roles, pub, entry FROM edge_view_keys WHERE marker = ? AND exp = ? ORDER BY kid, roles, pub`, m, exp)
}

func (ix *Index) viewKeyRows(ctx context.Context, q, m string, t int64) ([]viewKey, error) {
	rows, err := ix.db.QueryContext(ctx, q, m, t)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []viewKey
	for rows.Next() {
		var (
			k     viewKey
			roles string
		)
		if err := rows.Scan(&k.kid, &roles, &k.pub, &k.entry); err != nil {
			return nil, err
		}
		var ok bool
		if k.roles, ok = decodeStrings(roles); !ok {
			return nil, errors.New("edge_view_keys: roles of " + m + " aren't a JSON array of strings")
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

// isGMarker reports whether m is a marker reads:{ns}:g:{view} (§A.4).
func isGMarker(m string) bool {
	rest, ok := strings.CutPrefix(m, "reads:")
	if !ok {
		return false
	}
	_, vid, ok := strings.Cut(rest, ":g:")
	return ok && !strings.Contains(vid, ":")
}

// nsPrefix is the prefix of a view's results of ns, refsPrefix of
// its answers across namespaces: every at, and the head pointer under the
// prefix (§B.11.5).
func nsPrefix(ns, view string) string { return "/" + ns + "/view/" + view }
func refsPrefix(view string) string   { return "/_refs/view/" + view }

// edgeView parses one of the service's prefixes, /{ns}/view/{view} or (ns "")
// /_refs/view/{view}: the only prefixes its key vouches for (§C.5.3). A
// namespace named r or ns has none, since its prefix would lie under the
// core's.
func edgeView(p string) (ns, vid string, ok bool) {
	segs := strings.Split(p, "/")
	if len(segs) != 4 || segs[0] != "" || segs[2] != "view" {
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

// errUnknownSet is a read under an edge grant whose view, or the
// filter of one of its markers, the service doesn't know: minted by an
// instance with another database, or forgotten once expired.
var errUnknownSet = &grant.AuthError{Status: 401, Msg: "an edge grant for a subject set this service doesn't know: exchange the grant again"}

// cookieAccess is access to private namespace ns under one of the
// service's edge grants for /{ns}/view/{view} (ok false without one): the
// marker its view stands for, read as a grant with that marker would be.
func (ix *Index) cookieAccess(ctx context.Context, ns string, r *http.Request) (*access, bool, error) {
	cl := ix.edgeClaims(r)
	if cl == nil {
		return nil, false, nil
	}
	cns, vid, ok := edgeView(cl.Prefix)
	if !ok || cns != ns {
		return nil, false, nil
	}
	subs, ok := ix.edge.Subjects(ctx, cl.Prefix)
	if !ok || len(subs) != 1 {
		return nil, true, errUnknownSet
	}
	a, err := ix.markerAccess(ctx, ns, subs[0], cl.Exp)
	if a != nil {
		a.vid = vid
	}
	return a, true, err
}

// markerAccess is access to private namespace ns of a reader with marker m
// under an edge grant that expires at exp: reads:{ns}:{k} reads it whole,
// reads:{ns}:scope:… as its filter allows while ns is still uncovered
// (stillUncovered), reads:{ns}:g:… as its subjects and filter see ns at
// its current checkpoint, which must still be covered (§7.9,
// storedFview), each only while every key that cookie came from, and the
// roles its grant read through, are as the exchange recorded them (§A.4
// view, "reads:{ns}:{k} markers included"; readsKeysHold, scopeKeysHold,
// storedFview); any other marker reads none of it.
func (ix *Index) markerAccess(ctx context.Context, ns, m string, exp int64) (*access, error) {
	switch {
	case strings.HasPrefix(m, readsPrefix(ns)):
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
		return &access{marker: m, filter: f.f, allow: ix.revAllow(ns, f.f), cookie: true}, nil
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
			a.derive, a.allow = nil, func(string, string) bool { return false }
		case err != nil:
			return nil, err
		}
		return a, nil
	}
	return nil, &grant.AuthError{Status: 403, Msg: "the edge grant doesn't read this namespace"}
}

// keysHold checks the cookie of marker m of ns that expires at exp
// against ns's document at its head (its effective keys, §C.4):
// errRulesChanged unless every key that cookie came from (viewKeysAt) is
// still there with the pub it had and lists read, with its whole entry
// and its roles' whole definitions as the exchange recorded them
// (entryHolds; §7.9 view, v0.82: "gone or changes in any member"), and
// passes also, if any. A cookie with no key recorded, minted before
// migration 011, is refused: the reader exchanges again. A document that
// can't be read is an error, never a read.
//
// A purged namespace is judged like any other, by the document it had
// when it was purged, which the core still serves: the 410 and its head
// are for a request that passes the read check (§8.5), and a cookie that
// had ended before the purge doesn't. Where the core answers 410 for the
// document too (a sealed namespace, §8.5), nothing is left to judge the
// keys by but the last document the index read (§A.4 Unavailable
// namespaces, v0.85): a cookie passes with every key recorded with its
// entry and pub, as a cookie that never held, or that a document the
// index applied ended (cookieEnds), isn't (purgedKeysHold). One whose
// key or role changed after its exchange in a document the index never
// read before the purge still gets the 410 and its head until it
// expires.
func (ix *Index) keysHold(ctx context.Context, ns, m string, exp int64, also func(cfg *grantcheck.Config, key grant.Key, k viewKey) bool) error {
	recorded, err := ix.viewKeysAt(ctx, m, exp)
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
	if err := ix.basesJudged(ctx, cfg); err != nil {
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

// basesJudged is errRulesChanged where a cookie of cfg's namespace can't
// be judged by every namespace-document entry of its bases after its
// exchange (SERVICES §A.4 Cookies, v0.88: "in a branch by its bases'
// entries after their checkpoints then too … A cookie it can't judge so
// … is 403"): a base in its chain the index doesn't follow brings no
// batch to judge (cookieEnds), so a change there and back would go
// unseen. A base whose document can't be read now is that error.
func (ix *Index) basesJudged(ctx context.Context, cfg *grantcheck.Config) error {
	seen := map[string]bool{cfg.NS: true}
	for cur := cfg; cur.Base != ""; {
		if seen[cur.Base] || len(seen) > maxChain || !ix.known(cur.Base) {
			return errRulesChanged
		}
		seen[cur.Base] = true
		next, err := ix.checker.Config(ctx, cur.Base)
		if err != nil {
			return err
		}
		cur = next
	}
	return nil
}

// purgedKeysHold is keysHold where the namespace's document is 410 too
// (§8.5): errRulesChanged for a cookie with no key recorded, or with one
// recorded without its entry or its pub, which never held or which the
// last document the index read of the namespace ended (cookieEnds).
func purgedKeysHold(recorded []viewKey) error {
	if len(recorded) == 0 || slices.ContainsFunc(recorded, func(k viewKey) bool { return k.entry == "" || k.pub == "" }) {
		return errRulesChanged
	}
	return nil
}

// cookieEnds is what applying a batch of ns ends of the cookies recorded
// (edge_view_keys), worked out before the batch's transaction, since it
// reads other namespaces' documents, and written in it (apply).
//
// "Once an entry after its exchange changes one of them [the key its key:
// string names, or a key or role its rules came from], the cookie is 403
// from that entry on, even where a later entry undoes the change"
// (SERVICES §7.9 view, §A.4 view, v0.86; CONFORMANCE Tree 145). A live
// namespace's cookie is judged by the document at its head on every read
// (keysHold), which sees a change and not a change undone; so every
// namespace document a batch brings, each config entry's in order, is
// judged as it is applied: a row whose key or roles that document no
// longer gives as its exchange recorded them (the key gone, with another
// pub or without read, a role gone, or the entry digest another:
// entryHolds) loses its entry, which then never holds again
// (purgedKeysHold, entryHolds), whatever a later document says. One
// entry that changes nothing in sum brings one document, and ends
// nothing. Before v0.86 only a batch's last document was judged, so a
// change and its undo in one batch of the follower left the cookie
// reading.
//
// Only entries after the exchange count. A cookie minted while the index
// is behind was verified against the document at the head, which the
// index reaches later: its row is recorded with that position
// (viewKeyRow.pending, confPos), and the documents of the backlog, up to
// and including the entry at it, are from before the exchange and are
// not judged for the row, which leaves pending as the batch brings that
// entry. A position is recorded only where the origin says the index's
// checkpoint is in its chain (ahead), so the follower meets it. So an index catching up on several config entries
// ends no cookie minted meanwhile for what its key was before, and the
// first change after the exchange ends it. A row without a position,
// one from before positions were kept among them, is judged by every
// document.
//
// It also serves a sealed namespace that is then purged, whose document
// is 410 and judges nothing any more: its 410 is for a request that
// passes the read check "against the last namespace document the service
// read" (§A.4 Unavailable namespaces, v0.85; scenario 135), so a cookie
// the index saw end gets 403, not the purge's 410 and head.
//
// A local branch's keys are its base's (effectiveKey): a document of ns
// is judged for the rows of ns and for those of every namespace with
// rows whose chain of bases reaches ns, with that document in the place
// of ns's at the head and every other namespace's as the checker holds
// it; such a row is pending on each document of its chain the index had
// not reached. Before v0.86 a branch's rows were left to keysHold alone.
// A base the index doesn't follow brings no batch: a change there and
// back is seen only if a read falls between the two.
//
// A snapshot (all) starts ns from its /heads at one entry, whose document
// alone it reads: the entries it skipped may have changed a key and
// changed it back, and the rows, which a restart and a rebuild keep,
// can't tell. Every row of ns, and of the namespaces that draw on it, is
// ended: their readers exchange again.
type cookieEnds struct {
	all bool
	// ns is the batch's namespace, and steps its entries in order.
	ns    string
	steps []confStep
	// own says that none of the batch's documents names a base or fails
	// to parse: each alone gives its keys and roles, so a row of ns
	// recorded since is judged in tx (ownHolds).
	own bool
	// seen are, per namespace judged, the rows judged. Any other row
	// recorded since, which no document was judged for, ends (apply):
	// what can't be told is refused.
	seen map[string]map[viewKeyRow]rowEnd
}

// confStep is one entry of a batch of a namespace: its ns_id and, where
// it changes the configuration, the document in force after it, parsed
// (nil for one that doesn't parse, which judges nothing) and its digest.
type confStep struct {
	id     string
	hasDoc bool
	digest string
	cfg    *grantcheck.Config
}

// rowEnd is what a batch does to a row: ends it, or leaves it with
// pending.
type rowEnd struct {
	end     bool
	pending string
}

// judge runs row k through the batch's entries in order: those up to its
// position in ce's namespace are skipped, and of the rest each document
// must still give the row's key and roles (holds). The row ends at the
// first that doesn't.
func (ce *cookieEnds) judge(k viewKeyRow, holds func(cfg *grantcheck.Config) bool) rowEnd {
	p := decodePending(k.pending)
	for _, st := range ce.steps {
		if pos, waits := p[ce.ns]; waits {
			if head, _, _ := strings.Cut(pos, " "); st.id != "" && st.id == head {
				delete(p, ce.ns)
			}
			continue
		}
		if st.hasDoc && st.cfg != nil && !holds(st.cfg) {
			return rowEnd{end: true, pending: k.pending}
		}
	}
	return rowEnd{pending: encodePending(p)}
}

// ownHolds judges row k of cfg's namespace by cfg alone, as entryOfIn
// does for a namespace without a base.
func ownHolds(cfg *grantcheck.Config, k viewKeyRow) bool {
	roles, ok := decodeStrings(k.roles)
	if !ok {
		return false
	}
	i := slices.IndexFunc(cfg.Keys, func(o grant.Key) bool { return o.Kid == k.kid })
	if i < 0 || cfg.Keys[i].Raw == nil {
		return false
	}
	key := cfg.Keys[i]
	rs, ok := readRoleDefs(cfg.Doc, roles)
	if !ok {
		return false
	}
	return k.pub != "" && keyPub(key) == k.pub && key.Lists("read") && entryDigest(key.Raw, rs) == k.entry
}

// cookieEnds judges batch b of ns, and snap, the document a snapshot is
// taken at, if any.
func (ix *Index) cookieEnds(ctx context.Context, ns string, b *follow.Batch, snap *client.NSDoc) (*cookieEnds, error) {
	ce := &cookieEnds{all: b.Replaces(), ns: ns, own: true, seen: map[string]map[viewKeyRow]rowEnd{ns: {}}}
	docs := 0
	step := func(id string, d *client.NSDoc) {
		st := confStep{id: id}
		if d != nil {
			docs++
			st.hasDoc, st.digest = true, confDigest(d.Value)
			cfg, err := grantcheck.ParseConfig(ns, "", d.Value)
			if err == nil {
				st.cfg = cfg
			}
			ce.own = ce.own && err == nil && cfg.Base == ""
		}
		ce.steps = append(ce.steps, st)
	}
	for _, u := range b.Units {
		step(u.Entry.ID, u.Config)
	}
	if snap != nil {
		step("", snap)
	}
	if !b.Partial() {
		step(b.NewCheckpoint, nil)
	}
	q := `SELECT DISTINCT marker, kid, roles, pub, entry, pending, chain FROM edge_view_keys WHERE entry <> ''`
	if docs == 0 && !ce.all {
		// No document to judge: only rows waiting for an entry matter.
		q += ` AND pending <> ''`
	}
	rows, err := ix.db.QueryContext(ctx, q)
	if err != nil {
		return nil, err
	}
	live := map[string][]viewKeyRow{}
	for rows.Next() {
		var m string
		var k viewKeyRow
		if err := rows.Scan(&m, &k.kid, &k.roles, &k.pub, &k.entry, &k.pending, &k.chain); err != nil {
			rows.Close()
			return nil, err
		}
		if n, ok := markerNS(m); ok && !slices.Contains(live[n], k) {
			live[n] = append(live[n], k)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for n, ks := range live {
		// cfg is n's document where n isn't ns, as the checker holds it.
		// A row whose own chain names ns draws on it whatever the checker
		// says now; without n's document it ends at the first document
		// judged.
		var cfg *grantcheck.Config
		if n != ns {
			var draws bool
			if cfg, draws = ix.drawsOn(ctx, n, ns); !draws {
				ks = slices.DeleteFunc(slices.Clone(ks), func(k viewKeyRow) bool { return !k.drawsOn(ns) })
				if len(ks) == 0 {
					continue
				}
				cfg = nil
			}
		}
		seen := ce.seen[n]
		if seen == nil {
			seen = map[viewKeyRow]rowEnd{}
			ce.seen[n] = seen
		}
		for _, k := range ks {
			if ce.all {
				seen[k] = rowEnd{end: true}
				continue
			}
			seen[k] = ce.judge(k, func(at *grantcheck.Config) bool {
				if n != ns && cfg == nil {
					return false // its chain can't be read for now
				}
				roles, ok := decodeStrings(k.roles)
				if !ok {
					return false
				}
				in := cfg
				if n == ns {
					in = at
				}
				entry, key, ok, err := ix.entryOfIn(ctx, in, k.kid, roles, map[string]*grantcheck.Config{ns: at})
				return err == nil && ok && k.pub != "" && keyPub(key) == k.pub && key.Lists("read") && entry == k.entry
			})
		}
	}
	return ce, nil
}

// drawsOn reports whether the keys of namespace n may come from ns: n is
// a local branch whose chain of bases reaches ns, by the documents the
// checker holds, with n's. A namespace that is purged or gone draws on
// nothing any more: its last document is the one its cookies are judged
// by (purgedKeysHold). One whose chain can't be read for now may: true
// with no document, and its rows end.
func (ix *Index) drawsOn(ctx context.Context, n, ns string) (*grantcheck.Config, bool) {
	cfg, err := ix.checker.Config(ctx, n)
	if client.IsPurged(err) || client.IsNotFound(err) {
		return nil, false
	}
	if err != nil {
		return nil, true
	}
	cur := cfg
	for depth := 0; cur.Base != "" && depth < maxChain; depth++ {
		if cur.Base == ns {
			return cfg, true
		}
		next, err := ix.checker.Config(ctx, cur.Base)
		if client.IsPurged(err) || client.IsNotFound(err) {
			return nil, false
		}
		if err != nil {
			return nil, true
		}
		cur = next
	}
	return nil, false
}

// drawsOn reports whether the row's key was drawn through base ns
// (chain).
func (k viewKeyRow) drawsOn(ns string) bool {
	chain, _ := decodeStrings(k.chain)
	return k.chain != "" && slices.Contains(chain, ns)
}

// markerNS is the namespace of a marker reads:{ns}:….
func markerNS(m string) (string, bool) {
	rest, ok := strings.CutPrefix(m, "reads:")
	if !ok {
		return "", false
	}
	ns, _, ok := strings.Cut(rest, ":")
	return ns, ok && ns != ""
}

// apply writes, in tx, what ce found: the rows ended, and those that
// left pending. A row it didn't see, recorded between its reading and tx
// by an exchange that may have verified its grant under a document the
// batch is only now applying, is judged here: one of the batch's
// namespace by the batch's documents alone where they say everything
// (own); one of another namespace that waits for an entry of this one,
// or whose namespace was judged, by no document, so it ends if the
// whose own chain names it (viewKeyRow.chain), or whose namespace was
// judged, by no document, so it ends if the batch brings one. What can't
// be told is refused.
//
// The statements match a namespace's markers by substr(marker, 1, n)
// with n a length in bytes, where SQLite counts characters: a namespace
// name is ASCII (§3.6, client.ValidNSName: [a-z0-9][a-z0-9_-]{0,63}), so
// the two agree.
func (ce *cookieEnds) apply(ctx context.Context, tx *sql.Tx) error {
	if ce == nil {
		return nil
	}
	rows, err := tx.QueryContext(ctx, `SELECT DISTINCT marker, kid, roles, pub, entry, pending, chain FROM edge_view_keys WHERE entry <> ''`)
	if err != nil {
		return err
	}
	type change struct {
		n string
		k viewKeyRow
		r rowEnd
	}
	var todo []change
	done := map[string]map[viewKeyRow]bool{}
	for rows.Next() {
		var m string
		var k viewKeyRow
		if err := rows.Scan(&m, &k.kid, &k.roles, &k.pub, &k.entry, &k.pending, &k.chain); err != nil {
			rows.Close()
			return err
		}
		n, ok := markerNS(m)
		if !ok || done[n][k] {
			continue
		}
		if done[n] == nil {
			done[n] = map[viewKeyRow]bool{}
		}
		done[n][k] = true
		_, waits := decodePending(k.pending)[ce.ns]
		r, judged := ce.seen[n][k]
		switch {
		case judged:
		case n != ce.ns && ce.seen[n] == nil && !waits && !k.drawsOn(ce.ns):
			continue
		case ce.all:
			r = rowEnd{end: true}
		case n == ce.ns && ce.own:
			r = ce.judge(k, func(cfg *grantcheck.Config) bool { return ownHolds(cfg, k) })
		default:
			r = ce.judge(k, func(*grantcheck.Config) bool { return false })
		}
		if r.end || r.pending != k.pending {
			todo = append(todo, change{n, k, r})
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, c := range todo {
		prefix := "reads:" + c.n + ":"
		set, arg := `entry = ''`, []any{}
		if !c.r.end {
			set, arg = `pending = ?`, []any{c.r.pending}
		}
		arg = append(arg, len(prefix), prefix, c.k.kid, c.k.roles, c.k.pub, c.k.entry, c.k.pending, c.k.chain)
		if _, err := tx.ExecContext(ctx, `UPDATE edge_view_keys SET `+set+` WHERE substr(marker, 1, ?) = ? AND kid = ? AND roles = ? AND pub = ? AND entry = ? AND pending = ? AND chain = ?`, arg...); err != nil {
			return err
		}
	}
	return nil
}

// scopeKeysHold checks a cookie for scope marker m of ns, whose record is
// rec, as §7.9 view ends a view cookie (§A.4: "a cookie is 403 until the
// reader exchanges again ... where a marker's key, rules or roles would
// end a view cookie"): keysHold, each role a key digested still existing
// and listing read, and the scope digest over the current rules, with
// rec's block rules and principal and the key's key: string, still m's
// (scopeMarker).
func (ix *Index) scopeKeysHold(ctx context.Context, ns, m string, rec *markerRec, exp int64) error {
	return ix.keysHold(ctx, ns, m, exp, func(cfg *grantcheck.Config, key grant.Key, k viewKey) bool {
		return viewKeyHolds(cfg, []grant.Key{key}, rec.f, k, func(d string) bool { return scopeMarker(ns, d, k.kid, k.pub) == m })
	})
}

// readsKeysHold checks a cookie for marker reads:{ns}:{k}, m, that expires
// at exp, as scopeKeysHold checks a scope marker's (§A.4 view: a cookie is
// 403 "where a marker's key, rules or roles would end a view cookie
// (§7.9 view), its key being the one that verified the grant in {ns},
// reads:{ns}:{k} markers included"): keysHold. Readers through one key
// with other read roles, or with its entry as it was before a change,
// share the marker, never a cookie (recordCookies).
func (ix *Index) readsKeysHold(ctx context.Context, ns, m string, exp int64) error {
	return ix.keysHold(ctx, ns, m, exp, nil)
}

// purgedGKeysHold checks a cookie for g: marker m of purged ns, whose record
// is rec, which has no checkpoint left to be judged at (storedFview): as
// there, by ns's document at its head (keysHold).
func (ix *Index) purgedGKeysHold(ctx context.Context, ns, m string, rec *markerRec, exp int64) error {
	return ix.keysHold(ctx, ns, m, exp, func(cfg *grantcheck.Config, key grant.Key, k viewKey) bool {
		return viewKeyHolds(cfg, []grant.Key{key}, rec.f, k, func(d string) bool {
			return slices.Contains(rec.subjects, grantcheck.ScopePrefix+scopeKeyDigest(d, k.kid, k.pub))
		})
	})
}

// errCoveredNow refuses a cookie for marker reads:{ns}:scope:… once
// §7.9 covers ns: a partial reader's marker there is reads:{ns}:g:{view},
// its hits filtered by visibility (§A.4), which rules alone don't do.
var errCoveredNow = &grant.AuthError{Status: 403, Msg: "the namespace is read filtered now: exchange the grant again (§7.9)"}

// stillUncovered checks that §7.9 doesn't cover ns at the index's
// committed checkpoint, as when a scope marker of it was issued: else
// errCoveredNow. Before the index's first checkpoint
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
	return nil
}

// refsCookieReader is the reader of /_refs under one of the service's
// edge grants for /_refs/view/{view} (ok false without one): its view,
// whose markers decide which private namespaces it sees and how
// (markerAccess); every public one is seen too. A namespace a marker
// names whose document the service can't read is 502, as one a grant
// names.
func (ix *Index) refsCookieReader(ctx context.Context, r *http.Request, reached map[string]string) (*refsReader, bool, error) {
	cl := ix.edgeClaims(r)
	if cl == nil {
		return nil, false, nil
	}
	cns, vid, ok := edgeView(cl.Prefix)
	if !ok || cns != "" {
		return nil, false, nil
	}
	subs, ok := ix.edge.Subjects(ctx, cl.Prefix)
	if !ok {
		return nil, true, errUnknownSet
	}
	rd := &refsReader{vid: vid, public: true, allow: map[string]allowFunc{}, covs: map[string]*access{}}
	for _, ns := range ix.refsNamespaces() {
		if _, ok := reached[ns]; !ok || ix.keys.Skipped(ns) != "" || ix.basesUnfollowed(ctx, ns) {
			continue
		}
		i := slices.IndexFunc(subs, func(m string) bool {
			return strings.HasPrefix(m, readsPrefix(ns)) || strings.HasPrefix(m, "reads:"+ns+":scope:") || strings.HasPrefix(m, "reads:"+ns+":g:")
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
// grants for ns's view, which the service knows, it passes, and
// the head is cfgErr's (§8.5).
func (ix *Index) purgedRead(ctx context.Context, ns string, r *http.Request, cfgErr error) (string, error) {
	if cl := ix.edgeClaims(r); cl != nil {
		if cns, _, ok := edgeView(cl.Prefix); ok && cns == ns {
			subs, known := ix.edge.Subjects(ctx, cl.Prefix)
			if !known || len(subs) != 1 {
				return "", errUnknownSet
			}
			// Its keys can't be judged again (keysHold): a cookie
			// recorded with none, or with one that never held, is 403.
			recorded, err := ix.viewKeysAt(ctx, subs[0], cl.Exp)
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
		svcWithdraw(w, r, ix.opt.EdgeGrants, func(p string) bool { _, _, ok := edgeView(p); return ok },
			"/{ns}/view/{view} or /_refs/view/{view} (§A.4)")
	default:
		ix.issueEdgeGrants(w, r)
	}
}

// maxPrefixes is how many distinct prefixes one exchange may give
// (§C.5.2).
const maxPrefixes = 100

// exchanged is what one grant of an exchange gives: its edge grants, the
// markers behind each view, what each marker stands for and the key it came
// from (markerRec, for every marker), and the exchangeRate bucket of its
// principal.
type exchanged struct {
	issues   []svcIssue
	subjects map[string][]string
	filters  map[string]*markerRec
	bucket   string
}

// issueEdgeGrants is POST /edge-grants (§A.4, §B.11.5, following §C.5.2's
// issuance): with the grant in Authorization, or 1 to svcMaxGrants
// grants as { "grants": [ … ] } in an application/json body (415
// otherwise, svcBearers), it answers 200 { prefixes, exp } and one
// Set-Cookie per prefix. Each grant gives, for every private namespace
// the service follows that it names, /{ns}/view/{view} of the reader's
// marker there (exchangeGrant), and /_refs/view/{view} of its markers in those
// the service has reached, each lasting until the grant's exp or the
// cookies' TTL (15 minutes at most), whichever is sooner. A prefix
// several grants give gets one cookie, lasting as long as the longest,
// and exp is the earliest. Within a grant each namespace is judged alone,
// one it gets no marker in left out (exchangeGrant, §A.4); across grants
// it answers all or nothing (§C.5.2): a grant over grantSize or
// rulesPerGrant is 413 limit (§C.8); a grant left with no edge grant is
// refused 401 if any such is 401, else 403; else, where a namespace
// document a grant names can't be read, 502 if any such failure is
// lasting and 503 behind only if every one is for now (worseUpstream;
// §C.5.2); once none is, a grant left with
// no edge grant whose only refusals are purges is 410 purged, with ns and
// head naming the first in the order the grants and their root blocks
// list them (§8.5).
// More than maxPrefixes prefixes is 400.
// Once nothing is refused, it draws one token from the exchangeRate
// bucket of each distinct principal among the grants (ExchangeRate,
// §6.6), shared with the instances on its database (edgeStore), and
// is 429 (code "rate", limit "exchangeRate", with Retry-After) while any
// is empty. While the core's authentication is disabled (§1), it is 404
// not_offered, before the body is read; it takes no query parameter (400,
// §7). Cookies are Secure, HttpOnly and SameSite as EdgeGrants says.
func (ix *Index) issueEdgeGrants(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	// Whether the core's authentication is on is what its root says now
	// (authOff: read again once CheckerTTL has passed), never what an
	// earlier read said (§7.9 Where, v0.82). While the root can't be
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
	bearers, refusal := svcBearers(r, svcDefaultGrantSize)
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
		exs     []*exchanged
		limit   *grantcheck.LimitError
		denied  *grant.AuthError
		upErr   error
		purged  *purgedNS
		unavail bool
	)
	for _, b := range bearers {
		ex, pn, err := ix.exchangeGrant(ctx, b, reached, now)
		var le *grantcheck.LimitError
		var ae *grant.AuthError
		switch {
		case errors.Is(err, errUnavailable):
			unavail = true
		case errors.As(err, &le):
			if limit == nil {
				limit = le
			}
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
		svcLimit(limit.Limit, limit.Measured, limit.Max).Write(w)
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
	case unavail:
		// 404 as a query of it is, no other refusal being 401 or 403;
		// never 410, as a namespace refused isn't purged (§C.5.2 All or
		// nothing, SERVICES §A.4 Unavailable namespaces, v0.90).
		writeErr(w, http.StatusNotFound, "not_found", "a namespace the grants name is not indexed")
		return
	case purged != nil:
		purged.write(w)
		return
	}
	var issues []svcIssue
	subjects := map[string][]string{}
	filters := map[string]*markerRec{}
	var keys []string
	for _, ex := range exs {
		issues = append(issues, ex.issues...)
		for vid, subs := range ex.subjects {
			subjects[vid] = subs
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
	issues = svcMerge(issues)
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
		svcRateLimited(wait).Write(w)
		return
	}
	// What each marker stands for, and the keys it came from, per cookie:
	// recordCookies gives each edge grant the exp that tells it from
	// every cookie minted for other keys or entries, at most the one it
	// was to have, which the view, the cookie and the answer then
	// carry.
	recs := make([]*cookieRec, len(issues))
	for i, is := range issues {
		recs[i] = &cookieRec{filters: map[string]*markerRec{}, exp: is.Exp}
		for _, m := range subjects[is.Prefix] {
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
		p := issues[i].Prefix
		if err := ix.edge.Record(ctx, p, subjects[p], issues[i].Exp, now); err != nil {
			ix.opt.Logf("index: recording a subject set: %v", err)
			writeErr(w, http.StatusInternalServerError, "internal", "cannot record the subject set")
			return
		}
	}
	svcMint(w, ix.opt.EdgeGrants, now, issues)
}

// worseUpstream is the one of cur and err, failures to read upstream
// what an exchange needs, that answers it: the first that is lasting
// (502 upstream), else the first (503 behind), so that an exchange is 503
// only where every such failure is for now, whatever the order of its
// grants and of the namespaces each names (writeUpstreamErr).
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
// marker gives /{ns}/view/{view} of the reader's marker there, and the markers
// of those reached and not skipped give /_refs/view/{view} over them, as
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
		views   = map[string]string{}
		refsExp time.Time
		upErr   error
		denied  *grant.AuthError
	)
	// deny notes a namespace the grant gets no marker in: left out, the
	// first 401 answering if nothing is left, else the first 403.
	deny := func(err error) bool {
		var ae *grant.AuthError
		if !errors.As(err, &ae) {
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
	// unavailable notes a namespace the grant names that the service
	// doesn't follow, or answers as such: 404, at the exchange too, only
	// where no other refusal is 401 or 403 (SERVICES §A.4 Unavailable
	// namespaces, v0.90).
	unavailable := false
	if len(g.Blocks) > 0 {
		for _, ns := range g.Blocks[0].NS {
			if ns != "*" && !ix.known(ns) && g.NamesNS(ns) {
				unavailable = true
			}
		}
	}
	for _, ns := range namedInOrder(g, ix.refsNamespaces()) {
		tries := 1
	again:
		if _, lacks := ix.keys.Skip(ns); lacks || ix.basesUnfollowed(ctx, ns) {
			// One the service doesn't follow (§A.4): a sealed one whose
			// keys it lacks, or a branch whose bases' logs it doesn't all
			// follow (§C.4 Keys follow the base). No marker, no cookie.
			unavailable = true
			continue
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
		// Every marker, reads:{ns}:{k} included, records the key that
		// verified the grant here and its entry (§A.4 view).
		rec := markerRecOf(a, v)
		var behind, moved bool
		// With the entry, the documents it was drawn from that the index
		// has yet to reach, for it to tell those of its backlog from the
		// ones after (cookieEnds).
		rec.key, behind, moved = ix.exchangeEntry(ctx, ns, cfg.Head, a, v, rec.key)
		if moved && tries < exchangeTries {
			// The document moved while the grant was judged: judged again
			// from the document it moved to.
			tries++
			goto again
		}
		if behind || moved {
			fail(errExchangeBehind)
			continue
		}
		ex.filters[a.marker] = rec
		if _, _, ok := edgeView(nsPrefix(ns, a.vid)); ok {
			ex.issues = append(ex.issues, svcIssue{Prefix: nsPrefix(ns, a.vid), Exp: exp})
			ex.subjects[nsPrefix(ns, a.vid)] = []string{a.marker}
		}
		if _, ok := reached[ns]; ok && ix.keys.Skipped(ns) == "" {
			markers = append(markers, a.marker)
			views[ns] = a.vid
			if refsExp.IsZero() || exp.Before(refsExp) {
				refsExp = exp
			}
		}
	}
	if upErr != nil {
		return nil, nil, upErr
	}
	if len(markers) > 0 {
		vid := refsViewID(views)
		slices.Sort(markers)
		ex.issues = append(ex.issues, svcIssue{Prefix: refsPrefix(vid), Exp: refsExp})
		ex.subjects[refsPrefix(vid)] = markers
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
	if unavailable {
		return nil, nil, errUnavailable
	}
	return nil, nil, &grant.AuthError{Status: 403, Msg: "the grant reads no private namespace this service follows"}
}

// errUnavailable is an exchange whose grant gets no edge grant, no
// refusal of it is 401 or 403, and a namespace it names is one the
// service doesn't follow or answers as such: 404, as a query of it is
// (SERVICES §A.4 Unavailable namespaces, v0.90).
var errUnavailable = errors.New("namespace not indexed")

// basesUnfollowed reports whether ns is a branch a base of whose chain
// the service doesn't follow, so that it can't judge a cookie by every
// entry of its bases (basesJudged): it is answered as unfollowed, 404,
// its exchange minting no cookie, and /_refs leaves it out (SERVICES §A.4
// Unavailable namespaces, v0.90; §C.4 Keys follow the base). Until v0.90
// such an exchange minted a cookie under which every read was 403. A
// document that can't be read now is left to the read check.
func (ix *Index) basesUnfollowed(ctx context.Context, ns string) bool {
	cfg, err := ix.checker.Config(ctx, ns)
	if err != nil || cfg.Base == "" {
		return false
	}
	return errors.Is(ix.basesJudged(ctx, cfg), errRulesChanged)
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
// vouches only for its own prefixes (edgeView), and their state lives in
// the database (edgeStore, and edge_filters, migration 004).
func (ix *Index) initEdge(ctx context.Context, db *sql.DB) error {
	ix.filters = map[string]keptFilter{}
	if ix.opt.EdgeGrants == nil {
		return nil
	}
	ix.opt.EdgeGrants.Vouches = func(p string) bool { _, _, ok := edgeView(p); return ok }
	if ix.opt.ExchangeRate.Rate <= 0 || ix.opt.ExchangeRate.Burst < 1 {
		ix.opt.ExchangeRate = DefaultExchangeRate
	}
	ix.edge = newEdgeStore(db)
	return nil
}

// maxChain bounds a branch's chain of bases (the deployment's branch
// depth is 8 by default, grantcheck's bound 32).
const maxChain = 32
