package core

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"sort"
	"strings"

	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/seal"
)

// Namespaces a pre-v0.78 deployment raised to e2e by a config write, and
// remote branches that mirror a source raised so (Addendum E Levels: a
// namespace is end-to-end from its creation or never; v0.78). What they
// stored before the raise (plaintext revisions, documents and snapshots,
// pre-raise sealings and keys, plain blobs, grants recorded before it) has
// no read path any more, and the E3 paths would serve it in the clear,
// which the Invariant forbids. So Open fails closed, naming each, before
// migration 016 drops the tables that mark them (e2e_raises,
// remote_pending_sealings): an operator exports them with the v0.26.1
// tools, has a key holder import them into new e2e namespaces under new
// names (§G.5.1) and purges them, or starts with Options.PurgeRaisedE2E,
// which purges them at Open, destroying their epoch keys (§8.5), so they
// answer 410 purged.

// legacyE2E is what checkLegacyE2E found: the raised namespaces, and the
// remote branches whose shadows were raised or hold pending pre-raise
// sealings, by name.
type legacyE2E struct {
	raised, remote []string
}

func (l *legacyE2E) empty() bool { return l == nil || len(l.raised)+len(l.remote) == 0 }

// names lists them for an operator.
func (l *legacyE2E) names() string {
	var parts []string
	for _, n := range l.raised {
		parts = append(parts, "namespace "+n)
	}
	for _, n := range l.remote {
		parts = append(parts, "remote branch "+n)
	}
	return strings.Join(parts, ", ")
}

// errLegacyE2E is Open's refusal of a database that holds them.
func errLegacyE2E(l *legacyE2E) error {
	return fmt.Errorf("core: this database holds content stored before a raise to e2e, which a namespace can no longer have (Addendum E Levels; v0.78) and this version would serve weaker than it was stored: %s. "+
		"Before upgrading, export each with the v0.26.1 tools, have a key holder import it into a new e2e namespace under a new name (§G.5.1), then purge it, "+
		"its local branches first; a remote branch is purged and created again against a source that is e2e from its creation. "+
		"Or start once with -purge-raised-e2e, which purges them and their local branches now, destroying their keys: they then answer 410 purged", l.names())
}

// tableExists reports whether the schema has table name, before
// migrations run (a fresh database has none, one already past 016 lacks
// the marker tables).
func tableExists(db *sql.DB, pg bool, name string) (bool, error) {
	if pg {
		var reg sql.NullString
		err := db.QueryRow(`SELECT to_regclass('` + name + `')::text`).Scan(&reg)
		return reg.Valid, err
	}
	var n int
	err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = '` + name + `'`).Scan(&n)
	return n > 0, err
}

// checkLegacyE2E finds the raised namespaces and the remote branches of
// raised sources in db, before it is migrated: every unpurged namespace or
// shadow with an e2e_raises row, and every shadow with a
// remote_pending_sealings row. A shadow ("~{branch}" or "~{branch}~{i}")
// names its remote branch.
func checkLegacyE2E(db *sql.DB, pg bool) (*legacyE2E, error) {
	l := &legacyE2E{}
	remote := map[string]bool{}
	add := func(name string) {
		if strings.HasPrefix(name, "~") {
			b, _, _ := strings.Cut(name[1:], "~")
			remote[b] = true
			return
		}
		l.raised = append(l.raised, name)
	}
	for _, q := range []struct{ table, query string }{
		{"e2e_raises", `SELECT n.name FROM e2e_raises r JOIN namespaces n ON n.ns = r.ns WHERE n.purged = 0 ORDER BY n.name`},
		{"remote_pending_sealings", `SELECT DISTINCT n.name FROM remote_pending_sealings p JOIN namespaces n ON n.ns = p.shadow ORDER BY n.name`},
	} {
		ok, err := tableExists(db, pg, q.table)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		rows, err := db.Query(q.query)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var name string
			if err := rows.Scan(&name); err != nil {
				rows.Close()
				return nil, err
			}
			add(name)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, err
		}
	}
	for b := range remote {
		l.remote = append(l.remote, b)
	}
	sort.Strings(l.remote)
	l.raised = dedupSorted(l.raised)
	return l, nil
}

func dedupSorted(s []string) []string {
	sort.Strings(s)
	out := s[:0]
	for i, x := range s {
		if i == 0 || x != s[i-1] {
			out = append(out, x)
		}
	}
	return out
}

// purgeRaisedE2E purges what checkLegacyE2E found, once the schema is
// migrated (Options.PurgeRaisedE2E): each namespace and remote branch, and
// every local branch of them, leaves first, through the namespace purge
// (purgeNSNow), which destroys their epoch keys and their shadows'
// content (§8.5, §G.3). The purge-ns entries are by RotateAuthor's
// sibling, the system author UpgradeAuthor.
func (e *Engine) purgeRaisedE2E(ctx context.Context, l *legacyE2E) error {
	if l.empty() {
		return nil
	}
	return e.update(ctx, func(t *tx) error {
		author := t.authorID(UpgradeAuthor)
		var order []*nsRow
		seen := map[int64]bool{}
		var visit func(n *nsRow)
		visit = func(n *nsRow) {
			if n == nil || seen[n.id] {
				return
			}
			seen[n.id] = true
			for _, b := range t.branchesOf(n) {
				visit(b)
			}
			order = append(order, n) // leaves first
		}
		for _, name := range append(append([]string(nil), l.raised...), l.remote...) {
			visit(t.nsByName(name))
		}
		for _, n := range order {
			if n.purged || n.isShadow() {
				continue
			}
			t.purgeNSNow(n, false, author)
			log.Printf("purged namespace %s at start (-purge-raised-e2e): it held content stored before a raise to e2e (Addendum E Levels)", n.name)
		}
		return nil
	})
}

// UpgradeAuthor is the author of the namespace purges Open makes with
// Options.PurgeRaisedE2E.
const UpgradeAuthor = "system:upgrade"

// warnLegacyE2E logs, without refusing, what this version no longer
// reads in end-to-end namespaces (stored.md items 4–6, 17):
//   - keyrings in the pre-v0.63 form or with a pre-v0.76 $nonce, whose
//     entries /keys no longer relays (keyringEntries): a key holder runs
//     the v0.26.1 client's migrate-keyring first;
//   - prune snapshots whose header binds another id than §E.3.1's (at a
//     tombstone horizon, its parent), or carries a pre-v0.63 pl kind or a
//     zip member, which /rev/{id} answers 410 pruned instead
//     (snapshotServable);
//   - $schema pins to schema revisions of the namespaces purged as raised.
func (e *Engine) warnLegacyE2E(ctx context.Context, purged *legacyE2E) {
	var lines []string
	err := e.read(ctx, func(t *tx) error {
		rows, err := t.Query(`SELECT ` + nsCols + ` FROM namespaces WHERE purged = 0`)
		t.must(err)
		var nss []*nsRow
		for rows.Next() {
			n, err := scanNS(rows)
			t.must(err)
			nss = append(nss, n)
		}
		rows.Close()
		for _, n := range nss {
			if n.isShadow() || !t.isE2E(n) {
				continue
			}
			if d := t.ownKeyring(n, nil); d != nil && !keyringV2(d) {
				lines = append(lines, fmt.Sprintf("namespace %s: its keyring is in a form from before v0.76, so /keys relays none of its entries; run the v0.26.1 client's patchlog e2e migrate-keyring", n.name))
			}
		}
		srows, err := t.Query(`SELECT n.name, r.name, s.jwe, v.id, v.kind, v.parent_seq FROM e2e_snapshots s JOIN resources r ON r.res = s.res JOIN namespaces n ON n.ns = r.ns JOIN revisions v ON v.res = s.res AND v.seq = s.seq WHERE n.purged = 0 AND n.name NOT LIKE '~%' AND r.state <> ?`, statePurged)
		t.must(err)
		type snap struct {
			ns, name, jwe string
			id            []byte
			kind          int
			parent        sql.NullInt64
		}
		var snaps []snap
		for srows.Next() {
			var s snap
			t.must(srows.Scan(&s.ns, &s.name, &s.jwe, &s.id, &s.kind, &s.parent))
			snaps = append(snaps, s)
		}
		srows.Close()
		for _, s := range snaps {
			want := ids.FromBytes(s.id).String()
			if s.kind == kindTombstone {
				want = ""
				if s.parent.Valid {
					want = t.revID(s.parent.Int64).String()
				}
			}
			if !snapshotHeaderServable(s.jwe, s.ns, s.name, want) {
				lines = append(lines, fmt.Sprintf("namespace %s, resource %s: its prune snapshot binds another id than §E.3.1's, or a pre-v0.63 pl or zip, so /rev answers 410 pruned at its horizon", s.ns, s.name))
			}
		}
		return nil
	})
	if err != nil {
		log.Printf("checking for data this version no longer reads: %v", err)
	}
	for _, name := range append(append([]string(nil), purged.raisedOrNil()...), purged.remoteOrNil()...) {
		lines = append(lines, fmt.Sprintf("namespace %s was purged at start: $schema pins to its schema revisions now resolve as purged (schema_unavailable)", name))
	}
	for _, l := range lines {
		log.Printf("warning: %s", l)
	}
}

func (l *legacyE2E) raisedOrNil() []string {
	if l == nil {
		return nil
	}
	return l.raised
}

func (l *legacyE2E) remoteOrNil() []string {
	if l == nil {
		return nil
	}
	return l.remote
}

// keyringV2 reports whether a keyring document is in the v0.76 form
// (§E.3.2), whose entries /keys relays (keyringEntries).
func keyringV2(doc any) bool {
	_, err := seal.CheckKeyringV2(doc)
	return err == nil
}
