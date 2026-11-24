package core

import (
	"context"
	"database/sql"
	"strings"

	"github.com/middle-management/patchlog/internal/grant"
	"github.com/middle-management/patchlog/internal/jsonv"
)

// The deployment's namespaces, for operators (§7.4 GET /ns, v0.84).

// NamespacesPage is a page of GET /ns?after={name} (§7.4): rows of
// { name, created, base?, frozen, purged } in ascending byte order of
// name, and the name the next page starts after, "" on the last page.
type NamespacesPage struct {
	Items []map[string]any
	Next  string
}

// Namespaces lists the deployment's namespaces after the name after, a
// plain bound, and, if prefix isn't "", starting with it, a namespace
// name (400 bad_input otherwise, a request-shape error, §6.2), paged by
// logPageSize (§6.6). Branches and purged namespaces are listed (§7.4).
//
// It answers operator grants only (§C.4, namespaceLister), and everyone
// while authentication is disabled (§1).
func (e *Engine) Namespaces(ctx context.Context, after, prefix string, cred Credentials) (*NamespacesPage, error) {
	if prefix != "" && !ValidNSName(prefix) {
		return nil, badInput("prefix is not a namespace name (§3.6, §7.4)")
	}
	// No edge cookie covers the listing: it is the origin's, answered by
	// the grant in Authorization (§C.5).
	cred.Edge = nil
	var out *NamespacesPage
	err := e.read(ctx, func(t *tx) error {
		if err := t.namespaceLister(cred); err != nil {
			return err
		}
		out = t.pageNamespaces(after, prefix, e.opt.Maximums.LogPageSize)
		return nil
	})
	return out, err
}

// namespaceLister checks the credentials of GET /ns (§7.4), in its order:
//
//   - the request-shape checks of §C.2 item 1, as the grant is decoded:
//     grantSize (413), blocks that can't be parsed (401), rulesPerGrant
//     (413), a rule that isn't valid (401); a request without credentials
//     is 401 here, having no blocks to check;
//   - 403 for a grant with a block that carries ns without naming "*";
//   - 401 for a grant that fails verification by the operator keys in
//     force: its root kid names no operator key in its period (§C.4), a
//     signature, nbf and exp, a revocation;
//   - 403 for a grant the operator key's scope doesn't allow, as on any
//     other request (§C.2 item 1; CONFORMANCE Access 80);
//   - 403 for a grant that carries roles, one with a block that lists
//     roles, an empty list too (§2.1): an operator grant has no effective
//     role, so nothing allows config (§C.2 Invariant). And for a block
//     that carries can without config, or carries non-empty rules: a
//     narrowing block without can keeps the verbs it was given, and
//     "rules": [] is none (v0.85).
func (t *tx) namespaceLister(cred Credentials) *Error {
	if t.e.opt.AuthDisabled {
		return nil
	}
	// "*" is named by exactly the blocks the ns check accepts here.
	g, err := t.decodeGrant("*", cred)
	if err != nil {
		if err.Status == 403 {
			return forbidden(`listing namespaces needs an operator grant whose blocks name "*" in ns (§7.4)`)
		}
		return err
	}
	keys := t.operatorKeys()
	if keys == nil {
		keys = []grant.Key{}
	}
	a, err := t.verifyGrant(g, "*", nil, nil, keys)
	if err != nil {
		// 401 for no usable grant, 403 for one the key's scope doesn't
		// allow (authErr).
		return err
	}
	t.e.bearers.put(cred.Bearer, g)
	for _, b := range g.Blocks {
		if _, ok := b.Raw["roles"]; ok {
			return forbidden("a grant that carries roles doesn't list namespaces: an operator grant has no effective role (§7.4)")
		}
		if b.HasCan && !contains(b.Can, "config") {
			return forbidden("listing namespaces needs config in the can of every block of the grant that carries can (§7.4)")
		}
		if r, ok := b.Raw["rules"].([]any); ok && len(r) > 0 {
			return forbidden("a grant with rules in a block doesn't list namespaces (§7.4)")
		}
	}
	if ok, _ := a.verified.Allows("config"); !ok {
		return forbidden("the grant does not allow config")
	}
	return nil
}

// plainBound is after as a bound the database can compare names with: a
// namespace name is ASCII (§3.6), and after is any string. From its first
// NUL, which sorts below every byte of a name, after is cut, and from its
// first byte above ASCII, which sorts above them all, it is replaced by
// DEL: either way the same names are greater than it, and the bound is
// text Postgres accepts.
func plainBound(after string) string {
	for i := 0; i < len(after); i++ {
		switch c := after[i]; {
		case c == 0:
			return after[:i]
		case c >= 0x7f:
			return after[:i] + "\x7f"
		}
	}
	return after
}

// namesBelow sorts above every byte of a namespace name (§3.6), so every
// namespace's name is below it.
const namesBelow = "~"

// pageNamespaces is a page of at most limit rows of GET /ns (§7.4). One
// query reads the names, in byte order from the index on name (the "C"
// collation on Postgres, index namespaces_name_c; SQLite's BINARY), each
// with the created time of its chain's first entry (index one_ns_first),
// and one more the namespace documents the configuration cache lacks.
func (t *tx) pageNamespaces(after, prefix string, limit int) *NamespacesPage {
	col := "n.name"
	if t.e.pg && !t.e.spanner { // Spanner's order is byte order, and it has no COLLATE
		col = `n.name COLLATE "C"`
	}
	lower, bound, upper := ` > ?`, plainBound(after), namesBelow
	if prefix != "" {
		if prefix > bound {
			// An after below the prefix starts at it.
			lower, bound = ` >= ?`, prefix
		}
		upper = prefixEnd(prefix)
	}
	// One row more than the page, so next stays absent on the last page.
	rows, err := t.Query(`SELECT n.name, n.purged, n.config_seq, f.created
		FROM namespaces n LEFT JOIN ns_log f ON f.ns = n.ns AND f.prev_seq IS NULL
		WHERE `+col+lower+` AND `+col+` < ? ORDER BY `+col+` LIMIT ?`, bound, upper, limit+1)
	t.must(err)
	type row struct {
		name    string
		purged  bool
		cfg     sql.NullInt64
		created sql.NullInt64
	}
	var page []row
	for rows.Next() {
		var r row
		t.must(rows.Scan(&r.name, &r.purged, &r.cfg, &r.created))
		if strings.HasPrefix(r.name, prefix) {
			page = append(page, r)
		}
	}
	t.must(rows.Err())
	rows.Close()
	out := &NamespacesPage{Items: []map[string]any{}}
	if len(page) > limit {
		page = page[:limit]
		out.Next = page[limit-1].name
	}
	seqs := make([]int64, 0, len(page))
	for _, r := range page {
		if r.cfg.Valid {
			seqs = append(seqs, r.cfg.Int64)
		}
	}
	docs := t.listedDocs(seqs)
	for _, r := range page {
		d := docs[r.cfg.Int64]
		m := map[string]any{"name": r.name, "frozen": d.frozen, "purged": r.purged}
		if r.created.Valid {
			m["created"] = formatTime(r.created.Int64)
		}
		if d.base != nil {
			m["base"] = d.base
		}
		out.Items = append(out.Items, m)
	}
	return out
}

// listedDoc is what a row of GET /ns takes from a namespace document
// (§7.4): frozen (§8.4), and base (§7.6) without chain.
type listedDoc struct {
	frozen bool
	base   map[string]any
}

// listedDocs reads frozen and base of the namespace documents seqs: from
// the configuration cache where it has them, and the rest in one query,
// without caching them, so a listing doesn't hold every namespace's
// configuration in memory.
func (t *tx) listedDocs(seqs []int64) map[int64]listedDoc {
	out := make(map[int64]listedDoc, len(seqs))
	var want []int64
	t.e.cfgMu.Lock()
	for _, s := range seqs {
		c, ok := t.e.cfgCache[s]
		if !ok {
			want = append(want, s)
			continue
		}
		d := listedDoc{frozen: c.Frozen}
		if b := c.Base; b != nil {
			d.base = map[string]any{"ns": b.NS, "at": b.At}
		}
		out[s] = d
	}
	t.e.cfgMu.Unlock()
	if len(want) == 0 {
		return out
	}
	rows, err := t.Query(`SELECT seq, doc FROM ns_config WHERE `+t.e.inArray("seq", "bigint"), t.e.arrayArg(want))
	t.must(err)
	defer rows.Close()
	for rows.Next() {
		var seq int64
		var doc string
		t.must(rows.Scan(&seq, &doc))
		m, _ := jsonv.MustParse([]byte(doc)).(map[string]any)
		d := listedDoc{frozen: m["frozen"] == true}
		if b, ok := m["base"].(map[string]any); ok {
			d.base = map[string]any{"ns": b["ns"], "at": b["at"]}
		}
		out[seq] = d
	}
	t.must(rows.Err())
	return out
}
