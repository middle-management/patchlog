package tree

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/middle-management/patchlog/internal/derived"
	"github.com/middle-management/patchlog/internal/jsonv"
)

// Storage (§B.5, with additions):
//
//	checkpoints(origin, ns, ns_id)   follow.SQLCheckpoints: the catalog and each trusted namespace
//	seen(ns, ns_id)                  every ns_id applied, for ?min= (§A.5)
//	meta(k, v)                       "config": the catalog namespace document; "purged:{ns}"
//	nodes(href, name, kind, item, item_head, title, state, …)
//	                                 one row per node (explicit, or implicit from $parents);
//	                                 raw parents/$access kept to rebuild the graph on start
//	edges(child, pos, parent, ord, state)
//	                                 one row per declared parents entry (hrefs), with its state
//	items(ns, name, state, head)     liveness of every resource of the trusted namespaces
//	self_parents(ns, name, parents)  $parents of content documents (§B.9, -self-placing)
//	sealed_views, sealed_view_tags   sealed listings of a sealed/e2e catalog (derived.Cache)
var createStmts = []string{
	`CREATE TABLE IF NOT EXISTS seen (ns TEXT NOT NULL, ns_id TEXT NOT NULL, PRIMARY KEY (ns, ns_id)) WITHOUT ROWID`,
	`CREATE INDEX IF NOT EXISTS seen_by_id ON seen (ns_id)`,
	`CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT NOT NULL)`,
	`CREATE TABLE IF NOT EXISTS nodes (href TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, kind INTEGER NOT NULL,
		item TEXT, item_head TEXT, title TEXT, state INTEGER NOT NULL DEFAULT 0,
		self INTEGER NOT NULL DEFAULT 0, head TEXT, parents TEXT, access TEXT,
		dangling TEXT, cyclic INTEGER NOT NULL DEFAULT 0, deep INTEGER NOT NULL DEFAULT 0, depth INTEGER NOT NULL DEFAULT -1,
		item_state INTEGER NOT NULL DEFAULT 0)`,
	`CREATE TABLE IF NOT EXISTS edges (child TEXT NOT NULL, pos INTEGER NOT NULL, parent TEXT NOT NULL, ord TEXT,
		state INTEGER NOT NULL, PRIMARY KEY (child, pos))`,
	`CREATE INDEX IF NOT EXISTS edges_by_parent ON edges (parent, ord, child)`,
	`CREATE TABLE IF NOT EXISTS items (ns TEXT NOT NULL, name TEXT NOT NULL, state INTEGER NOT NULL, head TEXT,
		PRIMARY KEY (ns, name)) WITHOUT ROWID`,
	`CREATE TABLE IF NOT EXISTS self_parents (ns TEXT NOT NULL, name TEXT NOT NULL, parents TEXT NOT NULL,
		PRIMARY KEY (ns, name)) WITHOUT ROWID`,
}

var dropStmts = []string{
	`DROP TABLE IF EXISTS checkpoints`, `DROP TABLE IF EXISTS seen`, `DROP TABLE IF EXISTS meta`,
	`DROP TABLE IF EXISTS nodes`, `DROP TABLE IF EXISTS edges`, `DROP TABLE IF EXISTS items`,
	`DROP TABLE IF EXISTS self_parents`, derived.CacheDropStmts[0], derived.CacheDropStmts[1],
}

func canonJSON(v any) string {
	if v == nil {
		return ""
	}
	return string(jsonv.Canonical(v))
}

func parseJSON(s string) any {
	if s == "" {
		return nil
	}
	v, err := jsonv.Parse([]byte(s))
	if err != nil {
		return nil
	}
	return v
}

// persistNode writes a node's row and edges (or deletes them) and records
// what is saved.
func (s *Service) persistNode(ctx context.Context, tx *sql.Tx, g *Graph, name string) error {
	href := g.Href(name)
	if _, err := tx.ExecContext(ctx, `DELETE FROM edges WHERE child = ?`, href); err != nil {
		return err
	}
	n := g.nodes[name]
	if n == nil {
		delete(g.saved, name)
		_, err := tx.ExecContext(ctx, `DELETE FROM nodes WHERE name = ?`, name)
		return err
	}
	var item, itemHead, head, title, dangling any
	if it := n.Item(); it != "" {
		item = it
	}
	if n.ItemHead != "" {
		itemHead = n.ItemHead
	}
	if n.Head != "" {
		head = n.Head
	}
	if n.Title != "" {
		title = n.Title
	}
	if n.Dangling != "" {
		dangling = n.Dangling
	}
	var parents, access any
	if !n.Self {
		if n.rawParents != nil {
			parents = canonJSON(n.rawParents)
		}
		if n.rawAccess != nil {
			access = canonJSON(n.rawAccess)
		}
	}
	_, err := tx.ExecContext(ctx, `INSERT OR REPLACE INTO nodes (href, name, kind, item, item_head, title, state, self, head, parents, access,
		dangling, cyclic, deep, depth, item_state) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		href, name, n.Kind, item, itemHead, title, n.State, b2i(n.Self), head, parents, access,
		dangling, b2i(n.Cyclic), b2i(n.Deep), n.Depth, n.ItemState)
	if err != nil {
		return err
	}
	for i, p := range n.Parents {
		var ord any
		if p.HasOrder {
			ord = p.Order
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO edges (child, pos, parent, ord, state) VALUES (?, ?, ?, ?, ?)`,
			href, i, p.Href, ord, n.EdgeStates[i]); err != nil {
			return err
		}
	}
	g.saved[name] = n.snapshot()
	return nil
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

// loadGraph rebuilds the graph from the database.
func (s *Service) loadGraph(ctx context.Context, q queryer) (*Graph, error) {
	g := newGraph(s.opt.Catalog)
	g.Aliases = s.opt.Branches
	var cfg string
	err := q.QueryRowContext(ctx, `SELECT v FROM meta WHERE k = 'config'`).Scan(&cfg)
	switch {
	case err == nil:
		m, _ := parseJSON(cfg).(map[string]any)
		g.setConfig(m)
	case !errors.Is(err, sql.ErrNoRows):
		return nil, err
	}
	rows, err := q.QueryContext(ctx, `SELECT name, self, head, title, parents, access, state, dangling, cyclic, deep, item_state, item_head FROM nodes`)
	if err != nil {
		return nil, err
	}
	type rowT struct {
		name                    string
		self                    bool
		head, title             sql.NullString
		parents, access         sql.NullString
		state                   int
		dangling                sql.NullString
		cyclic, deep, itemState int
		itemHead                sql.NullString
	}
	var all []rowT
	for rows.Next() {
		var r rowT
		var self int
		if err := rows.Scan(&r.name, &self, &r.head, &r.title, &r.parents, &r.access, &r.state, &r.dangling, &r.cyclic, &r.deep, &r.itemState, &r.itemHead); err != nil {
			rows.Close()
			return nil, err
		}
		r.self = self == 1
		all = append(all, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for _, r := range all {
		g.saved[r.name] = &savedRow{state: r.state, dangling: r.dangling.String, cyclic: r.cyclic == 1, deep: r.deep == 1,
			itemState: r.itemState, itemHead: r.itemHead.String}
		if r.self {
			continue
		}
		doc := map[string]any{}
		if r.title.Valid {
			doc["title"] = r.title.String
		}
		if v := parseJSON(r.parents.String); v != nil {
			doc["parents"] = v
		}
		if v := parseJSON(r.access.String); v != nil {
			doc["$access"] = v
		}
		g.setExplicit(ParseNode(g.Catalog, r.name, r.head.String, doc))
	}
	// Saved edge states.
	erows, err := q.QueryContext(ctx, `SELECT child, pos, state FROM edges ORDER BY child, pos`)
	if err != nil {
		return nil, err
	}
	prefix := len("/r/" + g.Catalog + "/")
	for erows.Next() {
		var child string
		var pos, st int
		if err := erows.Scan(&child, &pos, &st); err != nil {
			erows.Close()
			return nil, err
		}
		if len(child) <= prefix {
			continue
		}
		if sv := g.saved[child[prefix:]]; sv != nil && pos == len(sv.edgeStates) {
			sv.edgeStates = append(sv.edgeStates, st)
		}
	}
	erows.Close()
	if err := erows.Err(); err != nil {
		return nil, err
	}
	// Implicit placements.
	srows, err := q.QueryContext(ctx, `SELECT ns, name, parents FROM self_parents`)
	if err != nil {
		return nil, err
	}
	var selfs []*Node
	for srows.Next() {
		var ns, name, ps string
		if err := srows.Scan(&ns, &name, &ps); err != nil {
			srows.Close()
			return nil, err
		}
		if n := parseSelf(g.Catalog, ns, name, map[string]any{"$parents": parseJSON(ps)}); n != nil {
			selfs = append(selfs, n)
		}
	}
	srows.Close()
	if err := srows.Err(); err != nil {
		return nil, err
	}
	for _, n := range selfs {
		g.setSelf(n)
	}
	// Item states of placements.
	for _, name := range g.Names() {
		n := g.nodes[name]
		if n.ItemNS == "" {
			continue
		}
		st, head, err := itemState(ctx, q, n.ItemNS, n.ItemName)
		if err != nil {
			return nil, err
		}
		g.setItem(name, st, head)
	}
	return g, nil
}

type queryer interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// ReadItemState is ItemState inside a transaction (for hooks, which see
// the apply's uncommitted item states).
func ReadItemState(ctx context.Context, tx *sql.Tx, ns, name string) (int, string, error) {
	return itemState(ctx, tx, ns, name)
}

func itemState(ctx context.Context, q queryer, ns, name string) (int, string, error) {
	var st int
	var head sql.NullString
	err := q.QueryRowContext(ctx, `SELECT state, head FROM items WHERE ns = ? AND name = ?`, ns, name).Scan(&st, &head)
	if errors.Is(err, sql.ErrNoRows) {
		return ItemUnknown, "", nil
	}
	if err != nil {
		return 0, "", err
	}
	if st != ItemLive {
		head.String = ""
	}
	return st, head.String, nil
}

// setConfig records the catalog namespace document and its trust list.
func (g *Graph) setConfig(doc map[string]any) {
	g.Config = doc
	g.Trust = map[string]bool{}
	cat, _ := doc["catalog"].(map[string]any)
	arr, _ := cat["trust"].([]any)
	for _, x := range arr {
		if s, ok := x.(string); ok && s != g.Catalog && validNS(s) {
			g.Trust[s] = true
		}
	}
}

func saveMeta(ctx context.Context, tx *sql.Tx, k, v string) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO meta (k, v) VALUES (?, ?) ON CONFLICT (k) DO UPDATE SET v = excluded.v`, k, v)
	return err
}

func marshal(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(fmt.Sprintf("tree: marshal: %v", err))
	}
	return string(b)
}
