package tree

import (
	"context"
	"database/sql"
	"embed"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/middle-management/patchlog/internal/derived"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/pointer"
)

// Storage (§B.5, with additions):
//
//	checkpoints(origin, ns, ns_id)   follow.SQLCheckpoints: the catalog and each trusted namespace
//	seen(ns, ns_id)                  every ns_id applied, for ?min= (§A.5)
//	meta(k, v)                       "config": the catalog namespace document; "config:{ns}": a
//	                                 content namespace's document as of its checkpoint; "purged:{ns}"
//	                                 when the service applied ns's purge (Unix nanoseconds; "1"
//	                                 from earlier releases); "caught:{ns}" the head its first
//	                                 catch-up with ns reached (behind)
//	nodes(href, name, kind, item, item_head, title, state, …)
//	                                 one row per node (explicit, or implicit from $parents);
//	                                 raw parents/$access kept to rebuild the graph on start
//	edges(child, pos, parent, ord, state)
//	                                 one row per declared parents entry (hrefs), with its state
//	items(ns, name, state, head, title, created, file)
//	                                 liveness of every resource of the trusted namespaces seen,
//	                                 with its head's created and, in a file tree, its file
//	                                 metadata (§H.3, files.go); a name without a row in a
//	                                 namespace with "purged:{ns}" is purged (itemInfo); meta
//	                                 "filed" marks file metadata computed for a file tree
//	self_parents(ns, name, parents)  $parents of content documents (§B.9, -self-placing)
//	sealed_views, sealed_view_tags   sealed listings of a sealed/e2e catalog (derived.Cache)
//	edge_subjects(gs, subjects, exp) the subjects of each subject set the service minted edge
//	                                 grants for, until the last of them expires (edgegrants.go);
//	                                 meta "trusted:{ns}" is when it came to trust ns
//	cdn_repurge(id, tags, due)       second CDN purges (package repurge), kept by a rebuild
//
// The tables are migrations (migrations/, package dbmigrate), applied under
// the namespace "tree"; the sealed-view cache's, the repurge queue's and a
// catalog hook's are applied by their packages under namespaces of their
// own.
//
//go:embed migrations
var migrations embed.FS

// resetStmts empty what a rebuild replays (cdn_repurge and edge_subjects
// stay, and so do a hook's tables, which its Rebuild recomputes).
var resetStmts = []string{
	`DELETE FROM checkpoints`, `DELETE FROM seen`, `DELETE FROM meta`,
	`DELETE FROM nodes`, `DELETE FROM edges`, `DELETE FROM items`,
	`DELETE FROM self_parents`, derived.CacheResetStmts[0], derived.CacheResetStmts[1],
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
	crows, err := q.QueryContext(ctx, `SELECT substr(k, 8), v FROM meta WHERE k LIKE 'config:%'`)
	if err != nil {
		return nil, err
	}
	for crows.Next() {
		var ns, v string
		if err := crows.Scan(&ns, &v); err != nil {
			crows.Close()
			return nil, err
		}
		if m, ok := parseJSON(v).(map[string]any); ok {
			g.Content[ns] = &NSConfig{NS: ns, Doc: m}
		}
	}
	crows.Close()
	if err := crows.Err(); err != nil {
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
		// The purged namespaces are s.purged, which mirrors the committed
		// "purged:{ns}" rows, so no query per name the service never saw
		// (itemInfo).
		it, err := itemRow(ctx, q, n.ItemNS, n.ItemName)
		if err != nil {
			return nil, err
		}
		if _, purged := s.purged[n.ItemNS]; purged && it.state == ItemUnknown {
			it.state = ItemPurged
		}
		g.setItem(name, it)
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
	it, err := itemInfo(ctx, q, ns, name)
	return it.state, it.head, err
}

// itemData is what the service holds of a content item: its state, its
// head if live, and that head's title (§B.5) and file metadata (§H.3).
type itemData struct {
	state       int
	head, title string
	file        *FileMeta
}

// itemInfo is itemState with the item's title and file metadata. A name the
// service holds no row for is purged in a namespace it holds as purged
// ("purged:{ns}"), not unknown: every name of a purged namespace is 410
// purged at the core (§8.5), which keeps no list of them a service could
// read, and one that started after the purge may hold rows for some of
// its names at most (a sealed one's log is 410 too, and an at-rest one's
// replay drops what comes before the purge-ns entry in its batch,
// follow.Coalesce). So a service that started after the purge answers as
// one that followed it, and so does one that followed it for names it
// never saw (§B.11.4).
func itemInfo(ctx context.Context, q queryer, ns, name string) (itemData, error) {
	it, err := itemRow(ctx, q, ns, name)
	if err != nil || it.state != ItemUnknown {
		return it, err
	}
	var one int
	err = q.QueryRowContext(ctx, `SELECT 1 FROM meta WHERE k = ?`, "purged:"+ns).Scan(&one)
	switch {
	case err == nil:
		return itemData{state: ItemPurged}, nil
	case errors.Is(err, sql.ErrNoRows):
		return itemData{state: ItemUnknown}, nil
	}
	return itemData{}, err
}

// itemRow reads a name's items row: ItemUnknown without one.
func itemRow(ctx context.Context, q queryer, ns, name string) (itemData, error) {
	var it itemData
	var head, title, file sql.NullString
	err := q.QueryRowContext(ctx, `SELECT state, head, title, file FROM items WHERE ns = ? AND name = ?`, ns, name).Scan(&it.state, &head, &title, &file)
	if errors.Is(err, sql.ErrNoRows) {
		return itemData{state: ItemUnknown}, nil
	}
	if err != nil {
		return itemData{}, err
	}
	if it.state == ItemLive {
		it.head, it.title, it.file = head.String, title.String, decodeFile(file.String)
	}
	return it, nil
}

// titlePointer reads catalog.title (§B.5), a JSON Pointer. Anything else
// is ignored: listings then carry no item titles.
func titlePointer(doc map[string]any) (pointer.Pointer, bool) {
	cat, _ := doc["catalog"].(map[string]any)
	if t, ok := cat["title"].(string); ok {
		if p, err := pointer.Parse(t); err == nil {
			return p, true
		}
	}
	return nil, false
}

// titleAt is the string at p in an item's head document ("" if there is
// none or it isn't a string, §B.5).
func titleAt(doc any, p pointer.Pointer) string {
	v, ok := pointer.Get(doc, p)
	if !ok {
		return ""
	}
	t, _ := v.(string)
	return t
}

// setConfig records the catalog namespace document, its trust list, its
// title pointer and whether it is a file tree.
func (g *Graph) setConfig(doc map[string]any) {
	g.Config = doc
	g.Trust = map[string]bool{}
	g.TitlePtr, g.HasTitle = titlePointer(doc)
	g.Files = isFileTree(doc)
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
