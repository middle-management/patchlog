package tree

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/derived"
	"github.com/middle-management/patchlog/internal/files"
)

// File trees (Addendum H). A catalog whose catalog.files names the
// content namespace and root folder (§H.2) is a file tree, and its
// listings give every placement the file metadata of its item's head
// (§H.3): for a raw file the blob reference's size and type, for a JSON
// file the length of its rendering (files.Rendering) and
// application/json, and modified, the head's created. The service reads
// each head for it once, as it applies the entry that made it the head,
// and stores it with the item (items.file), so a folder lists in one
// request. Items of every trusted namespace get it, not only files.ns,
// including implicit placements (§B.9). In sealed (E2) namespaces it is
// read with keys and sealed per entry under the item's K_r when listed
// (§E.2.6); at E3 it is left out. When catalog.files appears, every live
// item's head is read for it, and when it goes, the metadata does
// (refile).

// FileMeta is a placement's file metadata in a file tree (§H.3).
type FileMeta struct {
	Size int64
	Type string
	// Modified is the head's created (RFC 3339), "" where the service
	// doesn't know it: rows of a /heads listing in a sealed namespace, or
	// written before servers stored it (§7.4), whose document was served
	// without Last-Modified.
	Modified string
}

// value is m as a listing gives it: { "size", "type", "modified"? }.
func (m *FileMeta) value() map[string]any {
	v := map[string]any{"size": m.Size, "type": m.Type}
	if m.Modified != "" {
		v["modified"] = m.Modified
	}
	return v
}

// encode is m as the items table stores it, "" for none.
func (m *FileMeta) encode() string {
	if m == nil {
		return ""
	}
	b, _ := json.Marshal(m.value())
	return string(b)
}

// decodeFile reads what encode stored (nil for none or a malformed row).
func decodeFile(s string) *FileMeta {
	if s == "" {
		return nil
	}
	var v struct {
		Size     *int64 `json:"size"`
		Type     string `json:"type"`
		Modified string `json:"modified"`
	}
	if json.Unmarshal([]byte(s), &v) != nil || v.Size == nil || v.Type == "" {
		return nil
	}
	return &FileMeta{Size: *v.Size, Type: v.Type, Modified: v.Modified}
}

// fileMetaOf is the file metadata of an item's head doc (§H.3), with
// created, the head's created as the log gives it, else doc's
// Last-Modified.
func fileMetaOf(doc *client.Doc, created string) *FileMeta {
	m := files.MetaOf(doc.Value)
	out := &FileMeta{Size: m.Size, Type: m.Type, Modified: created}
	if out.Modified == "" && !doc.Modified.IsZero() {
		out.Modified = doc.Modified.UTC().Format(time.RFC3339)
	}
	return out
}

// isFileTree reports whether a catalog namespace document makes the
// catalog a file tree (§H.2, §B.6): catalog.files is an object naming a
// content namespace (ns) and a root folder (root, a resource name without
// a dot). The core refuses any other files (§7.4).
func isFileTree(doc map[string]any) bool {
	cat, _ := doc["catalog"].(map[string]any)
	f, _ := cat["files"].(map[string]any)
	ns, _ := f["ns"].(string)
	root, _ := f["root"].(string)
	return client.ValidNSName(ns) && client.ValidResourceName(root) && !strings.Contains(root, ".")
}

// refiling is what a change of catalog.files does to the items (refile):
// on, the file metadata of every live item it could read; off, none.
type refiling struct {
	on    bool
	metas map[[2]string]*FileMeta // ns, name → metadata (on)
}

// refile prepares a change of catalog.files: turning it on reads the head
// of every live item of a trusted namespace that isn't e2e, with keys in a
// sealed one, for its file metadata (§H.3), modified being the created the
// items table holds, else the head's Last-Modified. An item whose head
// can't be read is left without; its own entry follows. It runs under
// wmu, so no apply commits items meanwhile.
func (s *Service) refile(ctx context.Context, on bool) (*refiling, error) {
	fr := &refiling{on: on, metas: map[[2]string]*FileMeta{}}
	if !on {
		return fr, nil
	}
	s.mu.RLock()
	trust := make(map[string]bool, len(s.g.Trust))
	for ns := range s.g.Trust {
		trust[ns] = true
	}
	s.mu.RUnlock()
	rows, err := s.db.QueryContext(ctx, `SELECT ns, name, head, created FROM items WHERE state = ? AND head IS NOT NULL`, ItemLive)
	if err != nil {
		return nil, err
	}
	type it struct{ ns, name, head, created string }
	var all []it
	for rows.Next() {
		var i it
		var created sql.NullString
		if err := rows.Scan(&i.ns, &i.name, &i.head, &created); err != nil {
			rows.Close()
			return nil, err
		}
		i.created = created.String
		if trust[i.ns] {
			all = append(all, i)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	readable := map[string]bool{}
	for _, i := range all {
		ok, seen := readable[i.ns]
		if !seen {
			in, err := s.keys.Info(ctx, s.actual(i.ns))
			if err != nil {
				return nil, fmt.Errorf("tree: the encryption of %s: %w", s.actual(i.ns), err)
			}
			ok = in.Level != derived.LevelE2E
			readable[i.ns] = ok
		}
		if !ok {
			continue
		}
		doc, err := s.keys.FetchDoc(ctx, s.actual(i.ns), i.name, i.head, nil)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			continue
		}
		created := i.created
		if doc.ID != i.head {
			created = ""
		}
		fr.metas[[2]string{i.ns, i.name}] = fileMetaOf(doc, created)
	}
	return fr, nil
}

// apply writes fr in tx, sets the nodes' file metadata and marks those
// that change, and records in meta "filed" whether the items hold file
// metadata for a file tree.
func (fr *refiling) apply(ctx context.Context, tx *sql.Tx, g *Graph, changed map[string]bool) error {
	if _, err := tx.ExecContext(ctx, `UPDATE items SET file = NULL WHERE file IS NOT NULL`); err != nil {
		return err
	}
	for k, m := range fr.metas {
		if _, err := tx.ExecContext(ctx, `UPDATE items SET file = ? WHERE ns = ? AND name = ?`, m.encode(), k[0], k[1]); err != nil {
			return err
		}
	}
	for _, m := range []map[string]*Node{g.explicit, g.self} {
		for name, n := range m {
			if n.ItemNS == "" {
				continue
			}
			var meta *FileMeta
			if n.ItemState == ItemLive {
				meta = fr.metas[[2]string{n.ItemNS, n.ItemName}]
			}
			if n.ItemFile != nil || meta != nil {
				n.ItemFile = meta
				changed[name] = true
			}
		}
	}
	if fr.on {
		return saveMeta(ctx, tx, "filed", "1")
	}
	_, err := tx.ExecContext(ctx, `DELETE FROM meta WHERE k = 'filed'`)
	return err
}

// backfillFiles brings the items' file metadata in line with whether the
// catalog is a file tree when they disagree on start (meta "filed"): a
// database from before file metadata, or a catalog.files a release that
// ignored it applied. Listings change at an unchanged combined checkpoint,
// so every cached listing of the catalog goes (ns:{catalog}), as for the
// drift reload fixes.
func (s *Service) backfillFiles(ctx context.Context) error {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	s.mu.RLock()
	on := s.g.Files
	s.mu.RUnlock()
	var v string
	err := s.db.QueryRowContext(ctx, `SELECT v FROM meta WHERE k = 'filed'`).Scan(&v)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if on == (err == nil) {
		return nil
	}
	fr, err := s.refile(ctx, on)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := fr.apply(ctx, tx, s.g, map[string]bool{}); err != nil {
		return err
	}
	tags := []string{"ns:" + s.actual(s.opt.Catalog)}
	if err := s.sealed.Purge(ctx, tx, tags); err != nil {
		return err
	}
	if err := s.repurge.Add(ctx, tx, tags); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		if rerr := s.reload(context.WithoutCancel(ctx)); rerr != nil {
			s.opt.Logf("tree: reloading after a failed backfill: %v", rerr)
		}
		return err
	}
	s.kept.Purge(s.opt.Catalog, tags)
	s.opt.Purger.PurgeTags(tags)
	return nil
}

// fileSealing is how a listing gives placements their file metadata
// (§H.3): not at all outside a file tree; for items of a sealed (E2)
// namespace sealed per entry under the item's K_r (§E.2.6), with that
// namespace's current epoch key and padding; for items of an e2e one, or
// one whose encryption or keys the service can't tell now, not at all;
// otherwise in the clear. Its keys are read before the graph is, never
// under its lock.
type fileSealing struct {
	on   bool
	keys map[string]derived.Key // by the namespace read (Graph.Actual)
	omit map[string]bool
}

// seals reports whether listings seal file metadata.
func (fs *fileSealing) seals() bool { return fs != nil && len(fs.keys) > 0 }

// fileSealing reads what listings need now to give file metadata.
func (s *Service) fileSealing(ctx context.Context) *fileSealing {
	s.mu.RLock()
	on := s.g.Files
	var nss []string
	for ns := range s.g.Trust {
		if _, purged := s.purged[ns]; !purged {
			nss = append(nss, s.actual(ns))
		}
	}
	s.mu.RUnlock()
	fs := &fileSealing{on: on, keys: map[string]derived.Key{}, omit: map[string]bool{}}
	if !on {
		return fs
	}
	for _, ns := range nss {
		in, key, err := s.keys.Current(ctx, ns)
		switch {
		case err != nil:
			s.opt.Logf("tree: file metadata of %s left out: %v", ns, err)
			fs.omit[ns] = true
		case in.Level == derived.LevelE2E:
			fs.omit[ns] = true
		case in.Level == derived.LevelSealed:
			fs.keys[ns] = key
		}
	}
	return fs
}

// file is n's file metadata as a listing gives it (fileSealing), or nil.
func (q *query) file(n *Node) any {
	fs := q.files
	if fs == nil || !fs.on || n.ItemFile == nil {
		return nil
	}
	ns := q.g.Actual(n.ItemNS)
	if fs.omit[ns] {
		return nil
	}
	k, sealed := fs.keys[ns]
	if !sealed {
		return n.ItemFile.value()
	}
	jwe, err := derived.SealItem(k, q.view, n.ItemName, map[string]any{"file": n.ItemFile.value()})
	if err != nil {
		if q.serr != nil && *q.serr == nil {
			*q.serr = err
		}
		return nil
	}
	return map[string]any{"sealed": jwe}
}
