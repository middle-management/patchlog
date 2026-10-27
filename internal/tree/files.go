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
	"github.com/middle-management/patchlog/internal/follow"
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
// read with keys and sealed when listed in place of the value, as a value
// of another resource (§E.2.6), under the item's K_r of the epoch its head
// is served under (FileMeta.Epoch); at E3 it is absent, and the listing
// says so ({ "absent":
// "e2e" }), as it says a head not read for it is ({ "absent": "pending"
// }, query.file). When catalog.files appears, every live
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
	// Epoch is the epoch the head is served under in a sealed namespace
	// (derived.EpochOf), which a listing seals the metadata under
	// (§E.2.6 values of another resource); 0 where not known, as for rows
	// stored before it was kept, which take the epoch current then.
	Epoch int
}

// value is m as a listing gives it: { "size", "type", "modified"? }.
func (m *FileMeta) value() map[string]any {
	v := map[string]any{"size": m.Size, "type": m.Type}
	if m.Modified != "" {
		v["modified"] = m.Modified
	}
	return v
}

// encode is m as the items table stores it, "" for none: its value, and
// its epoch where known.
func (m *FileMeta) encode() string {
	if m == nil {
		return ""
	}
	v := m.value()
	if m.Epoch > 0 {
		v["epoch"] = m.Epoch
	}
	b, _ := json.Marshal(v)
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
		Epoch    int    `json:"epoch"`
	}
	if json.Unmarshal([]byte(s), &v) != nil || v.Size == nil || v.Type == "" {
		return nil
	}
	return &FileMeta{Size: *v.Size, Type: v.Type, Modified: v.Modified, Epoch: v.Epoch}
}

// fileMetaOf is the file metadata of an item's head doc (§H.3), read in
// namespace ns, with created, the head's created as the log gives it,
// else doc's Last-Modified, and the epoch the head is served under.
func fileMetaOf(doc *client.Doc, created, ns string) *FileMeta {
	m := files.MetaOf(doc.Value)
	out := &FileMeta{Size: m.Size, Type: m.Type, Modified: created, Epoch: derived.EpochOf(ns, doc.Kid)}
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
	return client.ValidNSName(ns) && filesRoot(doc) != ""
}

// filesRoot is catalog.files.root (§H.2), the node name of the folder
// whose children are a file tree's top level; "" if it isn't one.
func filesRoot(doc map[string]any) string {
	cat, _ := doc["catalog"].(map[string]any)
	f, _ := cat["files"].(map[string]any)
	root, _ := f["root"].(string)
	if !client.ValidResourceName(root) || strings.Contains(root, ".") {
		return ""
	}
	return root
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
// items table holds, else the head's Last-Modified. An item gone since, or
// whose head isn't readable content, is left without; its own entry
// follows. Any other failure to read a head is returned, so the change is
// made again, as an apply's fetches are, rather than leave the item
// without until it changes. It runs under wmu, so no apply commits items
// meanwhile.
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
		switch {
		case err == nil:
		case errors.Is(err, follow.ErrNotLive) || client.IsGone(err) || client.IsNotFound(err) || errors.Is(err, derived.ErrSkip):
			continue
		default:
			return nil, fmt.Errorf("tree: the file metadata of %s/%s: %w", s.actual(i.ns), i.name, err)
		}
		created := i.created
		if doc.ID != i.head {
			created = ""
		}
		fr.metas[[2]string{i.ns, i.name}] = fileMetaOf(doc, created, s.actual(i.ns))
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
// drift reload fixes. "filed" is recorded only once every head is read,
// so a failed one is made again (retryBackfill), and by the next start.
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

// retryBackfill runs fill (backfillFiles, backfillNodes) until it
// succeeds or ctx is done, with the pauses a follower makes between
// attempts: the core may not be up yet when the service starts.
func (s *Service) retryBackfill(ctx context.Context, what string, fill func(context.Context) error) {
	pause := time.Second
	for {
		t := time.NewTimer(pause)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
		err := fill(ctx)
		if err == nil || ctx.Err() != nil {
			return
		}
		s.opt.Logf("tree: %s: %v; retrying", what, err)
		if pause < 30*time.Second {
			pause *= 2
		}
	}
}

// fileSealing is how a listing gives placements their file metadata
// (§H.3): not at all outside a file tree; for items of a sealed (E2)
// namespace sealed in place of the value under the item's K_r of the epoch
// its head is served under (FileMeta.Epoch, the current one where that
// isn't known; §E.2.6 values of another resource), with that namespace's
// padding; for items of an e2e one, or one whose keys the service can't
// have (lastingly), not at all; otherwise in the clear. Its keys are read
// before the graph is, never under its lock: the current epoch's, and
// those of every older epoch a head shown may be served under (epochs).
type fileSealing struct {
	on     bool
	keys   map[string]derived.Key         // the current epoch's, by the namespace read (Graph.Actual)
	epochs map[string]map[int]derived.Key // older epochs' keys, by namespace and epoch
	// lacking are older epochs whose keys the service can't have, by
	// namespace: their items' metadata is left out, as for omit.
	lacking map[string]map[int]bool
	omit    map[string]bool
	e2e     map[string]bool // omitted as end-to-end (§H.3 absent: e2e)
}

// seals reports whether listings seal file metadata.
func (fs *fileSealing) seals() bool { return fs != nil && len(fs.keys) > 0 }

// errFileKeys is a sealed namespace's key, which seals its items' file
// metadata, failing for now: the listing is 503, as for the catalog's own
// key, rather than computed and kept without it at its at.
var errFileKeys = errors.New("the key that seals file metadata")

// lastingKeyErr reports a failure to get a key that lasts until the
// configuration changes: no keys for the service's grant, a namespace it
// can't read, absent or gone.
func lastingKeyErr(err error) bool {
	return errors.Is(err, client.ErrNoKeys) || client.IsNotFound(err) || client.IsAuth(err) || client.IsGone(err)
}

// fileSealing reads what listings need now to give file metadata. Only
// sealed namespaces' epoch keys are asked for: the current one, and each
// older epoch the file metadata of a live item is served under. A
// failure that lasts until the configuration changes leaves that
// namespace's file metadata out, or for an older epoch, that of the items
// served under it; any other is errFileKeys.
func (s *Service) fileSealing(ctx context.Context) (*fileSealing, error) {
	s.mu.RLock()
	on := s.g.Files
	var nss []string
	for ns := range s.g.Trust {
		if _, purged := s.purged[ns]; !purged {
			nss = append(nss, s.actual(ns))
		}
	}
	// The epochs the items' file metadata is served under.
	used := map[string]map[int]bool{}
	if on {
		for _, m := range []map[string]*Node{s.g.explicit, s.g.self} {
			for _, n := range m {
				if n.ItemFile == nil || n.ItemFile.Epoch <= 0 {
					continue
				}
				ns := s.g.Actual(n.ItemNS)
				if used[ns] == nil {
					used[ns] = map[int]bool{}
				}
				used[ns][n.ItemFile.Epoch] = true
			}
		}
	}
	s.mu.RUnlock()
	fs := &fileSealing{on: on, keys: map[string]derived.Key{}, epochs: map[string]map[int]derived.Key{},
		lacking: map[string]map[int]bool{}, omit: map[string]bool{}, e2e: map[string]bool{}}
	if !on {
		return fs, nil
	}
	for _, ns := range nss {
		in, err := s.keys.Info(ctx, ns)
		var key derived.Key
		if err == nil && in.Level == derived.LevelSealed {
			_, key, err = s.keys.Current(ctx, ns)
		}
		switch {
		case err != nil && lastingKeyErr(err):
			s.opt.Logf("tree: file metadata of %s left out: %v", ns, err)
			fs.omit[ns] = true
			continue
		case err != nil:
			return nil, fmt.Errorf("%w of %s: %w", errFileKeys, ns, err)
		case in.Level == derived.LevelE2E:
			fs.omit[ns], fs.e2e[ns] = true, true
			continue
		case in.Level != derived.LevelSealed:
			continue
		}
		fs.keys[ns] = key
		for e := range used[ns] {
			if e == key.Epoch {
				continue
			}
			k, err := s.keys.KeyAt(ctx, ns, e)
			switch {
			case err != nil && lastingKeyErr(err):
				s.opt.Logf("tree: file metadata of %s served under epoch %d left out: %v", ns, e, err)
				if fs.lacking[ns] == nil {
					fs.lacking[ns] = map[int]bool{}
				}
				fs.lacking[ns][e] = true
			case err != nil:
				return nil, fmt.Errorf("%w of %s epoch %d: %w", errFileKeys, ns, e, err)
			default:
				if fs.epochs[ns] == nil {
					fs.epochs[ns] = map[int]derived.Key{}
				}
				fs.epochs[ns][e] = k
			}
		}
	}
	return fs, nil
}

// file is the file member of n, a placement whose head a listing shows,
// in a file tree (§H.3): its file metadata (fileSealing), or why the
// service can't give it, { "absent": "e2e" } for an item of an e2e
// namespace and { "absent": "pending" } for a head it hasn't read for
// it, or can't (keys it can't have), which a tool reads from the core;
// nil outside a file tree.
func (q *query) file(n *Node) any {
	fs := q.files
	if fs == nil || !fs.on {
		return nil
	}
	ns := q.g.Actual(n.ItemNS)
	switch {
	case fs.e2e[ns]:
		return map[string]any{"absent": "e2e"}
	case n.ItemFile == nil || fs.omit[ns]:
		return map[string]any{"absent": "pending"}
	}
	k, sealed := fs.keys[ns]
	if !sealed {
		return n.ItemFile.value()
	}
	if e := n.ItemFile.Epoch; e > 0 && e != k.Epoch {
		// Sealed under the epoch the item's head is served under (§E.2.6).
		ek, ok := fs.epochs[ns][e]
		switch {
		case fs.lacking[ns][e]:
			return map[string]any{"absent": "pending"}
		case !ok:
			// A head read since the keys were: asked again.
			if q.serr != nil && *q.serr == nil {
				*q.serr = fmt.Errorf("%w of %s epoch %d: not read yet", errFileKeys, ns, e)
			}
			return nil
		}
		k = ek
	}
	// The plaintext is { "file": value } (F-E5, the default kept).
	jwe, err := derived.SealItem(k, q.view, n.ItemName, map[string]any{"file": n.ItemFile.value()})
	if err != nil {
		if q.serr != nil && *q.serr == nil {
			*q.serr = err
		}
		return nil
	}
	return map[string]any{"sealed": jwe}
}
