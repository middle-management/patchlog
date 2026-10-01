// Package archive stores pruning archives (§8.6) as full-history bundles
// (§G.4.1) in a directory, and restores them into a database offline (§D.4).
//
// # Destinations
//
// Destinations are file:// URLs of directories. The operator configures a
// default destination and the roots a namespace's `retention[].archive` may
// point into; anything else is refused when the namespace document is
// written (422), and never written to.
//
// # Naming
//
// An archive of ns/name pruned to horizon H is stored at
//
//	{destination}/{ns}/{name}/{H}.jsonl
//
// (core.ArchiveKey). It holds the entries from the previous horizon (or
// genesis) up to the one before H, with authors; an incremental archive names
// the last entry of the previous one in `requires`, so a resource's archives
// chain back to genesis. Archives are written to a temporary file in the
// same directory, synced and renamed, so a URL never holds a partial bundle.
//
// # Encrypted namespaces
//
// In a namespace encrypted at rest (Addendum E.1) the bundle is written
// through core.ArchiveBundle.Seal: the file is the standard bundle,
// encrypted as a chunked AES-256-GCM stream under a key derived from the
// resource's data key (format in internal/core/crypt.go). Restore decrypts
// it with core.Engine.OpenArchive. Purging the resource destroys the data
// key, so copies of the file that survive can't be read.
package archive

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/middle-management/patchlog/internal/bundle"
	"github.com/middle-management/patchlog/internal/core"
)

// Dir is a file:// archiver.
type Dir struct {
	def   string   // default destination directory, "" if none
	roots []string // directories destinations may point into
}

// NewDir returns an archiver writing to the default destination def (a
// file:// URL, or "" for none) and allowing rule destinations under roots
// (file:// URLs). def is always allowed.
func NewDir(def string, roots ...string) (*Dir, error) {
	d := &Dir{}
	if def != "" {
		p, err := dirPath(def)
		if err != nil {
			return nil, err
		}
		d.def = p
		d.roots = append(d.roots, p)
	}
	for _, r := range roots {
		p, err := dirPath(r)
		if err != nil {
			return nil, err
		}
		d.roots = append(d.roots, p)
	}
	return d, nil
}

// dirPath turns a file:// URL into a clean absolute path.
func dirPath(s string) (string, error) {
	u, err := url.Parse(s)
	if err != nil {
		return "", fmt.Errorf("invalid archive URL %q", s)
	}
	if u.Scheme != "file" {
		return "", fmt.Errorf("archive destination %q: only file:// is supported", s)
	}
	if u.Host != "" && u.Host != "localhost" {
		return "", fmt.Errorf("archive destination %q: file URLs must be local", s)
	}
	if u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return "", fmt.Errorf("archive destination %q: no query, fragment or user allowed", s)
	}
	if !strings.HasPrefix(u.Path, "/") {
		return "", fmt.Errorf("archive destination %q: the path must be absolute", s)
	}
	return filepath.Clean(u.Path), nil
}

func fileURL(p string) string { return (&url.URL{Scheme: "file", Path: filepath.ToSlash(p)}).String() }

// URL returns the file:// URL of a path.
func URL(p string) string { return fileURL(p) }

func within(p, root string) bool {
	return p == root || strings.HasPrefix(p, strings.TrimSuffix(root, "/")+"/")
}

// Check implements core.Archiver.
func (d *Dir) Check(dest string) error {
	_, err := d.resolve(dest)
	return err
}

func (d *Dir) resolve(dest string) (string, error) {
	if dest == "" {
		if d.def == "" {
			return "", errors.New("no default archive destination is configured")
		}
		return d.def, nil
	}
	p, err := dirPath(dest)
	if err != nil {
		return "", err
	}
	for _, r := range d.roots {
		if within(p, r) {
			return p, nil
		}
	}
	return "", fmt.Errorf("archive destination %q is not under a root the operator allows", dest)
}

// Write implements core.Archiver.
func (d *Dir) Write(ctx context.Context, dest, key string, b *core.ArchiveBundle) (string, error) {
	dir, err := d.resolve(dest)
	if err != nil {
		return "", err
	}
	p := filepath.Join(dir, filepath.FromSlash(key))
	if !within(p, dir) {
		return "", fmt.Errorf("invalid archive key %q", key)
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return "", err
	}
	f, err := os.CreateTemp(filepath.Dir(p), ".archive-*.tmp")
	if err != nil {
		return "", err
	}
	tmp := f.Name()
	defer os.Remove(tmp) // no-op after the rename
	bw := bufio.NewWriterSize(f, 1<<16)
	var w io.Writer = bw
	var sw io.WriteCloser
	if b.Seal != nil {
		// An encrypted namespace's archive (Addendum E.1).
		if sw, err = b.Seal(bw); err != nil {
			f.Close()
			return "", err
		}
		w = sw
	}
	if err := Encode(ctx, w, b); err != nil {
		f.Close()
		return "", err
	}
	if sw != nil {
		if err := sw.Close(); err != nil {
			f.Close()
			return "", err
		}
	}
	if err := bw.Flush(); err != nil {
		f.Close()
		return "", err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return "", err
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	if err := os.Rename(tmp, p); err != nil {
		return "", err
	}
	return fileURL(p), nil
}

// Delete implements core.Archiver. It deletes the file an earlier Write
// returned, wherever the roots are now.
func (d *Dir) Delete(ctx context.Context, u string) error {
	p, err := dirPath(u)
	if err != nil {
		return err
	}
	if err := os.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

// Open implements core.Archiver.
func (d *Dir) Open(ctx context.Context, u string) (io.ReadCloser, error) {
	p, err := dirPath(u)
	if err != nil {
		return nil, err
	}
	return os.Open(p)
}

// Encode writes an archive as a full-history bundle with authors, streaming
// its entries through bundle.Writer, which checks every line (chain order,
// recomputed ids) as it goes.
func Encode(ctx context.Context, w io.Writer, b *core.ArchiveBundle) error {
	k := bundle.Key(b.NS, b.Name)
	h := bundle.Header{
		Origin:  b.Origin,
		Created: b.Created.UTC().Format(time.RFC3339),
		At:      map[string]string{b.NS: b.At},
		Docs:    map[string]bundle.DocInfo{k: {History: bundle.Full, Head: b.Head}},
		Authors: true,
	}
	if b.Requires != "" {
		h.Requires = map[string]string{k: b.Requires}
	}
	bw, err := bundle.NewWriter(w, h)
	if err != nil {
		return err
	}
	err = b.Entries(func(e core.ArchiveEntry) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if e.Blob != nil {
			return bw.Line(bundle.Line{NS: b.NS, Resource: b.Name, Blob: e.Blob.ID, Type: e.Blob.Type, Nonce: e.Blob.Nonce, Data: e.Blob.Data})
		}
		return bw.Line(bundle.Line{NS: b.NS, Resource: b.Name, ID: e.ID, Parent: e.Parent, Kind: e.Kind,
			Patches: e.Patches, Author: e.Author, Created: e.Created, Signature: e.Signature})
	})
	if err != nil {
		return err
	}
	_, err = bw.Close()
	return err
}

// Opener reads archives back by URL.
type Opener interface {
	Open(ctx context.Context, url string) (io.ReadCloser, error)
}

// RestoreOptions select what Restore restores.
type RestoreOptions struct {
	// From, if set, is a file:// URL where the archives are now: each is
	// read from From/{key} instead of the URL recorded when it was written.
	From     string
	NS, Name string // "" = all
	// Log receives progress lines; nil discards them.
	Log func(format string, args ...any)
}

// ResourceReport is the outcome of restoring one resource.
type ResourceReport struct {
	NS, Name string
	Archives int
	Failed   []string // archives that couldn't be read or verified
	core.RestoreResult
}

// Restore re-inserts archived history (§D.4). It is an offline task: run
// it against a database no server has open. For every archive of every
// unpurged resource, it reads and verifies the bundle and re-inserts each
// patch set whose recomputed id matches the kept row; once a resource has
// all its patch sets back, its horizon is cleared and the attachments
// pruning ended get their bytes back from the archives' blob lines. An archive that can't be
// read or fails verification is reported, and the entries verified before
// the failure still count, because each is checked against the kept id.
func Restore(ctx context.Context, e *core.Engine, opt RestoreOptions) ([]ResourceReport, error) {
	logf := opt.Log
	if logf == nil {
		logf = func(string, ...any) {}
	}
	var from string
	if opt.From != "" {
		p, err := dirPath(opt.From)
		if err != nil {
			return nil, err
		}
		from = p
	}
	recs, err := e.Archives(ctx, opt.NS, opt.Name)
	if err != nil {
		return nil, err
	}
	opener := &Dir{}
	type group struct {
		ns, name string
		recs     []core.ArchiveRecord
	}
	var groups []*group
	for _, r := range recs {
		if len(groups) == 0 || groups[len(groups)-1].ns != r.NS || groups[len(groups)-1].name != r.Name {
			groups = append(groups, &group{ns: r.NS, name: r.Name})
		}
		g := groups[len(groups)-1]
		g.recs = append(g.recs, r)
	}
	var out []ResourceReport
	for _, g := range groups {
		rep := ResourceReport{NS: g.ns, Name: g.name, Archives: len(g.recs)}
		res, err := e.RestoreResource(ctx, g.ns, g.name, func(yield func(core.ArchiveEntry) error) error {
			rep.Failed = nil // a run again starts over
			for _, r := range g.recs {
				u := r.URL
				if from != "" {
					u = fileURL(filepath.Join(from, filepath.FromSlash(r.Key)))
				}
				if err := readArchive(ctx, e, opener, u, g.ns, g.name, yield); err != nil {
					if ctx.Err() != nil {
						return ctx.Err()
					}
					logf("%s/%s: archive %s: %v", g.ns, g.name, u, err)
					rep.Failed = append(rep.Failed, u)
				}
			}
			return nil
		})
		if err != nil {
			return out, fmt.Errorf("%s/%s: %w", g.ns, g.name, err)
		}
		rep.RestoreResult = *res
		switch {
		case res.Purged:
			logf("%s/%s: purged, skipped", g.ns, g.name)
		case res.Cleared:
			logf("%s/%s: restored %d patch sets and %d blobs from %d archives; horizon cleared", g.ns, g.name, res.Restored, res.Blobs, len(g.recs))
		default:
			logf("%s/%s: restored %d patch sets from %d archives; history still incomplete (%d skipped)", g.ns, g.name, res.Restored, len(g.recs), res.Skipped)
		}
		out = append(out, rep)
	}
	return out, nil
}

func readArchive(ctx context.Context, e *core.Engine, o Opener, u, ns, name string, yield func(core.ArchiveEntry) error) error {
	rc, err := o.Open(ctx, u)
	if err != nil {
		return err
	}
	defer rc.Close()
	// An archive of an encrypted namespace is decrypted with the
	// resource's data key; a purge destroyed it (Addendum E.1).
	plain, err := e.OpenArchive(ctx, ns, name, rc)
	if err != nil {
		return err
	}
	rd, err := bundle.NewReader(plain)
	if err != nil {
		return err
	}
	for {
		l, err := rd.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if l.IsBlob() && l.NS == ns && l.Resource == name {
			// The bytes of attachments pruning ended (§7.8), verified
			// against their ids by the reader (§G.4.1).
			if err := yield(core.ArchiveEntry{Blob: &core.ArchiveBlob{ID: l.Blob, Type: l.Type, Nonce: l.Nonce, Data: l.Data}}); err != nil {
				return err
			}
			continue
		}
		if l.IsSnapshot() || l.NS != ns || l.Resource != name {
			return fmt.Errorf("line for %s is not a history line of %s/%s", l.Key(), ns, name)
		}
		if err := yield(core.ArchiveEntry{ID: l.ID, Parent: l.Parent, Kind: l.Kind, Patches: l.Patches}); err != nil {
			return err
		}
	}
}
