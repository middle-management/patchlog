package tree

import (
	"context"
	"fmt"
	"net/http"
	"slices"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/follow"
)

// catalogOpts is opts for following real in the place of ns, with
// follow.AsBranch added where ns is the catalog, served directly (no
// release preview stands another namespace in its place), and its current
// namespace document names a base: "A catalog branch, previewed or served
// directly, lists the nodes it reads through from its base as of the
// branch's at" (SERVICES §B.5 Previews, v0.85; §7.6, §10 Branches). The
// follower then starts, on an empty checkpoint, from the branch's first
// entry and its /heads there, as a preview's does, and follows the
// branch's own log from it. A checkpoint from before v0.85 already lies
// past that entry: such a database is rebuilt to gain the base's nodes.
//
// For the catalog it also resolves, before the follower applies anything,
// the local base chain of the namespace followed, whose names count as
// the catalog's own in its nodes' links (setBases; §B.5 Previews, v0.86).
//
// An error is the document's read failing: the follower isn't started
// without knowing, since it would then checkpoint past the first entry.
// A purged catalog is the follower's to find.
func (s *Service) catalogOpts(ctx context.Context, ns, real string, opts []follow.Option) ([]follow.Option, error) {
	if ns != s.opt.Catalog {
		return opts, nil
	}
	h, err := s.c.NSHead(ctx, real)
	if err != nil {
		return nil, err
	}
	d, err := s.c.NSDoc(ctx, real, h.ID)
	if client.IsPurged(err) {
		// A purged namespace's document is 410 where it was sealed
		// (§8.5): the follower delivers the purge.
		return opts, nil
	}
	if err != nil {
		return nil, err
	}
	bases, err := s.baseChain(ctx, real, d.Value)
	if err != nil {
		return nil, err
	}
	if err := s.setBases(ctx, bases); err != nil {
		return nil, err
	}
	if b, _ := d.Value["base"].(map[string]any); b == nil || real != ns {
		return opts, nil
	}
	return append(opts[:len(opts):len(opts)], follow.AsBranch()), nil
}

// baseChain is the local base chain of namespace real, whose document is
// doc: its base, that one's base and so on, nearest first, without the
// catalog's own name (a release preview follows a branch of the catalog
// under the catalog's name). A remote base (one with an origin, §G.3)
// ends it: a namespace of that name here is unrelated. So does a base
// whose document the service can't read (purged, or refused: 401, 403,
// 404): only the bases known so far count, and a link into one further up
// stays a link to another namespace, which shows less. Any other failure
// is an error, tried again.
func (s *Service) baseChain(ctx context.Context, real string, doc map[string]any) ([]string, error) {
	var out []string
	seen := map[string]bool{real: true}
	for len(seen) <= MaxDepth {
		b, _ := doc["base"].(map[string]any)
		name, _ := b["ns"].(string)
		if _, remote := b["origin"]; b == nil || remote || name == "" || seen[name] {
			break
		}
		seen[name] = true
		if name != s.opt.Catalog {
			out = append(out, name)
		}
		var d *client.NSDoc
		h, err := s.c.NSHead(ctx, name)
		if err == nil {
			d, err = s.c.NSDoc(ctx, name, h.ID)
		}
		if ae, ok := client.AsAPIError(err); client.IsPurged(err) || ok && (ae.Status == http.StatusUnauthorized || ae.Status == http.StatusForbidden || ae.Status == http.StatusNotFound) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("tree: the document of %s, a base of %s: %w", name, real, err)
		}
		doc = d.Value
	}
	return out, nil
}

// setBases makes bases the catalog's base chain (Graph.Bases), kept in
// meta "bases" for the graph a restart loads. Where it differs from the
// graph's, the graph is loaded again, its nodes parsed under the new
// chain (reload, which purges the listings that change): a database
// written before v0.86, or one reset. An implicit placement whose
// $parents name only a base's folders isn't stored before the chain is
// known; the catalog's follower, which calls this before it runs,
// applies the catalog.trust that content followers wait for, so that
// happens only in a database from before v0.86, which is rebuilt.
func (s *Service) setBases(ctx context.Context, bases []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if slices.Equal(s.g.Bases, bases) {
		return nil
	}
	l := make([]any, len(bases))
	for i, b := range bases {
		l[i] = b
	}
	if _, err := s.db.ExecContext(ctx, `INSERT INTO meta (k, v) VALUES ('bases', ?) ON CONFLICT (k) DO UPDATE SET v = excluded.v`, canonJSON(l)); err != nil {
		return err
	}
	return s.reload(ctx)
}
