package tree

import (
	"context"

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
// An error is the document's read failing: the follower isn't started
// without knowing, since it would then checkpoint past the first entry.
// A purged catalog is the follower's to find.
func (s *Service) catalogOpts(ctx context.Context, ns, real string, opts []follow.Option) ([]follow.Option, error) {
	if ns != s.opt.Catalog || real != ns {
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
	if b, _ := d.Value["base"].(map[string]any); b == nil {
		return opts, nil
	}
	return append(opts[:len(opts):len(opts)], follow.AsBranch()), nil
}
