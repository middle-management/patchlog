package bundle

import (
	"context"

	"github.com/middle-management/patchlog/internal/client"
)

// NoncedUpstreams runs an import's checks as Import does, up to the access
// check, and returns the namespaces whose generated patch sets carry a
// fresh $nonce (sealedT): the targets and upstreams the import writes, and
// the upstreams of the snapshot documents a partial import holds, whose
// chains it compares as they were written (§G.4.4).
func NoncedUpstreams(ctx context.Context, c *client.Client, open Opener, opt ImportOptions) (map[string]bool, error) {
	if opt.UpstreamSuffix == "" {
		opt.UpstreamSuffix = "-upstream"
	}
	im := &importer{c: c, opt: opt, docs: map[string]*bdoc{}, up: map[string]*upPlan{},
		points: map[string]map[string]point{}, schemas: map[string]any{}, nodes: map[string]*node{}, listed: map[string]*listing{}, gates: map[string]*gate{}}
	if len(opt.Only) > 0 {
		im.only, im.outRefs, im.held = map[string]bool{}, map[string]map[string]bool{}, map[string]bool{}
		for _, ns := range opt.Only {
			im.only[ns] = true
		}
	}
	if err := im.load(open); err != nil {
		return nil, err
	}
	im.leaveOut()
	im.rep = &Report{Origin: im.h.Origin, Digest: im.digest, Mode: opt.Mode}
	to, err := c.Origin(ctx)
	if err != nil {
		return nil, err
	}
	im.origin, im.local = to, to == im.h.Origin
	if err := im.resolveRenames(ctx); err != nil {
		return nil, err
	}
	if err := im.checkUpstreams(); err != nil {
		return nil, err
	}
	if err := im.checkAccess(ctx); err != nil {
		return nil, err
	}
	return im.sealedT, nil
}
