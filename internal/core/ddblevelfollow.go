package core

// Following a remote base's level on DynamoDB (§G.5.2): followConfig,
// followLevel and restrictRead of remote_branch.go, each raise and
// restriction a config write of this deployment's own (serverConfig),
// committed one namespace at a time, leaves first; the raises it couldn't
// follow recorded in #REMLEVEL items (ddb/remotelevels.go), which
// recordedLevel and lostRemote read.

import (
	"context"
	"log"

	"github.com/middle-management/patchlog/internal/ddb"
	"github.com/middle-management/patchlog/internal/grant"
)

func (r *ddbReads) recordedLevel(bn *nsRow) int {
	l, err := r.s.RemoteLevelOf(r.ctx, bn.name)
	r.must(err)
	if l == nil {
		return levelNone
	}
	return l.Level
}

// lostRemote: as SQL's, over the #REMLEVEL items.
func (r *ddbReads) lostRemote(n *nsRow) (*nsRow, string, bool) {
	for b := n; b.isBranch() && !b.isShadow(); b = r.nsByID(b.base.Int64) {
		if r.remoteShadow(b) == nil {
			continue
		}
		l, err := r.s.RemoteLevelOf(r.ctx, b.name)
		r.must(err)
		if l == nil || !l.Lacks {
			return nil, "", false
		}
		rb, err := r.s.RemoteBaseOf(r.ctx, b.name)
		r.must(err)
		if rb == nil {
			return nil, "", false
		}
		return b, rb.Origin, true
	}
	return nil, "", false
}

func (b *ddbBackend) remoteLevels(ctx context.Context, ns string) ([]RemoteLevel, error) {
	ls, err := b.store.RemoteLevels(ctx)
	if err != nil {
		return nil, ddbAsErr(err)
	}
	var out []RemoteLevel
	for _, l := range ls {
		if ns != "" && l.Branch != ns {
			continue
		}
		out = append(out, RemoteLevel{Branch: l.Branch, Level: levelNames[l.Level], Lacks: l.Lacks, Rebase: l.Rebase, ID: l.ID, Created: formatTime(l.Created)})
	}
	return out, nil
}

func (b *ddbBackend) followSealed(ctx context.Context, rb *remoteBase, head string) error {
	return b.followConfig(ctx, rb.branchName, head, sourceDoc{level: levelSealed})
}

// followConfig: as SQL's, a raise of the base's level above the branch's
// followed as far as Levels allow, a read the base made non-public
// restricting a public branch's, either recorded as a config notice.
func (b *ddbBackend) followConfig(ctx context.Context, branch, id string, d sourceDoc) error {
	r := newDDBReads(b, ctx)
	type state struct {
		cur      *Config
		recorded int
		purged   bool
	}
	st, perr := ddbCheck(func() *state {
		bn := r.nsByName(branch)
		if bn == nil {
			return nil
		}
		return &state{r.config(bn.configSeq), r.recordedLevel(bn), bn.purged}
	})
	if perr != nil || st == nil || st.purged {
		return asErrOrNil(perr)
	}
	raise := d.level > st.cur.level && d.level > st.recorded
	restrict := d.read != "" && d.read != "public" && st.cur.Read == "public"
	if !raise && !restrict {
		return nil
	}
	applied := true
	if raise {
		ok, err := b.followLevel(ctx, branch, id, d.level, d.pre)
		if err != nil {
			return err
		}
		applied = ok
	}
	if restrict {
		applied = b.restrictRead(ctx, branch) && applied
	}
	now := b.e.now().UnixMilli()
	return asErrOrNil(b.store.PutNotice(ctx, branch, ddb.Notice{ID: id, Kind: "config", Applied: applied, Created: now, Seq: uint64(now) * 1000}))
}

// followLevel: as SQL's; what it couldn't follow is recorded in the
// branch's #REMLEVEL item.
func (b *ddbBackend) followLevel(ctx context.Context, branch, id string, level, pre int) (bool, error) {
	lacks, rebase := false, false
	switch {
	case b.e.opt.KeyStore == nil:
		lacks = true
	case level == levelE2E:
		rebase = true
		if err := b.raiseLeavesFirst(ctx, branch, pre); err != nil {
			log.Printf("remote branch %s: following its base's level before its raise to e2e, %s: %v", branch, levelNames[pre], err)
			lacks = true
		}
	default:
		if err := b.raiseLeavesFirst(ctx, branch, level); err != nil {
			log.Printf("remote branch %s: following its base's raise to %s: %v", branch, levelNames[level], err)
			lacks, rebase = true, true
		}
	}
	if !lacks && !rebase {
		return true, nil
	}
	was, err := b.store.RemoteLevelOf(ctx, branch)
	if err != nil {
		return false, ddbAsErr(err)
	}
	if was != nil {
		lacks, rebase = lacks || was.Lacks, rebase || was.Rebase
	}
	if err := b.store.PutRemoteLevel(ctx, ddb.RemoteLevel{Branch: branch, Level: level, Lacks: lacks, Rebase: rebase, ID: id, Created: b.e.now().UnixMilli()}); err != nil {
		return false, ddbAsErr(err)
	}
	if lacks {
		// Copies of its resources, at the edge and in the read cache, go:
		// they answer 502 now (§9).
		names, err := b.leavesFirst(ctx, branch)
		if err != nil {
			return false, err
		}
		inv := invalidation{nss: names, meta: true, flushDocs: true}
		b.e.rc.begin(inv)
		b.e.invalidate(inv, false)
		for _, n := range names {
			b.committed(n, "ns:"+n)
		}
		log.Printf("remote branch %s: its base was raised to %s, which this server lacks: what it had at at answers 502 upstream (§1)", branch, levelNames[level])
	} else {
		log.Printf("remote branch %s: its base was raised to %s, which Levels refuse a branch whose at is before the raise: rebase it (§G.5.2)", branch, levelNames[level])
	}
	return false, nil
}

// leavesFirst: branch and the branches of it that aren't purged, at any
// depth, each after its own branches (leavesFirst of remote_branch.go).
func (b *ddbBackend) leavesFirst(ctx context.Context, branch string) ([]string, error) {
	r := newDDBReads(b, ctx)
	return ddbCheck(func() []string {
		var walk func(n *nsRow) []string
		walk = func(n *nsRow) []string {
			var out []string
			for _, x := range r.branchesOf(n) {
				if !x.purged {
					out = append(out, walk(x)...)
				}
			}
			return append(out, n.name)
		}
		n := r.nsByName(branch)
		if n == nil {
			return nil
		}
		return walk(n)
	})
}

// raiseLeavesFirst raises branch and its dependents to level, leaves
// first, each that is below it.
func (b *ddbBackend) raiseLeavesFirst(ctx context.Context, branch string, level int) error {
	names, err := b.leavesFirst(ctx, branch)
	if err != nil {
		return err
	}
	for _, name := range names {
		cur, err := b.configOf(ctx, name)
		if err != nil {
			return err
		}
		if cur == nil || cur.level >= level {
			continue
		}
		ps := []any{map[string]any{"op": "add", "path": "/encryption", "value": map[string]any{"level": levelNames[level]}}}
		if _, ok := cur.Doc["schemaReads"]; ok && level >= levelSealed {
			// A member the new level refuses goes in the same write
			// (§6.1, Addendum E Levels).
			ps = append(ps, map[string]any{"op": "remove", "path": "/schemaReads"})
		}
		if err := b.serverConfig(ctx, name, ps); err != nil {
			return err
		}
	}
	return nil
}

// restrictRead: as SQL's, each public namespace of leavesFirst made
// readable by grant only. It reports whether it did.
func (b *ddbBackend) restrictRead(ctx context.Context, branch string) bool {
	names, err := b.leavesFirst(ctx, branch)
	if err != nil {
		log.Printf("remote branch %s: restricting its read as its base's: %v", branch, err)
		return false
	}
	for _, name := range names {
		cur, err := b.configOf(ctx, name)
		if err != nil || cur == nil {
			log.Printf("remote branch %s: restricting the read of %s as its base's: %v", branch, name, err)
			return false
		}
		if cur.Read != "public" {
			continue
		}
		if err := b.serverConfig(ctx, name, []any{map[string]any{"op": "add", "path": "/read", "value": "grant"}}); err != nil {
			log.Printf("remote branch %s: restricting the read of %s as its base's: %v", branch, name, err)
			return false
		}
	}
	return true
}

// serverConfig: a config write of this deployment's own to ns, by
// RemoteAuthor, under no grant, checked as one under a * key is.
func (b *ddbBackend) serverConfig(ctx context.Context, ns string, patches []any) error {
	a := &actor{principal: grant.Principal{ID: RemoteAuthor}, star: true, bucketKey: RemoteAuthor}
	_, err := b.writeConfigAs(ctx, Request{NS: ns}, ConfigChange{Patches: patches}, a)
	return err
}
