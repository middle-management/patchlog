package core

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/jsonv"
)

// RetentionRule is one entry of a namespace document's `retention` (§8.6):
//
//	{ "select"?: { "prefix": "telemetry-" } | { "names": ["a", "b"] },
//	  "keep": { "revisions"?: 50, "age"?: "PT10M" },
//	  "archive"?: "file:///var/archive/telemetry/" | false }
//
// keep is required and needs at least one of revisions and age, so a rule
// can't prune everything by accident.
type RetentionRule struct {
	Prefix string   // select.prefix
	Names  []string // select.names
	// KeepRevisions is the number of newest entries kept; -1 if unset.
	KeepRevisions int
	// KeepAge keeps everything newer than it; 0 if unset.
	KeepAge time.Duration
	Archive string // destination for this rule's archives; "" = the operator's default
	// NoArchive is "archive": false: the rule prunes without an archive,
	// irreversibly (§8.6).
	NoArchive bool
}

// matches reports whether the rule selects a resource.
func (r *RetentionRule) matches(name string) bool {
	switch {
	case r.Names != nil:
		for _, n := range r.Names {
			if n == name {
				return true
			}
		}
		return false
	case r.Prefix != "":
		return strings.HasPrefix(name, r.Prefix)
	}
	return true
}

// retentionRule returns the first rule selecting name, or nil.
func (c *Config) retentionRule(name string) *RetentionRule {
	for i := range c.Retention {
		if c.Retention[i].matches(name) {
			return &c.Retention[i]
		}
	}
	return nil
}

// retentionIndex is the index of a rule of cfg.Retention.
func (t *gate) retentionIndex(cfg *Config, r *RetentionRule) int {
	for i := range cfg.Retention {
		if &cfg.Retention[i] == r {
			return i
		}
	}
	return -1
}

func parseRetention(v any) ([]RetentionRule, error) {
	arr, ok := v.([]any)
	if !ok {
		return nil, fmt.Errorf("/retention must be an array")
	}
	out := make([]RetentionRule, 0, len(arr))
	for i, e := range arr {
		m, ok := e.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("/retention/%d must be an object", i)
		}
		r := RetentionRule{KeepRevisions: -1}
		hasKeep := false
		for k, x := range m {
			switch k {
			case "select":
				s, ok := x.(map[string]any)
				if !ok || len(s) != 1 {
					return nil, fmt.Errorf("/retention/%d/select must be { prefix } or { names }", i)
				}
				if p, has := s["prefix"]; has {
					ps, ok := p.(string)
					if !ok || ps == "" {
						return nil, fmt.Errorf("/retention/%d/select/prefix must be a non-empty string", i)
					}
					r.Prefix = ps
				} else if ns, has := s["names"]; has {
					na, ok := ns.([]any)
					if !ok {
						return nil, fmt.Errorf("/retention/%d/select/names must be an array of resource names", i)
					}
					r.Names = []string{}
					for _, n := range na {
						s, ok := n.(string)
						if !ok || !ValidResourceName(s) {
							return nil, fmt.Errorf("/retention/%d/select/names must be an array of resource names", i)
						}
						r.Names = append(r.Names, s)
					}
				} else {
					return nil, fmt.Errorf("/retention/%d/select must be { prefix } or { names }", i)
				}
			case "keep":
				km, ok := x.(map[string]any)
				if !ok || len(km) == 0 {
					return nil, fmt.Errorf("/retention/%d/keep must be { revisions?, age? } with at least one", i)
				}
				for kk, kv := range km {
					switch kk {
					case "revisions":
						n, ok := kv.(float64)
						if !ok || n < 0 || n != float64(int(n)) {
							return nil, fmt.Errorf("/retention/%d/keep/revisions must be a non-negative integer", i)
						}
						r.KeepRevisions = int(n)
					case "age":
						s, _ := kv.(string)
						d, err := ParseDuration(s)
						if err != nil || d <= 0 {
							return nil, fmt.Errorf("/retention/%d/keep/age must be a positive ISO 8601 duration", i)
						}
						r.KeepAge = d
					default:
						return nil, fmt.Errorf("/retention/%d/keep/%s is not a known field", i, kk)
					}
				}
				hasKeep = true
			case "archive":
				if x == false {
					r.NoArchive = true
					continue
				}
				s, ok := x.(string)
				u, err := url.Parse(s)
				if !ok || err != nil || u.Scheme == "" {
					return nil, fmt.Errorf("/retention/%d/archive must be a URL or false", i)
				}
				r.Archive = s
			default:
				return nil, fmt.Errorf("/retention/%d/%s is not a known field", i, k)
			}
		}
		if !hasKeep {
			return nil, fmt.Errorf("/retention/%d needs keep", i)
		}
		out = append(out, r)
	}
	return out, nil
}

// checkArchives rejects retention archive destinations the operator doesn't
// allow (§8.6: the server MUST NOT write anywhere else).
func (e *Engine) checkArchives(cfg *Config) *Error {
	for i, r := range cfg.Retention {
		if r.Archive == "" {
			continue
		}
		if e.opt.Archiver == nil {
			return invalid(fmt.Sprintf("/retention/%d/archive: this deployment allows no archive destinations", i))
		}
		if err := e.opt.Archiver.Check(r.Archive); err != nil {
			return invalid(fmt.Sprintf("/retention/%d/archive: %v", i, err))
		}
	}
	return nil
}

// retentionBoundary is the seq of the oldest entry the rule keeps for res:
// entries at or after it stay. keep keeps whichever is longer, the last
// revisions or everything newer than age (§8.6); the head always stays.
func (t *gate) retentionBoundary(r *RetentionRule, res *resRow) int64 {
	head := res.headSeq.Int64
	b := head
	if r.KeepRevisions > 0 {
		seq, ok := t.nthNewestRev(res.id, r.KeepRevisions)
		if !ok {
			// Fewer entries than that: everything stays.
			seq = t.firstRev(res.id)
		}
		b = min(b, seq)
	}
	if r.KeepAge > 0 {
		if seq, ok := t.firstRevSince(res.id, t.now.Add(-r.KeepAge).UnixMilli()); ok {
			b = min(b, seq)
		}
	}
	return b
}

// nthNewestRev is res's k-th newest revision (k ≥ 1).
func (t *tx) nthNewestRev(res int64, k int) (int64, bool) {
	var seq int64
	err := t.QueryRow(`SELECT seq FROM revisions WHERE res = ? ORDER BY seq DESC LIMIT 1 OFFSET ?`, res, k-1).Scan(&seq)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, false
	}
	t.must(err)
	return seq, true
}

// firstRev is res's first revision.
func (t *tx) firstRev(res int64) int64 {
	var seq int64
	t.must(t.QueryRow(`SELECT MIN(seq) FROM revisions WHERE res = ?`, res).Scan(&seq))
	return seq
}

// RetentionAuthor is the author recorded for prunes by the retention applier.
const RetentionAuthor = "system:retention"

// RetentionReport summarises one run of the retention applier.
type RetentionReport struct {
	Checked int // resources a rule selected
	Pruned  int // resources whose horizon moved
	Errors  []error
}

// ApplyRetention applies every non-branch namespace's retention rules once
// (§8.6). It runs as the server itself, not under a grant: the rules were
// set with a * key. Each resource is pruned in its own transaction.
func (e *Engine) ApplyRetention(ctx context.Context) (*RetentionReport, error) {
	type target struct{ ns, name string }
	var targets []target
	err := e.gateRead(ctx, func(t *gate) error {
		all := t.allNamespaces()
		sort.Slice(all, func(i, j int) bool { return all[i].name < all[j].name })
		for _, n := range all {
			// At E3 the server can't compute the snapshot a prune needs:
			// a key-holding janitor applies retention (§8.6).
			if c := t.config(n.configSeq); n.isBranch() || len(c.Retention) == 0 || c.level == levelE2E {
				continue
			}
			for _, name := range t.retainedNames(n) {
				targets = append(targets, target{n.name, name})
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	rep := &RetentionReport{}
	for _, tg := range targets {
		if err := e.jobStep(ctx); err != nil {
			return rep, err
		}
		checked, pruned, err := e.be.retain(ctx, tg.ns, tg.name)
		if checked {
			rep.Checked++
		}
		if pruned {
			rep.Pruned++
		}
		if err != nil {
			rep.Errors = append(rep.Errors, fmt.Errorf("%s/%s: %w", tg.ns, tg.name, err))
		}
	}
	return rep, nil
}

// planRetention decides what retention prunes of name in nsName (§8.6):
// nil if nothing; checked if a rule selected it.
func (t *gate) planRetention(nsName, name string) (p *prunePlan, checked bool, err error) {
	n := t.nsForWrite(nsName)
	if n == nil || n.purged || n.isBranch() || n.isShadow() {
		return nil, false, nil
	}
	cfg := t.config(n.configSeq)
	rule := cfg.retentionRule(name)
	if rule == nil || cfg.level == levelE2E {
		return nil, false, nil
	}
	v := t.resolve(n, name, nil)
	own := v.own
	if own == nil || v.state == Purged || !own.headSeq.Valid {
		return nil, false, nil
	}
	// A rule without archive uses the operator's destination; with none,
	// it applies only if it says "archive": false (§8.6).
	var dest string
	var hasArchive bool
	if !rule.NoArchive {
		dest, hasArchive = t.archiveDest(rule)
		if rule.Archive != "" && !hasArchive {
			return nil, true, fmt.Errorf("archive destination %q is not allowed by this deployment; not pruning", rule.Archive)
		}
		if !hasArchive {
			key := fmt.Sprintf("%s\x00%d\x00%d", n.name, n.configSeq, t.retentionIndex(cfg, rule))
			if _, logged := t.e.retentionSkipped.LoadOrStore(key, true); !logged {
				log.Printf("retention: %s: a rule without archive applies only with an operator archive destination or \"archive\": false; skipping it (§8.6)", n.name)
			}
			return nil, false, nil
		}
	}
	h := t.rev(t.retentionBoundary(rule, own))
	h = t.protect(n, cfg, own.id, h)
	// The resource's current keep set stays: retention doesn't replace it.
	head := t.rev(own.headSeq.Int64)
	var keepStrs []string
	var keep []*revRow
	if own.keep.Valid {
		if a, ok := jsonv.MustParse([]byte(own.keep.String)).([]any); ok {
			for _, x := range a {
				s, _ := x.(string)
				id, err := ids.Parse(s)
				if err != nil {
					continue
				}
				if row := t.findInAncestry(head, id); row != nil && row.kind == kindRev {
					keep = append(keep, row)
					keepStrs = append(keepStrs, s)
				}
			}
		}
	}
	return &prunePlan{n: n, cfg: cfg, own: own, h: h, keep: keep, keepStrs: keepStrs, dest: dest, hasArchive: hasArchive}, true, nil
}

func (t *tx) applyRetention(nsName, name string) (checked, pruned bool, err error) {
	p, checked, err := t.planRetention(nsName, name)
	if p == nil || err != nil {
		return checked, false, err
	}
	res, perr := t.pruneTo(p.n, name, p.own, p.h, p.keep, p.keepStrs, p.dest, p.hasArchive, t.authorID(RetentionAuthor))
	if perr != nil {
		return true, false, perr
	}
	return true, res.NSID != "", nil
}

// retentionLoop runs the applier every interval until Close.
func (e *Engine) retentionLoop(interval time.Duration) {
	defer e.bg.Done()
	tk := time.NewTicker(interval)
	defer tk.Stop()
	for {
		select {
		case <-e.stop:
			return
		case <-tk.C:
			ctx, cancel := context.WithCancel(context.Background())
			go func() {
				select {
				case <-e.stop:
				case <-ctx.Done():
				}
				cancel()
			}()
			if !e.leader(ctx) {
				cancel()
				continue // another instance applies it (pglock.go)
			}
			rep, err := e.ApplyRetention(leaderJob(ctx))
			cancel()
			if err != nil {
				log.Printf("retention: %v", err)
				continue
			}
			for _, err := range rep.Errors {
				log.Printf("retention: %v", err)
			}
			if rep.Pruned > 0 {
				log.Printf("retention: pruned %d of %d resources", rep.Pruned, rep.Checked)
			}
		}
	}
}

// sqlRetain applies retention to name in ns (ApplyRetention, on SQL).
func (e *Engine) sqlRetain(ctx context.Context, ns, name string) (checked, pruned bool, err error) {
	err = e.update(ctx, func(t *tx) error {
		c, p, err := t.applyRetention(ns, name)
		checked, pruned = c, p
		return err
	})
	return checked, pruned, err
}

// resourceNames lists n's own unpurged resources with a head, by name.
func (t *tx) retainedNames(n *nsRow) []string {
	rs, err := t.Query(`SELECT name FROM resources WHERE ns = ? AND state != ? AND head_seq IS NOT NULL ORDER BY name`, n.id, statePurged)
	t.must(err)
	defer rs.Close()
	var out []string
	for rs.Next() {
		var name string
		t.must(rs.Scan(&name))
		out = append(out, name)
	}
	t.must(rs.Err())
	return out
}
