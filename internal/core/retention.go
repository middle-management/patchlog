package core

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net/url"
	"strings"
	"time"

	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/jsonv"
)

// RetentionRule is one entry of a namespace document's `retention` (§8.6):
//
//	{ "select"?: { "prefix": "telemetry-" } | { "names": ["a", "b"] },
//	  "keep": { "revisions"?: 50, "age"?: "PT10M" },
//	  "archive"?: "file:///var/archive/telemetry/" }
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
				s, ok := x.(string)
				u, err := url.Parse(s)
				if !ok || err != nil || u.Scheme == "" {
					return nil, fmt.Errorf("/retention/%d/archive must be a URL", i)
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
func (t *tx) retentionBoundary(r *RetentionRule, res *resRow) int64 {
	head := res.headSeq.Int64
	b := head
	if r.KeepRevisions > 0 {
		var seq int64
		err := t.QueryRow(`SELECT seq FROM revisions WHERE res = ? ORDER BY seq DESC LIMIT 1 OFFSET ?`, res.id, r.KeepRevisions-1).Scan(&seq)
		if errors.Is(err, sql.ErrNoRows) {
			// Fewer entries than that: everything stays.
			t.must(t.QueryRow(`SELECT MIN(seq) FROM revisions WHERE res = ?`, res.id).Scan(&seq))
		} else {
			t.must(err)
		}
		b = min(b, seq)
	}
	if r.KeepAge > 0 {
		var seq sql.NullInt64
		t.must(t.QueryRow(`SELECT MIN(seq) FROM revisions WHERE res = ? AND created >= ?`, res.id, t.now.Add(-r.KeepAge).UnixMilli()).Scan(&seq))
		if seq.Valid {
			b = min(b, seq.Int64)
		}
	}
	return b
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
	err := e.read(ctx, func(t *tx) error {
		rows, err := t.Query(`SELECT ` + nsCols + ` FROM namespaces WHERE purged = 0 AND base IS NULL AND name NOT LIKE '~%' ORDER BY name`)
		t.must(err)
		var all []*nsRow
		for rows.Next() {
			n, err := scanNS(rows)
			t.must(err)
			all = append(all, n)
		}
		rows.Close()
		for _, n := range all {
			if len(t.config(n.configSeq).Retention) == 0 {
				continue
			}
			rs, err := t.Query(`SELECT name FROM resources WHERE ns = ? AND state != ? AND head_seq IS NOT NULL ORDER BY name`, n.id, statePurged)
			t.must(err)
			for rs.Next() {
				var name string
				t.must(rs.Scan(&name))
				targets = append(targets, target{n.name, name})
			}
			rs.Close()
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	rep := &RetentionReport{}
	for _, tg := range targets {
		if err := ctx.Err(); err != nil {
			return rep, err
		}
		var checked, pruned bool
		err := e.update(ctx, func(t *tx) error {
			c, p, err := t.applyRetention(tg.ns, tg.name)
			checked, pruned = c, p
			return err
		})
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

func (t *tx) applyRetention(nsName, name string) (checked, pruned bool, err error) {
	n := t.nsByName(nsName)
	if n == nil || n.purged || n.isBranch() || n.isShadow() {
		return false, false, nil
	}
	cfg := t.config(n.configSeq)
	rule := cfg.retentionRule(name)
	if rule == nil {
		return false, false, nil
	}
	own := t.resource(n.id, name)
	if own == nil || own.state == statePurged || !own.headSeq.Valid {
		return false, false, nil
	}
	dest, hasArchive := t.archiveDest(rule)
	if rule.Archive != "" && !hasArchive {
		return true, false, fmt.Errorf("archive destination %q is not allowed by this deployment; not pruning", rule.Archive)
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
	res, perr := t.pruneTo(n, name, own, h, keep, keepStrs, dest, hasArchive, t.authorID(RetentionAuthor))
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
			rep, err := e.ApplyRetention(ctx)
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
