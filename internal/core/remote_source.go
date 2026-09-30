package core

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/middle-management/patchlog/internal/ids"
)

// This file is the source side of remote branches (§G.3): the deployment
// that holds the base accepts registrations of branches living elsewhere,
// records them in the base's chain, lists them and protects their history
// from pruning while they are unexpired.

// RemoteRegistration is POST /ns/{ns}/branches with a remote body (§G.3):
// { "remote": { "origin", "ns" }, "at" }, with If-None-Match: * to register
// or If-Match: "{ns_id of the latest entry}" to renew.
type RemoteRegistration struct {
	Origin      string
	NS          string
	At          string
	IfNoneMatch bool
	IfMatch     string
}

// RegistrationResult is the registration's latest entry.
type RegistrationResult struct {
	Status  int // 201, or 200 for an idempotent retry
	NSID    string
	Origin  string
	NS      string
	At      string
	Expires time.Time
}

// Value is the registration as listed in /branches (§7.4).
func (r *RegistrationResult) Value() map[string]any {
	return map[string]any{
		"remote":  map[string]any{"origin": r.Origin, "ns": r.NS},
		"at":      r.At,
		"ns_id":   r.NSID,
		"expires": formatTime(r.Expires.UnixMilli()),
	}
}

// regRow is a remote_branches row.
type regRow struct {
	atSeq, nsSeq int64
	prevSeq      sql.NullInt64
	expires      int64
}

func (t *tx) registration(ns int64, origin, name string) *regRow {
	r := &regRow{}
	err := t.QueryRow(`SELECT at_seq, ns_seq, prev_seq, expires FROM remote_branches WHERE ns = ? AND origin = ? AND name = ?`, ns, origin, name).
		Scan(&r.atSeq, &r.nsSeq, &r.prevSeq, &r.expires)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	t.must(err)
	return r
}

// RegisterRemoteBranch registers or renews a remote branch of a namespace
// (§G.3). It needs read and export, is evaluated as an export envelope whose
// doc is { remote, at }, and appends a remote branch entry (§3.5).
func (e *Engine) RegisterRemoteBranch(ctx context.Context, req Request, rr RemoteRegistration) (*RegistrationResult, error) {
	var out *RegistrationResult
	err := e.update(ctx, func(t *tx) error {
		r, err := t.registerRemote(req, rr)
		out = r
		return asErr(err)
	})
	return out, err
}

func (t *tx) registerRemote(req Request, rr RemoteRegistration) (*RegistrationResult, *Error) {
	n := t.nsByName(req.NS)
	if n == nil {
		return nil, notFound()
	}
	if n.purged {
		return nil, gone()
	}
	cfg := t.config(n.configSeq)
	a, aerr := t.authenticate(n.name, n, cfg, req.Cred, nil)
	if aerr != nil {
		return nil, aerr
	}
	// Step 1: read and export, then the rate limit. Remote entries don't
	// count toward the live-branches limit, but are rate-limited.
	if cfg.Read != "public" {
		if err := t.authorize(a, "read", ""); err != nil {
			return nil, forbidden("registering a remote branch needs read")
		}
	}
	if err := t.authorize(a, "export", ""); err != nil {
		return nil, err
	}
	if err := t.rateLimit(n, cfg, a, nil, 1); err != nil {
		return nil, err
	}
	if !ValidRemoteOrigin(rr.Origin) {
		return nil, invalid("remote.origin must be an https origin (or http on a loopback host)")
	}
	if rr.Origin == t.e.opt.Origin {
		return nil, invalid("remote.origin is this deployment; create a local branch instead")
	}
	if !ValidNSName(rr.NS) {
		return nil, invalid("remote.ns must be a namespace name")
	}
	atID, perr := ids.Parse(rr.At)
	if perr != nil {
		return nil, invalid("at is not in the namespace's chain")
	}
	atSeq, ok := t.nsLogSeq(n.id, atID)
	if !ok {
		return nil, invalid("at is not in the namespace's chain")
	}
	// Step 2: preconditions and idempotent retries.
	author := t.authorID(a.id())
	now := t.now.UnixMilli()
	row := t.registration(n.id, rr.Origin, rr.NS)
	latest := func() *RegistrationResult {
		return &RegistrationResult{Status: 200, NSID: t.nsLogID(row.nsSeq).String(), Origin: rr.Origin, NS: rr.NS,
			At: t.nsLogID(row.atSeq).String(), Expires: time.UnixMilli(row.expires).UTC()}
	}
	entryBy := func(seq int64) (int64, int64) {
		var au, created int64
		t.must(t.QueryRow(`SELECT author, created FROM ns_log WHERE seq = ?`, seq).Scan(&au, &created))
		return au, created
	}
	stale := func() *Error {
		e := apiErr(412, "stale")
		if row != nil {
			e.Body["head"] = t.nsLogID(row.nsSeq).String()
		} else {
			e.Body["head"] = nil
		}
		return e
	}
	switch {
	case rr.IfNoneMatch && rr.IfMatch != "":
		return nil, badInput("both If-Match and If-None-Match")
	case rr.IfNoneMatch:
		if row != nil && row.expires > now {
			// A retry of the request that wrote the latest entry: same
			// principal and at, within the retry window (§7.2).
			au, created := entryBy(row.nsSeq)
			if au == author && row.atSeq == atSeq && now-created <= cfg.Limits.RetryWindow.Milliseconds() {
				return latest(), nil
			}
			return nil, stale()
		}
	case rr.IfMatch != "":
		if row == nil {
			return nil, stale()
		}
		if rr.IfMatch != t.nsLogID(row.nsSeq).String() {
			// A retry by the same principal whose If-Match names the entry
			// before the latest gets the latest.
			if row.prevSeq.Valid && rr.IfMatch == t.nsLogID(row.prevSeq.Int64).String() && row.atSeq == atSeq {
				if au, _ := entryBy(row.nsSeq); au == author {
					return latest(), nil
				}
			}
			return nil, stale()
		}
		if row.atSeq != atSeq {
			return nil, invalid("a renewal must keep the registration's at")
		}
	default:
		return nil, apiErr(428, "precondition_required")
	}
	// Step 6: the export envelope.
	doc := map[string]any{"remote": map[string]any{"origin": rr.Origin, "ns": rr.NS}, "at": atID.String()}
	env := t.basicEnvelope("export", "", a)
	env["writes"], env["patches"], env["doc"] = []any{}, []any{}, doc
	if err := t.checkRules(cfg, a, env, false); err != nil {
		return nil, err
	}
	// Step 7.
	entry := map[string]any{"kind": "branch", "remote": map[string]any{"origin": rr.Origin, "ns": rr.NS}, "at": atID.String()}
	seq, nsID := t.appendNS(n, entry, nil, nil, n.configSeq, author)
	expires := t.now.Add(cfg.Limits.RemoteBranchLife)
	var prev any
	if row != nil {
		prev = row.nsSeq
	}
	_, err := t.Exec(`INSERT INTO remote_branches (ns, origin, name, at_seq, ns_seq, prev_seq, expires) VALUES (?,?,?,?,?,?,?)
		ON CONFLICT (ns, origin, name) DO UPDATE SET at_seq = excluded.at_seq, ns_seq = excluded.ns_seq, prev_seq = excluded.prev_seq, expires = excluded.expires`,
		n.id, rr.Origin, rr.NS, atSeq, seq, prev, expires.UnixMilli())
	t.must(err)
	return &RegistrationResult{Status: 201, NSID: nsID.String(), Origin: rr.Origin, NS: rr.NS, At: atID.String(), Expires: expires}, nil
}

// liveRegistrations lists the unexpired remote branch registrations of n.
func (t *tx) liveRegistrations(n *nsRow) []map[string]any {
	rows, err := t.Query(`SELECT origin, name, at_seq, ns_seq, expires FROM remote_branches WHERE ns = ? AND expires > ? ORDER BY origin, name`, n.id, t.now.UnixMilli())
	t.must(err)
	type raw struct {
		origin, name string
		at, seq, exp int64
	}
	var rs []raw
	for rows.Next() {
		var r raw
		t.must(rows.Scan(&r.origin, &r.name, &r.at, &r.seq, &r.exp))
		rs = append(rs, r)
	}
	rows.Close()
	out := make([]map[string]any, 0, len(rs))
	for _, r := range rs {
		out = append(out, map[string]any{
			"remote":  map[string]any{"origin": r.origin, "ns": r.name},
			"at":      t.nsLogID(r.at).String(),
			"ns_id":   t.nsLogID(r.seq).String(),
			"expires": formatTime(r.exp),
		})
	}
	return out
}

// registeredAts are the at seqs of n's unexpired registrations, which
// protect history from pruning (§8.6).
func (t *tx) registeredAts(n *nsRow) []int64 {
	rows, err := t.Query(`SELECT at_seq FROM remote_branches WHERE ns = ? AND expires > ?`, n.id, t.now.UnixMilli())
	t.must(err)
	defer rows.Close()
	var out []int64
	for rows.Next() {
		var s int64
		t.must(rows.Scan(&s))
		out = append(out, s)
	}
	return out
}
