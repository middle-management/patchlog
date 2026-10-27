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

// regRow is a remote_branches row: the registration's at, its latest
// entry and the one before, and when it expires.
type regRow struct {
	atSeq, nsSeq int64
	prevSeq      sql.NullInt64
	expires      int64
}

func (t *tx) registration(n *nsRow, origin, name string) *regRow {
	r := &regRow{}
	err := t.QueryRow(`SELECT at_seq, ns_seq, prev_seq, expires FROM remote_branches WHERE ns = ? AND origin = ? AND name = ?`, n.id, origin, name).
		Scan(&r.atSeq, &r.nsSeq, &r.prevSeq, &r.expires)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	t.must(err)
	return r
}

// entryBy is the author and created time of n's entry seq.
func (t *tx) entryBy(seq int64) (author, created int64) {
	t.must(t.QueryRow(`SELECT author, created FROM ns_log WHERE seq = ?`, seq).Scan(&author, &created))
	return author, created
}

// RegisterRemoteBranch registers or renews a remote branch of a namespace
// (§G.3). It needs unrestricted read and export, is evaluated as an export
// envelope whose doc is { remote, at }, and appends a remote branch entry
// (§3.5).
func (e *Engine) RegisterRemoteBranch(ctx context.Context, req Request, rr RemoteRegistration) (*RegistrationResult, error) {
	return e.be.registerRemote(ctx, req, rr)
}

// sqlRegisterRemote is RegisterRemoteBranch on SQL.
func (e *Engine) sqlRegisterRemote(ctx context.Context, req Request, rr RemoteRegistration) (*RegistrationResult, error) {
	var out *RegistrationResult
	err := e.update(ctx, func(t *tx) error {
		p, replay, err := t.planRegistration(req, rr)
		switch {
		case err != nil:
			return err
		case replay != nil:
			out = replay
			return nil
		}
		seq, nsID := t.appendNS(p.n, p.entry, nil, nil, p.n.configSeq, t.actorID(p.a))
		var prev any
		if p.row != nil {
			prev = p.row.nsSeq
		}
		_, xerr := t.Exec(`INSERT INTO remote_branches (ns, origin, name, at_seq, ns_seq, prev_seq, expires) VALUES (?,?,?,?,?,?,?)
		ON CONFLICT (ns, origin, name) DO UPDATE SET at_seq = excluded.at_seq, ns_seq = excluded.ns_seq, prev_seq = excluded.prev_seq, expires = excluded.expires`,
			p.n.id, rr.Origin, rr.NS, p.atSeq, seq, prev, p.expires.UnixMilli())
		t.must(xerr)
		out = p.result(nsID.String())
		return nil
	})
	return out, err
}

// regPlan is a registration the gate allowed: its entry in n, by a, at
// atSeq, expiring at expires; row is the registration it renews, if any.
type regPlan struct {
	n       *nsRow
	a       *actor
	rr      RemoteRegistration
	atSeq   int64
	atID    ids.ID
	row     *regRow
	entry   map[string]any
	expires time.Time
}

func (p *regPlan) result(nsID string) *RegistrationResult {
	return &RegistrationResult{Status: 201, NSID: nsID, Origin: p.rr.Origin, NS: p.rr.NS, At: p.atID.String(), Expires: p.expires}
}

// planRegistration checks a registration (§G.3): authentication, read and
// export, the rate limit, the preconditions and retries, the rules. A
// retry of the latest entry answers it (replay).
func (t *gate) planRegistration(req Request, rr RemoteRegistration) (*regPlan, *RegistrationResult, *Error) {
	n := t.nsForWrite(req.NS)
	if n == nil {
		return nil, nil, t.absentNS(req.NS, req.Cred)
	}
	cfg := t.config(n.configSeq)
	a, aerr := t.authenticate(n.name, n, cfg, req.Cred, nil)
	if aerr != nil {
		return nil, nil, aerr
	}
	// Step 1: unrestricted read (§2.1) and export, then the rate limit.
	// Remote entries don't count toward the live-branches limit, but are
	// rate-limited.
	if !t.readsNS(n, cfg, a, true) {
		return nil, nil, forbidden("registering a remote branch needs unrestricted read (§2.1)")
	}
	if err := t.authorize(a, "export", ""); err != nil {
		return nil, nil, err
	}
	if err := t.rateLimit(n, cfg, a, nil, 1); err != nil {
		return nil, nil, err
	}
	// 410 after authorisation and the rate limit, like every write to a
	// purged namespace (§6.2, §8.5).
	if n.purged {
		return nil, nil, t.purgedNS(n)
	}
	// A remote branch of a private, sealed or e2e namespace must itself be
	// private or sealed (§G.5). This side can't enforce it: it is part of
	// what the export grant entrusts, and the branch's deployment enforces
	// it when it creates the branch.
	if !ValidRemoteOrigin(rr.Origin) {
		return nil, nil, invalid("remote.origin must be an https origin (or http on a loopback host)")
	}
	if rr.Origin == t.e.opt.Origin {
		return nil, nil, invalid("remote.origin is this deployment; create a local branch instead")
	}
	if !ValidNSName(rr.NS) {
		return nil, nil, invalid("remote.ns must be a namespace name")
	}
	atID, perr := ids.Parse(rr.At)
	if perr != nil {
		return nil, nil, invalid("at is not in the namespace's chain")
	}
	atSeq, ok := t.nsLogSeq(n.id, atID)
	if !ok {
		return nil, nil, invalid("at is not in the namespace's chain")
	}
	// Step 2: preconditions and idempotent retries.
	author := t.actorID(a)
	now := t.now.UnixMilli()
	row := t.registration(n, rr.Origin, rr.NS)
	latest := func() *RegistrationResult {
		return &RegistrationResult{Status: 200, NSID: t.nsLogID(row.nsSeq).String(), Origin: rr.Origin, NS: rr.NS,
			At: t.nsLogID(row.atSeq).String(), Expires: time.UnixMilli(row.expires).UTC()}
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
		return nil, nil, badInput("both If-Match and If-None-Match")
	case rr.IfNoneMatch:
		if row != nil && row.expires > now {
			// A retry of the request that wrote the latest entry: the same
			// principal and at, for as long as the registration is
			// unexpired, with no other bound (§G.3).
			if row.atSeq == atSeq && t.samePrincipal(row.nsSeq, a, author) {
				return nil, latest(), nil
			}
			return nil, nil, stale()
		}
	case rr.IfMatch != "":
		if row == nil {
			return nil, nil, stale()
		}
		if rr.IfMatch != t.nsLogID(row.nsSeq).String() {
			// A retry by the same principal whose If-Match names the entry
			// before the latest gets the latest, while the registration is
			// unexpired (§G.3).
			if row.prevSeq.Valid && rr.IfMatch == t.nsLogID(row.prevSeq.Int64).String() && row.atSeq == atSeq &&
				row.expires > now && t.samePrincipal(row.nsSeq, a, author) {
				return nil, latest(), nil
			}
			return nil, nil, stale()
		}
		if row.atSeq != atSeq {
			return nil, nil, invalid("a renewal must keep the registration's at")
		}
	default:
		return nil, nil, apiErr(428, "precondition_required")
	}
	// Step 6: the export envelope.
	doc := map[string]any{"remote": map[string]any{"origin": rr.Origin, "ns": rr.NS}, "at": atID.String()}
	env := t.basicEnvelope("export", "", a)
	env["writes"], env["patches"], env["doc"] = []any{}, []any{}, doc
	if err := t.checkRules(cfg, a, env, false); err != nil {
		return nil, nil, err
	}
	// Step 7.
	entry := map[string]any{"kind": "branch", "remote": map[string]any{"origin": rr.Origin, "ns": rr.NS}, "at": atID.String()}
	return &regPlan{n: n, a: a, rr: rr, atSeq: atSeq, atID: atID, row: row, entry: entry, expires: t.now.Add(cfg.Limits.RemoteRegistration)}, nil, nil
}

// samePrincipal reports whether namespace entry seq was written by the
// principal of a, whose author id is author: the same root sub and kid,
// or, while authentication is disabled, the same author (§7.2, §6.6). An
// entry that records no grant, written while authentication was disabled
// or before grants were recorded (v0.37), matches on author.
func (t *gate) samePrincipal(seq int64, a *actor, author int64) bool {
	if au, _ := t.entryBy(seq); au != author {
		return false
	}
	gid := t.entryGrantID(seq)
	if a.grant == nil || gid == nil {
		return true
	}
	if len(a.grant.Blocks) == 0 {
		return false
	}
	ref, root := t.grantRef(gid), a.grant.Blocks[0]
	return ref != nil && ref["sub"] == root.Sub && ref["kid"] == root.Kid
}

// entryGrantID is the grant namespace entry seq was written under, nil
// for none.
func (t *tx) entryGrantID(seq int64) []byte {
	var gid []byte
	t.must(t.QueryRow(`SELECT grant_id FROM ns_log WHERE seq = ?`, seq).Scan(&gid))
	return gid
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
