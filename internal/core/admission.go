package core

import (
	"time"

	"github.com/middle-management/patchlog/internal/grant"
)

// What an event stream was admitted under (§7.3).
//
// An event stream judges its read check again before each page it sends,
// and ends instead if it fails, as every fetch it makes is checked as a
// request made then. It also ends, at the latest, when the grant or cookie
// it was admitted under expires (§C.2, §C.5.3), even when nothing is
// written to wake it: each read it makes answers that expiry in Log.Until,
// and the stream ends there.

// admittedUntil is when the credential that admitted a read of n by a,
// with cred, expires: the earliest exp of the grant's blocks, or an edge
// grant's (the cookie's) exp, as the origin verified it from the cookie
// itself, never from the edge's headers (§C.5.3). It is zero where none
// bounds the read: in a public namespace, which reads without a grant
// (§7), with authentication disabled (§1), and for a grant whose blocks
// carry no exp.
func (t *tx) admittedUntil(n *nsRow, cred Credentials, a *actor) time.Time {
	switch {
	case t.cachePublic(n) || t.e.opt.AuthDisabled:
		return time.Time{}
	case cred.Edge != nil:
		return cred.Edge.Exp
	case a != nil && a.grant != nil:
		return grantExp(a.grant)
	}
	return time.Time{}
}

// grantExp is the earliest exp of g's blocks, zero if none has one: a
// narrowed grant expires with its earliest block (§C.1).
func grantExp(g *grant.Grant) time.Time {
	var exp time.Time
	for _, b := range g.Blocks {
		if b.Exp != nil && (exp.IsZero() || b.Exp.Before(exp)) {
			exp = *b.Exp
		}
	}
	return exp
}
