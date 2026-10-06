package core

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/middle-management/patchlog/internal/grant"
)

// Operator key history (§C.4). A deployment publishes its operator keys as
// a JWK Set at the jwks_uri of GET / (§7), by default
// <origin>/.well-known/patchlog-keys: a history, not a current set, each
// key with the RFC 3339 period it was in force, so a grant an operator key
// signed verifies against the key in force at a revision's created time
// (§C.3.1).
//
// The history is configuration: Options.OperatorKeyHistory lists every
// key the deployment has had with its period, retired ones included, which
// are published but no longer accepted. A key past its until authorises
// nothing (§C.4): an operator key the history gives an until is refused
// from that time on (operatorKeys), judged against the current time, so a
// key can be scheduled to retire. A key of Options.OperatorKeys that
// the history doesn't list is published as in force from the deployment's
// first namespace entry (the earliest time anything it signed can have
// been used here), or from the time the server started if there is none
// yet; one it lists takes the listed period, whose public key must match.

// OperatorKeyPeriod is an operator key and the period it was in force.
// Until is zero for a key still in force.
type OperatorKeyPeriod struct {
	Kid         string
	Pub         ed25519.PublicKey
	From, Until time.Time
}

// operatorKeys is Options.OperatorKeys without the keys past their until
// in the history (§C.4): nil if none are configured, else possibly empty.
func (t *tx) operatorKeys() []grant.Key {
	keys := t.e.opt.OperatorKeys
	if len(keys) == 0 || len(t.e.opt.OperatorKeyHistory) == 0 {
		return keys
	}
	out := make([]grant.Key, 0, len(keys))
	for _, k := range keys {
		if !operatorKeyRetired(t.e.opt.OperatorKeyHistory, k.Kid, t.now) {
			out = append(out, k)
		}
	}
	return out
}

// operatorKeyRetired reports whether the history gives kid an until at or
// before now.
func operatorKeyRetired(hist []OperatorKeyPeriod, kid string, now time.Time) bool {
	for _, p := range hist {
		if p.Kid == kid {
			return !p.Until.IsZero() && !now.Before(p.Until)
		}
	}
	return false
}

// DefaultJWKSPath is where the operator key history is served by default
// (§C.4).
const DefaultJWKSPath = "/.well-known/patchlog-keys"

// JWKSURI is the jwks_uri GET / publishes (§7, §C.4).
func (e *Engine) JWKSURI() string {
	if e.opt.JWKSURI != "" {
		return e.opt.JWKSURI
	}
	return strings.TrimSuffix(e.opt.Origin, "/") + DefaultJWKSPath
}

// checkOperatorKeyHistory validates Options.OperatorKeyHistory against
// Options.OperatorKeys: kids are unique, never reused for another key, and
// periods are well formed.
func checkOperatorKeyHistory(o *Options) error {
	seen := map[string]ed25519.PublicKey{}
	for _, p := range o.OperatorKeyHistory {
		if p.Kid == "" || len(p.Pub) != ed25519.PublicKeySize {
			return fmt.Errorf("operator key history: an entry needs a kid and an Ed25519 public key")
		}
		if _, dup := seen[p.Kid]; dup {
			return fmt.Errorf("operator key history: kid %q is listed twice", p.Kid)
		}
		seen[p.Kid] = p.Pub
		if p.From.IsZero() {
			return fmt.Errorf("operator key history: %q needs a from time", p.Kid)
		}
		if !p.Until.IsZero() && !p.From.Before(p.Until) {
			return fmt.Errorf("operator key history: %q: from must be before until", p.Kid)
		}
	}
	for _, k := range o.OperatorKeys {
		if pub, ok := seen[k.Kid]; ok && !pub.Equal(k.Pub) {
			return fmt.Errorf("operator key history: kid %q names another key than the operator key (kids are never reused, §C.4)", k.Kid)
		}
	}
	return nil
}

// OperatorKeyHistory is the deployment's operator key history (§C.4), in
// the order configured: the history's entries, then the operator keys it
// doesn't list.
func (e *Engine) OperatorKeyHistory(ctx context.Context) ([]OperatorKeyPeriod, error) {
	out := append([]OperatorKeyPeriod(nil), e.opt.OperatorKeyHistory...)
	listed := map[string]bool{}
	for _, p := range out {
		listed[p.Kid] = true
	}
	var from time.Time
	for _, k := range e.opt.OperatorKeys {
		if listed[k.Kid] {
			continue
		}
		if from.IsZero() {
			var err error
			if from, err = e.firstEntryTime(ctx); err != nil {
				return nil, err
			}
		}
		out = append(out, OperatorKeyPeriod{Kid: k.Kid, Pub: k.Pub, From: from})
	}
	return out, nil
}

// firstEntryTime is the created time of the deployment's first namespace
// entry, or the time the engine started if there is none. It is cached
// once found.
func (e *Engine) firstEntryTime(ctx context.Context) (time.Time, error) {
	e.firstEntryMu.Lock()
	defer e.firstEntryMu.Unlock()
	if !e.firstEntry.IsZero() {
		return e.firstEntry, nil
	}
	var ms sql.NullInt64
	err := e.read(ctx, func(t *tx) error {
		return t.QueryRow(`SELECT MIN(created) FROM ns_log WHERE seq = (SELECT MIN(seq) FROM ns_log)`).Scan(&ms)
	})
	if err != nil {
		return time.Time{}, err
	}
	if !ms.Valid {
		// Nothing signed by an operator key has been used yet: in force
		// from now on. Not cached, so the first entry sets it later.
		return e.started, nil
	}
	e.firstEntry = time.UnixMilli(ms.Int64).UTC()
	return e.firstEntry, nil
}

// JWKS is the operator key history as a JWK Set (RFC 7517, §C.4): OKP
// Ed25519 keys with kid, use "sig" and "patchlog": { from, until? }.
func (e *Engine) JWKS(ctx context.Context) (map[string]any, error) {
	hist, err := e.OperatorKeyHistory(ctx)
	if err != nil {
		return nil, err
	}
	keys := []any{}
	for _, p := range hist {
		period := map[string]any{"from": p.From.UTC().Format(time.RFC3339)}
		if !p.Until.IsZero() {
			period["until"] = p.Until.UTC().Format(time.RFC3339)
		}
		keys = append(keys, map[string]any{"kty": "OKP", "crv": "Ed25519", "x": base64.RawURLEncoding.EncodeToString(p.Pub),
			"kid": p.Kid, "use": "sig", "patchlog": period})
	}
	return map[string]any{"keys": keys}, nil
}
