package client

import (
	"errors"
	"fmt"
	"sync"
)

// Levels a client has learnt (§7.1 End-to-end namespaces, Addendum E
// Levels). A client learns a namespace's encryption level from its
// configuration (WithExpectedLevel), from the namespace's current
// document, or else from the level POST /keys names, and keeps the highest
// it has learnt: a level is never lowered, so a source that names a lower
// one than the client holds, as a server or a cache in front of it may to
// have content read or written in the clear, is ErrLevelLowered, never
// believed. A transport error, a 404 and an answer that names no level
// teach nothing. The table is in memory only, shared by a Client, its
// With copies and their E2E views: a client's first contact can't tell a
// server that claims a lower level, so a namespace known to be end-to-end
// is configured with WithExpectedLevel.

// ErrLevelLowered reports a namespace document or /keys answer naming a
// lower encryption level than the client has learnt for the namespace
// (§7.1, Levels).
var ErrLevelLowered = errors.New("the server names a lower encryption level than this client has learnt for the namespace (§7.1, Levels)")

// levelRank orders the levels: none < at-rest < sealed < e2e. A level
// this client doesn't know has no rank.
func levelRank(level string) (int, bool) {
	switch level {
	case "":
		return 0, true
	case "at-rest":
		return 1, true
	case "sealed":
		return 2, true
	case "e2e":
		return 3, true
	}
	return 0, false
}

// levelTable holds the highest level learnt per namespace.
type levelTable struct {
	mu sync.Mutex
	m  map[string]string
}

// held is the level held for ns, "" for none.
func (t *levelTable) held(ns string) string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.m[ns]
}

// expect records level for ns as configuration gives it, keeping the
// higher. A level it doesn't know is held as e2e: the highest, so that a
// mistyped setting refuses rather than protects nothing.
func (t *levelTable) expect(ns, level string) {
	r, ok := levelRank(level)
	if !ok {
		level, r = "e2e", 3
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if h, _ := levelRank(t.m[ns]); r > h {
		if t.m == nil {
			t.m = map[string]string{}
		}
		t.m[ns] = level
	}
}

// learn takes level, which ns's current document or /keys names, and
// returns the level held after it: level itself, recorded, unless a
// higher one is held, which is ErrLevelLowered, as is a level this client
// doesn't know while any is held.
func (t *levelTable) learn(ns, level string) (string, error) {
	r, ok := levelRank(level)
	t.mu.Lock()
	defer t.mu.Unlock()
	held := t.m[ns]
	h, _ := levelRank(held)
	if r < h || !ok && h > 0 {
		return held, fmt.Errorf("client: namespace %s: level %q where %q is held: %w", ns, level, held, ErrLevelLowered)
	}
	if ok && r > h {
		if t.m == nil {
			t.m = map[string]string{}
		}
		t.m[ns] = level
	}
	return level, nil
}

// WithExpectedLevel configures the encryption level namespace ns is known
// to have: "at-rest", "sealed" or "e2e" (§7.1, Levels). The client holds
// it from its first request on, so a server that claims a lower one is
// ErrLevelLowered, and with "e2e" a 200 of a resource other than the
// keyring that isn't application/jose is refused. The highest of several
// counts, and it is shared with the client's With copies. A level this
// client doesn't know is held as "e2e".
func WithExpectedLevel(ns, level string) Option {
	return func(c *Client) {
		if c.levels == nil {
			c.levels = &levelTable{}
		}
		c.levels.expect(ns, level)
	}
}

// ValidLevel reports whether level is an encryption level WithExpectedLevel
// takes as named: "at-rest", "sealed" or "e2e".
func ValidLevel(level string) bool {
	r, ok := levelRank(level)
	return ok && r > 0
}

// HeldLevel is the encryption level the client holds for ns: the highest
// it was configured with or has learnt, "" for none.
func (c *Client) HeldLevel(ns string) string { return c.levels.held(ns) }

// heldOver is level, which something that teaches nothing suggests (a
// 404's "not sealed", a log's delivery), unless the client holds sealed
// or e2e for ns above it: then the level held. Plain and at rest read
// alike, so neither is held over the other.
func (c *Client) heldOver(ns, level string) string {
	held := c.levels.held(ns)
	hr, _ := levelRank(held)
	if lr, ok := levelRank(level); hr >= 2 && (!ok || lr < hr) {
		return held
	}
	return level
}

// learnDocLevel learns ns's level from r, a 200 for its current namespace
// document: "sealed" for one served as a JWE (E2), else its
// encryption.level.
func (c *Client) learnDocLevel(ns string, r *response) (string, error) {
	lv := "sealed"
	if !isJOSE(r) {
		enc, _ := r.obj()["encryption"].(map[string]any)
		lv, _ = enc["level"].(string)
	}
	return c.levels.learn(ns, lv)
}

// refusePlain is the error for r, a 200 for a document of ns/name, where
// the client holds e2e for ns and r isn't a JWE: an end-to-end namespace
// serves no document but its keyring in the clear (§7.1).
func (c *Client) refusePlain(ns, name string, r *response) error {
	if name == KeyringName || isJOSE(r) || c.levels.held(ns) != "e2e" {
		return nil
	}
	return fmt.Errorf("client: %s/%s: the server answered 200 %s in a namespace this client holds as e2e, not application/jose (§7.1): %w", ns, name, r.header.Get("Content-Type"), ErrLevelLowered)
}
