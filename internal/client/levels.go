package client

import (
	"context"
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
//
// A branch is held at least at the level held for any base in its base
// chain (§7.1, v0.86): a branch's level is never below its base's. The
// chain is what the namespace documents the client has read name as each
// namespace's local base (link), which never changes; the level held for
// a namespace is the highest over it and those bases. A client that has
// read no document of a branch doesn't know its bases, and a remote base
// (base.origin) is another deployment's namespace, for which this table,
// kept per deployment, holds nothing.

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

// levelTable holds the highest level learnt per namespace, and the local
// bases its documents named.
type levelTable struct {
	mu sync.Mutex
	m  map[string]string
	// base[ns] lists the namespaces a document of ns named as its local
	// base: one, as a base never changes, unless a server lied, and then
	// each counts, since a link only ever raises what is held.
	base map[string][]string
	// read marks the namespaces whose current document was asked for and
	// answered, readable or not (unread).
	read map[string]bool
}

// unread reports whether the client holds any level at all and has not
// yet asked for ns's current namespace document: its chain of bases is
// then unknown, and what is held for a base can't yet hold for it.
func (t *levelTable) unread(ns string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.read[ns] {
		return false
	}
	for _, lv := range t.m {
		if lv != "" {
			return true
		}
	}
	return false
}

// markRead records that ns's current namespace document was asked for
// and answered.
func (t *levelTable) markRead(ns string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.read == nil {
		t.read = map[string]bool{}
	}
	t.read[ns] = true
}

// bases lists the local bases the documents of ns named.
func (t *levelTable) bases(ns string) []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]string(nil), t.base[ns]...)
}

// held is the level held for ns, "" for none: the highest of its own and
// those of the bases in its chain.
func (t *levelTable) held(ns string) string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.floor(ns)
}

// floor is held, for a caller that holds mu.
func (t *levelTable) floor(ns string) string {
	best := t.m[ns]
	if len(t.base[ns]) == 0 {
		return best
	}
	br, _ := levelRank(best)
	seen := map[string]bool{ns: true}
	for todo := []string{ns}; len(todo) > 0; {
		cur := todo[0]
		todo = todo[1:]
		for _, b := range t.base[cur] {
			if seen[b] {
				continue
			}
			seen[b] = true
			if r, _ := levelRank(t.m[b]); r > br {
				best, br = t.m[b], r
			}
			todo = append(todo, b)
		}
	}
	return best
}

// link records that a document of ns names base as its local base.
func (t *levelTable) link(ns, base string) {
	if base == ns || !ValidNSName(base) {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, b := range t.base[ns] {
		if b == base {
			return
		}
	}
	if t.base == nil {
		t.base = map[string][]string{}
	}
	t.base[ns] = append(t.base[ns], base)
}

// learnBase records the local base that doc, a namespace document of ns,
// names (link). A remote base, one with an origin, is none.
func (t *levelTable) learnBase(ns string, doc map[string]any) {
	b, _ := doc["base"].(map[string]any)
	if _, remote := b["origin"]; b == nil || remote {
		return
	}
	if base, _ := b["ns"].(string); base != "" {
		t.link(ns, base)
	}
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
// higher one is held, for ns or for a base in its chain, which is
// ErrLevelLowered, as is a level this client doesn't know while any is
// held.
func (t *levelTable) learn(ns, level string) (string, error) {
	r, ok := levelRank(level)
	t.mu.Lock()
	defer t.mu.Unlock()
	held := t.floor(ns)
	h, _ := levelRank(held)
	if r < h || !ok && h > 0 {
		return held, fmt.Errorf("client: namespace %s: level %q where %q is held: %w", ns, level, held, ErrLevelLowered)
	}
	if own, _ := levelRank(t.m[ns]); ok && r > own {
		// Kept as the namespace's own, though a base's already holds it.
		if t.m == nil {
			t.m = map[string]string{}
		}
		t.m[ns] = level
	}
	return level, nil
}

// learnChain reads the current namespace document of ns, and of the local
// bases those documents name, where the client holds any level and hasn't
// asked for them yet (unread), learning their levels and bases. A document
// that names a lower level than held is ErrLevelLowered. One the client
// may not read, or that isn't there, teaches nothing and isn't asked for
// again; a failure of the moment (transport, 429, 5xx) is returned, and
// asked for again next time.
func (c *Client) learnChain(ctx context.Context, ns string) error {
	todo := []string{ns}
	for n := 0; len(todo) > 0 && n < 16; n++ {
		cur := todo[0]
		todo = todo[1:]
		if c.levels.unread(cur) {
			_, _, _, err := c.currentLevel(ctx, cur)
			var ae *APIError
			switch {
			case err == nil:
			case errors.Is(err, ErrLevelLowered):
				return err
			case errors.As(err, &ae) && !Retryable(err):
				c.levels.markRead(cur)
			default:
				return err
			}
		}
		todo = append(todo, c.levels.bases(cur)...)
	}
	return nil
}

// WithExpectedLevel configures the encryption level namespace ns is known
// to have: "at-rest", "sealed" or "e2e" (§7.1, Levels). The client holds
// it from its first request on, so a server that claims a lower one is
// ErrLevelLowered, and a document's 200 that isn't application/jose is
// refused with "sealed" or "e2e" (at "e2e" but the keyring's). It holds
// for the branches of ns too, once the client has read a document of
// theirs that names ns in its base chain. The highest of several counts,
// and it is shared with the client's With copies. A level this client
// doesn't know is held as "e2e".
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
// it was configured with or has learnt for ns or for a base in its chain
// of local bases, as far as the documents it has read name them, "" for
// none.
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
// encryption.level. A document in the clear names its base too, which is
// taken first, and from a document that is then refused as well: the
// level it claims is judged against what is held for that base, and a
// link only raises what is held. A sealed document's base is learnt where
// it is opened (NSDoc).
func (c *Client) learnDocLevel(ns string, r *response) (string, error) {
	c.levels.markRead(ns)
	lv := "sealed"
	if !isJOSE(r) {
		doc := r.obj()
		c.levels.learnBase(ns, doc)
		enc, _ := doc["encryption"].(map[string]any)
		lv, _ = enc["level"].(string)
	}
	return c.levels.learn(ns, lv)
}

// refusePlain is the error for r, a 200 for a document of ns/name, where
// the client holds sealed or e2e for ns, as its own level or a base's, and
// r isn't a JWE: a sealed namespace serves every document as one, and an
// end-to-end one every document but its keyring (§7.1; v0.86 scenario 94
// for sealed).
//
// A client that holds any level and has read no namespace document of ns
// doesn't know whether ns is a branch of a namespace it holds a level
// for. So before the first such 200 is trusted it reads ns's current
// document, and those of the local bases it names, once each per client
// (learnChain): scenario 94's client "has learnt no level for Z". A
// client that holds no level asks for nothing.
func (c *Client) refusePlain(ctx context.Context, ns, name string, r *response) error {
	if isJOSE(r) {
		return nil
	}
	if err := c.learnChain(ctx, ns); err != nil {
		return fmt.Errorf("client: %s/%s: the server answered 200 %s, and its namespace's level could not be confirmed: %w", ns, name, r.header.Get("Content-Type"), err)
	}
	held := c.levels.held(ns)
	if hr, _ := levelRank(held); hr < 2 || held == "e2e" && name == KeyringName {
		return nil
	}
	return fmt.Errorf("client: %s/%s: the server answered 200 %s in a namespace this client holds as %s, not application/jose (§7.1): %w", ns, name, r.header.Get("Content-Type"), held, ErrLevelLowered)
}
