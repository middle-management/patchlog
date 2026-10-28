package dav

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/jsonv"
)

// A user's own entries are those whose grant has its sub and a kid that
// named, when written, its key, or the catalog's key there (§H.7 "Users").
// A kid is only a name, which a namespace may give to another key later
// (§C.4), so a kid is judged by the key it named at the entry: from the
// keys of the namespace documents in force, read from the namespace log's
// config writes (keyHistory), and of its local bases, whose keys a branch
// accepts (§C.4, §7.6).

// keyChange is one config write of a namespace: when it was written and
// the keys and local base of the document it left in force.
type keyChange struct {
	at   time.Time
	keys map[string]string // kid → "alg pub"
	base string            // the local base, "" for none (or a remote one)
}

// keyHistory is a namespace's config writes as a token read them: its log
// up to head, of which asOf is the latest created time known to be
// covered (a later entry may follow a config write not read yet), read at
// read by the server's clock.
type keyHistory struct {
	head, config string
	asOf         time.Time
	read         time.Time
	changes      []keyChange
}

// maxKeyHistories bounds the namespaces whose key history a token keeps.
const maxKeyHistories = 64

// keysOf reads a namespace document's keys and local base.
func keysOf(doc map[string]any) (map[string]string, string) {
	out := map[string]string{}
	arr, _ := doc["keys"].([]any)
	for _, x := range arr {
		m, _ := x.(map[string]any)
		kid, _ := m["kid"].(string)
		alg, _ := m["alg"].(string)
		pub, _ := m["pub"].(string)
		if kid != "" && pub != "" {
			out[kid] = strings.ToLower(alg) + " " + pub
		}
	}
	bref, _ := doc["base"].(map[string]any)
	base, _ := bref["ns"].(string)
	if _, remote := bref["origin"]; remote {
		base = ""
	}
	return out, base
}

// isConfig reports a config write: a config entry, or a batch whose first
// item is one (§7.5).
func isConfig(e client.NSEntry) bool {
	return e.Kind == "config" || e.Kind == "batch" && len(e.Entries) > 0 && e.Entries[0].Kind == "config"
}

// keyHistory returns ns's key history as the token reads it, covering
// every config write created at or before need: read whole the first
// time, then from where it was left whenever an entry later than what it
// covers is judged, and at least every writerTTL. ok is false where it
// can't be read (a grant without read of the namespace log, say).
func (st *reqState) keyHistory(ctx context.Context, ns string, need time.Time) (*keyHistory, bool) {
	tk, now := st.tk, st.s.opt.Now()
	tk.mu.Lock()
	h := tk.keyHist[ns]
	tk.mu.Unlock()
	if h != nil && !need.After(h.asOf) && now.Sub(h.read) < st.s.writerTTL() {
		return h, true
	}
	head, err := tk.c.NSHead(ctx, ns)
	if err != nil {
		return nil, false
	}
	nh := &keyHistory{head: head.ID, config: head.Config, read: now}
	since := ""
	if h != nil {
		nh.asOf, nh.changes, since = h.asOf, h.changes, h.head
	}
	if h == nil || head.ID != h.head {
		if h != nil && head.Config == h.config {
			// No config write since: the entries after it change no key.
			nh.asOf = maxTime(nh.asOf, need)
		} else {
			es, err := tk.c.NSLog(ctx, ns, head.ID, since)
			if err != nil {
				return nil, false
			}
			nh.changes = append([]keyChange(nil), nh.changes...)
			for _, e := range es {
				at, err := time.Parse(time.RFC3339Nano, e.Created)
				if err != nil {
					return nil, false
				}
				nh.asOf = maxTime(nh.asOf, at)
				if !isConfig(e) {
					continue
				}
				d, err := tk.c.NSDoc(ctx, ns, e.ID)
				if err != nil {
					return nil, false
				}
				keys, base := keysOf(d.Value)
				nh.changes = append(nh.changes, keyChange{at: at, keys: keys, base: base})
			}
		}
	}
	// The head read now follows every entry the user can be judging.
	nh.asOf = maxTime(nh.asOf, need)
	tk.mu.Lock()
	if tk.keyHist == nil || len(tk.keyHist) >= maxKeyHistories && tk.keyHist[ns] == nil {
		tk.keyHist = map[string]*keyHistory{}
	}
	tk.keyHist[ns] = nh
	tk.mu.Unlock()
	return nh, true
}

func maxTime(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}

// keyAt returns the key kid named in ns at time at, as "alg pub", by the
// documents in force then: a local base's for a kid it has, as the core
// takes a base's key over a branch's own of that kid (§C.4), else ns's
// own. A kid no document named is "". ok is false where it can't be told:
// a config write created at the same time changed the kid, which can't be
// ordered against the entry; read is false where a history can't be read.
func (st *reqState) keyAt(ctx context.Context, ns, kid string, at time.Time, depth int) (key string, ok, read bool) {
	if depth > maxDepth {
		return "", false, true
	}
	h, read := st.keyHistory(ctx, ns, at)
	if !read {
		return "", false, false
	}
	var cur *keyChange
	for i := range h.changes {
		c := &h.changes[i]
		if c.at.After(at) {
			break
		}
		if c.at.Equal(at) && cur != nil && cur.keys[kid] != c.keys[kid] {
			return "", false, true
		}
		cur = c
	}
	if cur == nil {
		return "", true, true
	}
	if cur.base != "" {
		k, ok, read := st.keyAt(ctx, cur.base, kid, at, depth+1)
		if !ok || k != "" {
			return k, ok, read
		}
	}
	return cur.keys[kid], true, true
}

// maxDepth bounds base chains (the deployment's branch depth is 8 by
// default, §6.6).
const maxDepth = 32

// keyThumbprint is the RFC 7638 thumbprint GET /ns/{ns}/principal names a
// key by (§7.4): of the JWK {"crv":"Ed25519","kty":"OKP","x":pub}; "" for
// a key of another algorithm.
func keyThumbprint(key string) string {
	alg, pub, _ := strings.Cut(key, " ")
	if alg != "ed25519" || pub == "" {
		return ""
	}
	sum := sha256.Sum256(jsonv.Canonical(map[string]any{"crv": "Ed25519", "kty": "OKP", "x": pub}))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// wroteAs reports whether log entry e of ns was written by the user as
// the core records its writes (§H.7 "Users"): with authentication
// disabled, under its X-Author; else under a grant with its sub and a kid
// that named, when written, its key (one GET /ns/{ns}/principal named,
// verifiedAs), or for a kid the catalog issued it a grant under
// (issuedTo), the key that kid names now, the catalog's. An entry whose
// kid named another key then, as before a namespace gave the kid to the
// user's key, is someone else's; so is one whose key can't be ordered
// against a config write of the same time. Where the token can't read
// the namespace's history (a grant limited to some resources, or a
// content namespace a catalog's grants open, §H.7), the kid is judged as
// it names the key now, as the user was told.
func (st *reqState) wroteAs(ctx context.Context, ns string, e client.LogEntry) bool {
	known, verified, key := st.p.wroteAs(ns, e)
	switch {
	case !known:
		return false
	case e.Grant == nil:
		return true // an X-Author's (authentication disabled)
	}
	at, err := time.Parse(time.RFC3339Nano, e.Created)
	if err != nil {
		return false
	}
	then, ok, read := st.keyAt(ctx, ns, e.Grant.Kid, at, 0)
	switch {
	case !read:
		return true
	case !ok || then == "":
		return false
	case verified && key != "":
		return keyThumbprint(then) == key
	}
	// The kid named the key it names now when the user was given it.
	now, ok, read := st.keyAt(ctx, ns, e.Grant.Kid, st.keyNow(ctx, ns), 0)
	return !read || ok && now == then
}

// keyNow is the latest time ns's key history covers, read now.
func (st *reqState) keyNow(ctx context.Context, ns string) time.Time {
	h, ok := st.keyHistory(ctx, ns, time.Time{})
	if !ok {
		return time.Time{}
	}
	if n := len(h.changes); n > 0 {
		return maxTime(h.asOf, h.changes[n-1].at)
	}
	return h.asOf
}
