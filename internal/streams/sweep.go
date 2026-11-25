package streams

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/middle-management/patchlog/internal/client"
)

// known is what the sweeper learnt of a resource at head target.
type known struct {
	target  string
	closed  bool      // a closed stream, created at created
	other   bool      // not a stream document: left alone
	created time.Time // the genesis entry's created
}

// segmentOf is SegmentName's inverse: the id of the stream a resource
// name is a segment of, and which one, 0 for a name that is no
// continuation's ({id}.{n}, n from 1, J.1).
func segmentOf(name string) (id string, n int) {
	i := strings.LastIndexByte(name, '.')
	if i <= 0 || i == len(name)-1 || name[i+1] == '0' {
		return name, 0
	}
	n, err := strconv.Atoi(name[i+1:])
	if err != nil || n < 1 || SegmentName(name[:i], n) != name {
		return name, 0
	}
	return name[:i], n
}

// state is the state file: the resources of the streams being written.
type state struct {
	NS   string   `json:"ns"`
	Open []string `json:"open"`
}

// saveStateLocked writes the names of the open streams' resources to the
// state file, if there is one. p.mu is held.
func (p *Proxy) saveStateLocked() {
	if p.opt.StateFile == "" {
		return
	}
	st := state{NS: p.opt.NS, Open: make([]string, 0, len(p.open))}
	for name := range p.open {
		st.Open = append(st.Open, name)
	}
	sort.Strings(st.Open)
	b, _ := json.Marshal(st)
	tmp := p.opt.StateFile + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		p.opt.Logf("streams: state file: %v", err)
		return
	}
	if err := os.Rename(tmp, p.opt.StateFile); err != nil {
		p.opt.Logf("streams: state file: %v", err)
	}
}

// recover closes the streams the state file lists that are still open,
// with "error": a previous run was writing them, and upstream can't be
// resumed (J.2 Restarts).
func (p *Proxy) recover(ctx context.Context) error {
	if p.opt.StateFile == "" {
		return nil
	}
	b, err := os.ReadFile(p.opt.StateFile)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(filepath.Dir(p.opt.StateFile), 0o700); err != nil {
			return fmt.Errorf("streams: state file: %w", err)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("streams: state file: %w", err)
	}
	var st state
	if err := json.Unmarshal(b, &st); err != nil {
		return fmt.Errorf("streams: state file %s: %w", p.opt.StateFile, err)
	}
	if st.NS != "" && st.NS != p.opt.NS {
		return fmt.Errorf("streams: state file %s is of namespace %s, not %s", p.opt.StateFile, st.NS, p.opt.NS)
	}
	left := 0
	for _, name := range st.Open {
		if !client.ValidResourceName(name) {
			continue
		}
		closed, err := p.closeOpen(ctx, name, "", &Closed{Reason: ReasonError, Error: "the proxy restarted while the stream was open"})
		switch {
		case err != nil:
			// The idle sweep closes it later, with "timeout".
			left++
			p.opt.Logf("streams: closing %s, open when the proxy last stopped: %v", name, err)
		case closed:
			p.opt.Logf("streams: closed %s, open when the proxy last stopped", name)
		}
	}
	if left == 0 {
		p.mu.Lock()
		p.saveStateLocked()
		p.mu.Unlock()
	}
	return nil
}

// closeOpen sets closed on resource name unless it is closed already,
// removed, or not a stream; it reports whether it did. head "" reads the
// current head; a head given is the only one closed on.
func (p *Proxy) closeOpen(ctx context.Context, name, head string, c *Closed) (bool, error) {
	for try := 0; ; try++ {
		at := head
		if at == "" {
			h, err := p.c.Head(ctx, p.opt.NS, name)
			if err != nil {
				return false, err
			}
			if h.State != client.Live {
				return false, nil
			}
			at = h.ID
		}
		d, err := p.c.Doc(ctx, p.opt.NS, name, at)
		if err != nil {
			if client.IsGone(err) || client.IsNotFound(err) {
				return false, nil
			}
			return false, err
		}
		sd, err := ParseDoc(d.Value)
		if err != nil || sd.Closed != nil {
			return false, nil
		}
		_, err = p.c.Append(ctx, p.opt.NS, name, at, p.closeOps(c))
		switch {
		case err == nil:
			return true, nil
		case client.IsStale(err) && head == "" && try < 5:
			// It moved: look again, never resend blindly.
			continue
		case client.IsStale(err), client.IsGone(err):
			return false, nil
		}
		return false, err
	}
}

// Sweep goes through the namespace once: an open stream no proxy has
// appended to for IdleTimeout is closed with "timeout" (J.2 Restarts), and
// a closed stream whose read grants have expired is removed with its
// continuations (J.4 Expiry, v0.85). Its grants all end TTL after the
// stream's creation, its first resource's, whenever a continuation was
// created; and a stream is closed once the last resource it continued in
// is, not when its first filled up ("size" with next). So no resource of
// a stream still being carried is removed, and none outlives the others.
// Streams this proxy is writing are left alone.
func (p *Proxy) Sweep(ctx context.Context) error {
	h, err := p.c.NSHead(ctx, p.opt.NS)
	if err != nil {
		return err
	}
	items, _, err := p.c.Unfiltered().Heads(ctx, p.opt.NS, h.ID)
	if err != nil {
		return err
	}
	now := p.opt.Now()
	settle := min(p.opt.IdleTimeout, p.opt.TTL)
	seen := make(map[string]bool, len(items))
	// What this sweep knows of each resource: absent for one that is open,
	// being written, too young to judge or unreadable for now.
	settled := make(map[string]known, len(items))
	for _, it := range items {
		if it.Kind != "head" {
			continue
		}
		name := it.Resource
		seen[name] = true
		p.mu.Lock()
		owned := p.open[name] != nil
		k, have := p.known[name]
		p.mu.Unlock()
		if owned {
			continue
		}
		if !have || k.target != it.Target {
			last, _ := time.Parse(time.RFC3339, it.Created)
			if !last.IsZero() && now.Sub(last) < settle {
				// Written a moment ago: a stream being carried, by this
				// proxy or another, or one too young for either rule.
				continue
			}
			d, err := p.c.Doc(ctx, p.opt.NS, name, it.Target)
			if err != nil {
				if !client.IsGone(err) && !client.IsNotFound(err) {
					p.opt.Logf("streams: sweep: reading %s: %v", name, err)
				}
				continue
			}
			if last.IsZero() {
				last = d.Modified
			}
			k = known{target: it.Target}
			sd, err := ParseDoc(d.Value)
			switch {
			case err != nil:
				k.other = true
			case sd.Closed == nil:
				if now.Sub(last) < p.opt.IdleTimeout {
					continue
				}
				closed, err := p.closeOpen(ctx, name, it.Target, &Closed{Reason: ReasonTimeout, Error: "no append for " + p.opt.IdleTimeout.String()})
				if err != nil {
					p.opt.Logf("streams: sweep: closing %s: %v", name, err)
				} else if closed {
					p.opt.Logf("streams: sweep: closed %s with timeout", name)
				}
				// Its head moved either way: the next sweep reads it again.
				continue
			default:
				k.closed = true
				if k.created, _, err = p.createdAt(ctx, name, it.Target); err != nil {
					p.opt.Logf("streams: sweep: reading the log of %s: %v", name, err)
					continue
				}
			}
			p.mu.Lock()
			p.known[name] = k
			p.mu.Unlock()
		}
		settled[name] = k
	}
	// A stream's resources go together (J.4): the first, and the
	// continuations of it that are there.
	groups := map[string][]string{}
	for name := range seen {
		id, n := segmentOf(name)
		if n > 0 && !seen[id] {
			// A continuation whose first resource is gone (a sweep that
			// was cut short, or a removal by hand): judged alone, by its
			// own creation.
			id = name
		}
		groups[id] = append(groups[id], name)
	}
	for id, names := range groups {
		// Closed, all of them: a resource that names a next which isn't
		// there is as closed as the stream gets, its continuation gone.
		done := true
		for _, name := range names {
			if k, ok := settled[name]; !ok || !k.closed {
				done = false
				break
			}
		}
		if !done || now.Before(settled[id].created.Add(p.opt.TTL)) {
			continue
		}
		// The continuations first, the last one first, so that a sweep
		// cut short leaves the first resource to find the rest by.
		sort.Slice(names, func(i, j int) bool {
			_, a := segmentOf(names[i])
			_, b := segmentOf(names[j])
			return names[j] == id || names[i] != id && a > b
		})
		for _, name := range names {
			_, err := p.c.Purge(ctx, p.opt.NS, name, settled[name].target, false)
			switch {
			case err == nil:
				p.opt.Logf("streams: sweep: purged %s: the read grants of stream %s expired", name, id)
			case client.IsStale(err), client.IsGone(err):
			default:
				p.opt.Logf("streams: sweep: purging %s: %v", name, err)
				continue
			}
			p.mu.Lock()
			delete(p.known, name)
			p.mu.Unlock()
		}
	}
	p.mu.Lock()
	for name := range p.known {
		if !seen[name] {
			delete(p.known, name)
		}
	}
	p.mu.Unlock()
	return ctx.Err()
}
