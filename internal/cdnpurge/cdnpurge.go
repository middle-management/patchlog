// Package cdnpurge purges CDN cache tags over HTTP (§9, §8.3). It
// implements the Purger interfaces of internal/core, internal/index and
// internal/tree.
//
// A purge is a request to each configured CDN URL, by default
//
//	PURGE / HTTP/1.1
//	X-Purge-Tags: ns:demo r:demo/derby
//
// which the Varnish configuration in deploy/varnish turns into a ban on
// objects whose Cache-Tag names any of the tags.
//
// PurgeTags never blocks and never fails: tags are queued per CDN URL,
// coalesced (a tag already waiting is not queued twice), sent in batches of
// bounded count and header length, and retried with exponential backoff.
// A CDN that stays down loses the tags it couldn't take, which is logged:
// the write that caused the purge has committed long before, and holding
// it up would not make the CDN come back. The queue is bounded; tags beyond
// it are dropped and logged too. Close flushes what is queued, within a
// deadline.
package cdnpurge

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/middle-management/patchlog/internal/telemetry"
)

// Options configure a Purger. Zero values take the defaults.
type Options struct {
	// URLs are the CDN endpoints purges go to (at least one).
	URLs []string
	// Method is the request method (default PURGE).
	Method string
	// Header carries the space-separated tags (default X-Purge-Tags).
	Header string
	// MaxTags is the most tags per request (default 64).
	MaxTags int
	// MaxHeaderBytes bounds the header value per request (default 2048,
	// well below Varnish's 8 KiB http_req_hdr_len). A single longer tag
	// is still sent, alone.
	MaxHeaderBytes int
	// QueueSize bounds the tags waiting per URL (default 100000). Tags
	// beyond it are dropped and logged.
	QueueSize int
	// Timeout bounds one request (default 5s).
	Timeout time.Duration
	// Attempts is how often a batch is tried before it is dropped
	// (default 6).
	Attempts int
	// Backoff is the first retry delay, doubled per attempt up to
	// MaxBackoff (defaults 250ms and 10s).
	Backoff, MaxBackoff time.Duration
	// Client sends the requests (default: a client with Timeout).
	Client *http.Client
	// Logf logs sent batches and failures (default log.Printf).
	Logf func(format string, args ...any)
}

// Purger sends cache-tag purges to one or more CDNs.
type Purger struct {
	opt     Options
	targets []*target
	wg      sync.WaitGroup

	closeOnce, deadlineOnce sync.Once
	closing                 chan struct{} // closed by Close: drain, then stop
	deadline                chan struct{} // closed when Close's context ends: give up
}

// target is one CDN URL with its own queue, so a CDN that is down doesn't
// hold up the others.
type target struct {
	url  string
	wake chan struct{}

	mu      sync.Mutex
	pending []string
	queued  map[string]bool
	dropped int // tags dropped since last logged
}

// New returns a Purger for opt.URLs and starts its senders.
func New(opt Options) (*Purger, error) {
	if len(opt.URLs) == 0 {
		return nil, errors.New("cdnpurge: no URL")
	}
	for _, u := range opt.URLs {
		pu, err := url.Parse(u)
		if err != nil || (pu.Scheme != "http" && pu.Scheme != "https") || pu.Host == "" {
			return nil, fmt.Errorf("cdnpurge: bad URL %q", u)
		}
	}
	if opt.Method == "" {
		opt.Method = "PURGE"
	}
	if opt.Header == "" {
		opt.Header = "X-Purge-Tags"
	}
	if opt.MaxTags <= 0 {
		opt.MaxTags = 64
	}
	if opt.MaxHeaderBytes <= 0 {
		opt.MaxHeaderBytes = 2048
	}
	if opt.QueueSize <= 0 {
		opt.QueueSize = 100000
	}
	if opt.Timeout <= 0 {
		opt.Timeout = 5 * time.Second
	}
	if opt.Attempts <= 0 {
		opt.Attempts = 6
	}
	if opt.Backoff <= 0 {
		opt.Backoff = 250 * time.Millisecond
	}
	if opt.MaxBackoff <= 0 {
		opt.MaxBackoff = 10 * time.Second
	}
	if opt.Client == nil {
		opt.Client = &http.Client{Timeout: opt.Timeout, Transport: telemetry.Transport(nil)}
	}
	if opt.Logf == nil {
		opt.Logf = log.Printf
	}
	p := &Purger{opt: opt, closing: make(chan struct{}), deadline: make(chan struct{})}
	for _, u := range opt.URLs {
		t := &target{url: u, wake: make(chan struct{}, 1), queued: map[string]bool{}}
		p.targets = append(p.targets, t)
		p.wg.Add(1)
		go p.run(t)
	}
	return p, nil
}

// PurgeTags queues tags for every CDN and returns at once.
func (p *Purger) PurgeTags(tags []string) {
	select {
	case <-p.closing:
		p.opt.Logf("cdn purge: closed, dropping %v", tags)
		return
	default:
	}
	for _, t := range p.targets {
		t.add(tags, p.opt.QueueSize)
	}
}

func (t *target) add(tags []string, max int) {
	t.mu.Lock()
	for _, tag := range tags {
		tag = strings.TrimSpace(tag)
		if tag == "" || t.queued[tag] {
			continue
		}
		if len(t.pending) >= max {
			t.dropped++
			continue
		}
		t.queued[tag] = true
		t.pending = append(t.pending, tag)
	}
	t.mu.Unlock()
	select {
	case t.wake <- struct{}{}:
	default:
	}
}

// take removes the next batch from the queue, and reports tags dropped
// for a full queue since the last call.
func (t *target) take(maxTags, maxBytes int) (batch []string, dropped int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	n := 0
	for len(batch) < maxTags && len(t.pending) > 0 {
		tag := t.pending[0]
		if len(batch) > 0 && n+1+len(tag) > maxBytes {
			break
		}
		if len(batch) > 0 {
			n++
		}
		n += len(tag)
		batch = append(batch, tag)
		t.pending = t.pending[1:]
		delete(t.queued, tag)
	}
	if len(t.pending) == 0 {
		t.pending = nil // let the backing array go
	}
	dropped, t.dropped = t.dropped, 0
	return batch, dropped
}

func (p *Purger) run(t *target) {
	defer p.wg.Done()
	for {
		batch, dropped := t.take(p.opt.MaxTags, p.opt.MaxHeaderBytes)
		if dropped > 0 {
			p.opt.Logf("cdn purge %s: queue full, dropped %d tags", t.url, dropped)
		}
		if len(batch) == 0 {
			select {
			case <-t.wake:
				continue
			case <-p.closing:
				// Tags queued between take and here are still sent.
				if t.empty() {
					return
				}
				continue
			}
		}
		if !p.deliver(t, batch) {
			select {
			case <-p.deadline:
				// Shutting down past the deadline: drop the rest.
				rest := t.drain()
				p.opt.Logf("cdn purge %s: shutdown deadline, dropped %d tags", t.url, len(batch)+len(rest))
				return
			default:
			}
		}
	}
}

func (t *target) empty() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.pending) == 0
}

func (t *target) drain() []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	rest := t.pending
	t.pending, t.queued = nil, map[string]bool{}
	return rest
}

// deliver sends one batch, retrying with backoff. It reports whether the
// CDN took it; a batch it gives up on is logged and dropped.
func (p *Purger) deliver(t *target, batch []string) bool {
	delay := p.opt.Backoff
	var err error
	for attempt := 1; attempt <= p.opt.Attempts; attempt++ {
		var retry bool
		retry, err = p.send(t.url, batch)
		if err == nil {
			p.opt.Logf("cdn purge %v -> %s", batch, t.url)
			return true
		}
		if !retry || attempt == p.opt.Attempts {
			break
		}
		timer := time.NewTimer(delay)
		select {
		case <-timer.C:
		case <-p.deadline:
			timer.Stop()
			p.opt.Logf("cdn purge %v -> %s: %v (giving up at shutdown)", batch, t.url, err)
			return false
		}
		if delay *= 2; delay > p.opt.MaxBackoff {
			delay = p.opt.MaxBackoff
		}
	}
	p.opt.Logf("cdn purge %v -> %s failed: %v (dropped)", batch, t.url, err)
	return false
}

// send makes one request. retry says whether a failure may be transient.
func (p *Purger) send(u string, batch []string) (retry bool, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), p.opt.Timeout)
	defer cancel()
	go func() {
		// A request in flight when Close's deadline passes is abandoned.
		select {
		case <-p.deadline:
			cancel()
		case <-ctx.Done():
		}
	}()
	req, err := http.NewRequestWithContext(ctx, p.opt.Method, u, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set(p.opt.Header, strings.Join(batch, " "))
	resp, err := p.opt.Client.Do(req)
	if err != nil {
		return true, err
	}
	resp.Body.Close()
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return false, nil
	case resp.StatusCode == http.StatusRequestTimeout || resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500:
		return true, fmt.Errorf("status %s", resp.Status)
	default:
		// 403 (not in the CDN's purge ACL), 400, 405: retrying won't help.
		return false, fmt.Errorf("status %s", resp.Status)
	}
}

// Close stops accepting tags and sends what is queued, retrying as usual,
// until ctx ends; whatever is left then is dropped and logged. It returns
// ctx's error if it had to give up.
func (p *Purger) Close(ctx context.Context) error {
	p.closeOnce.Do(func() { close(p.closing) })
	done := make(chan struct{})
	go func() { p.wg.Wait(); close(done) }()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		p.deadlineOnce.Do(func() { close(p.deadline) })
		<-done
		return ctx.Err()
	}
}
