package tree

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/follow"
	"github.com/middle-management/patchlog/internal/release"
)

// Preview is a long-running release preview (§B.5, §F.9): a tree service
// following the branches a release document lists in place of their bases
// (Options.Branches), which also follows the release document's own
// namespace log (§10). When a new revision of the document lists other
// branches, such as a rebase's successors, the preview switches to them
// without a restart: it rebuilds its database from the new branches, and
// answers 503 "behind" until it has reached them. A revision that lists
// the same branches changes nothing, and one that can't be read or isn't
// a valid release document is logged and leaves the preview as it is, as
// does deleting the document.
type Preview struct {
	opt  Options // Branches is set per revision
	c    *client.Client
	ref  release.Ref // the document's live link
	from string      // the release namespace's ns_id before the first read

	mu      sync.RWMutex // guards svc and rev; requests hold it for reading
	svc     *Service
	rev     string            // the revision of the document svc previews
	aliases map[string]string // its branches
	runCtx  context.Context   // Run's context (nil before Run)
	stop    context.CancelFunc
	done    chan struct{}
}

// OpenPreview reads the release document at link (/r/{ns}/{name}, its
// head) and opens a tree service previewing it.
func OpenPreview(ctx context.Context, opt Options, link string) (*Preview, error) {
	if opt.Client == nil {
		return nil, errors.New("tree: no client")
	}
	if opt.Logf == nil {
		opt.Logf = log.Printf
	}
	ref, err := release.ParseRef(link)
	if err != nil {
		return nil, err
	}
	if ref.Rev != "" {
		return nil, fmt.Errorf("tree: a preview follows its release document: give its live link, not %s", link)
	}
	// The namespace's head before the read: entries after it are replayed,
	// so no revision is missed between reading and following.
	h, err := opt.Client.NSHead(ctx, ref.NS)
	if err != nil {
		return nil, fmt.Errorf("tree: the release namespace %s: %w", ref.NS, err)
	}
	loaded, err := release.Load(ctx, opt.Client, ref.Live())
	if err != nil {
		return nil, err
	}
	p := &Preview{opt: opt, c: opt.Client, ref: ref, from: h.ID, rev: loaded.Ref.Rev, aliases: loaded.Doc.Aliases()}
	o := opt
	o.Branches = p.aliases
	if p.svc, err = Open(ctx, o); err != nil {
		return nil, err
	}
	p.logf("tree: previewing release %s at %s: %v", ref.Live(), p.rev, p.aliases)
	return p, nil
}

func (p *Preview) logf(format string, args ...any) { p.opt.Logf(format, args...) }

// Service is the tree service previewing the current revision.
func (p *Preview) Service() *Service {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.svc
}

// Revision is the revision of the release document being previewed.
func (p *Preview) Revision() string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.rev
}

// Handler serves the current tree service's listings.
func (p *Preview) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.mu.RLock()
		defer p.mu.RUnlock()
		p.svc.serveHTTP(w, r)
	})
}

// Close closes the current tree service.
func (p *Preview) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.svc.Close()
}

// startLocked runs the current service until stopped. Called with mu held.
func (p *Preview) startLocked() {
	ctx, cancel := context.WithCancel(p.runCtx)
	done := make(chan struct{})
	p.stop, p.done = cancel, done
	svc := p.svc
	go func() {
		defer close(done)
		svc.Run(ctx)
	}()
}

// stopLocked stops the current service's followers. Called with mu held.
func (p *Preview) stopLocked() {
	if p.stop != nil {
		p.stop()
		<-p.done
		p.stop = nil
	}
}

// Run follows the branches and the release document until ctx is done.
func (p *Preview) Run(ctx context.Context) error {
	p.mu.Lock()
	p.runCtx = ctx
	p.startLocked()
	origin := p.svc.Origin()
	p.mu.Unlock()
	defer func() {
		p.mu.Lock()
		p.stopLocked()
		p.mu.Unlock()
	}()

	cps := &follow.MemoryCheckpoints{}
	cps.Save(origin, p.ref.NS, p.from)
	h := follow.HandlerFunc(func(ctx context.Context, b *follow.Batch) error {
		if err := p.apply(ctx, b); err != nil {
			return err
		}
		cps.Save(b.Origin, b.NS, b.NewCheckpoint)
		return nil
	})
	opts := []follow.Option{
		follow.WithMaxUnits(0),
		follow.WithOnError(func(n string, err error) { p.logf("tree: release %s: %v", p.ref.Live(), err) }),
	}
	opts = append(opts, p.opt.FollowOptions...)
	pause := time.Second
	for ctx.Err() == nil {
		err := follow.New(p.c, p.ref.NS, cps, h, opts...).Run(ctx)
		if ctx.Err() != nil {
			break
		}
		if errors.Is(err, follow.ErrPurged) {
			p.logf("tree: the release namespace %s was purged; previewing %s as it was", p.ref.NS, p.Revision())
			<-ctx.Done()
			break
		}
		p.logf("tree: following the release document %s stopped: %v; restarting in %s", p.ref.Live(), err, pause)
		t := time.NewTimer(pause)
		select {
		case <-ctx.Done():
			t.Stop()
		case <-t.C:
		}
		if pause < 30*time.Second {
			pause *= 2
		}
	}
	return ctx.Err()
}

// apply looks for a new revision of the release document in a batch of
// its namespace's log.
func (p *Preview) apply(ctx context.Context, b *follow.Batch) error {
	for _, ch := range b.Coalesce().Changes {
		if ch.Resource != p.ref.Name {
			continue
		}
		if ch.Kind != "head" {
			p.logf("tree: the release document %s is %sd; previewing %s as it was", p.ref.Live(), ch.Kind, p.Revision())
			continue
		}
		if err := p.switchTo(ctx, ch.Target); err != nil {
			return err
		}
	}
	return nil
}

// switchTo previews revision rev of the release document. Errors worth
// retrying (the core unreachable, the new service not opening) are
// returned, so the follower retries the batch.
func (p *Preview) switchTo(ctx context.Context, rev string) error {
	if rev == p.Revision() {
		return nil
	}
	d, err := p.c.Doc(ctx, p.ref.NS, p.ref.Name, rev)
	if err != nil && client.Retryable(err) {
		return err
	}
	var doc *release.Doc
	if err == nil {
		doc, err = release.Parse(d.Value)
	}
	if err != nil {
		p.logf("tree: the release document %s at %s: %v; previewing %s as it was", p.ref.Live(), rev, err, p.Revision())
		return nil
	}
	aliases := doc.Aliases()
	p.mu.Lock()
	defer p.mu.Unlock()
	if sameAliases(aliases, p.aliases) {
		p.rev = rev
		return nil
	}
	// Requests are held (mu) while the service is replaced: its followers
	// stop, and a new service rebuilds the database from the new branches.
	p.stopLocked()
	o := p.opt
	o.Branches, o.Rebuild = aliases, true
	svc, err := Open(ctx, o)
	if err != nil {
		p.startLocked() // keep previewing the old revision meanwhile
		return fmt.Errorf("tree: previewing %s at %s: %w", p.ref.Live(), rev, err)
	}
	if err := p.svc.Close(); err != nil {
		p.logf("tree: closing the previous preview: %v", err)
	}
	p.svc, p.rev, p.aliases = svc, rev, aliases
	p.startLocked()
	p.logf("tree: previewing release %s at %s: %v", p.ref.Live(), rev, aliases)
	return nil
}

func sameAliases(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}
