package index

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/derived"
	"github.com/middle-management/patchlog/internal/grant"
	"github.com/middle-management/patchlog/internal/grantcheck"
	"github.com/middle-management/patchlog/internal/lru"
)

// Namespaces §7.9 covers (§A.4 Private namespaces).
//
// A followed namespace is covered, as the origin decides it, from its
// namespace document alone (§7.9 Where), whether or not the origin
// implements filtered reads, and only while the core's authentication is
// on (authOff): neither a branch, public nor e2e (sealed ones since v0.89).
//
// A partial reader of a covered namespace (one whose grant allows read
// there without a namespace-wide edge grant, §C.5.2) reads it filtered by
// visibility: a resource is visible where its grant's blocks, key scope
// and roles allow reading it. Its marker is reads:{ns}:g:{view}, view being
// the origin's (grantcheck.FilteredSubjects: scope:{digest} of
// grantcheck.ReadsScope's digest with its key, and grantcheck.KeySubject
// of its key), and its answers are at the index's checkpoint of {ns},
// which they list as namespaces (fcp.ids).

// fcp is a covered namespace's checkpoint (§A.4): at is the index's
// checkpoint of ns, and ids lists it, {ns: at}. It is immutable.
type fcp struct {
	ns  string
	at  string
	ids map[string]string
}

// errNotReached is a namespace the index hasn't reached yet whose
// coverage can't be told until it has (503 behind, as any query of it);
// errPurgedNS one purged, whose queries are 410 (§8.5) whatever the
// reader's marker.
var (
	errNotReached = errors.New("the index has not reached the namespace yet")
	errPurgedNS   = errors.New("the namespace is purged")
)

// errGrantLacks is a namespace the index's own grant (Options.Client)
// can't read, 401 or 403, that it reads only to tell whether §7.9
// covers a namespace it follows: its state at a checkpoint. Its coverage
// can't be told, so a partial reader is refused (502) rather than
// answered as by an uncovered namespace's rules. Its Error names the
// namespace, for the operator's log; answers don't.
type errGrantLacks struct {
	ns  string
	err error
}

func (e *errGrantLacks) Error() string {
	return "the index's grant cannot read " + e.ns + ", which tells whether §7.9 covers a namespace the index follows, or what visibility reads there (widen Options.Client's grant to it): " + e.err.Error()
}

func (e *errGrantLacks) Unwrap() error { return e.err }

// msgGrantLacks answers errGrantLacks.
const msgGrantLacks = "the index's grant cannot read a namespace that decides how this one is read (§7.9): see the index's log"

// lacksRead is err, an upstream read of ns, as errGrantLacks where it is
// 401 or 403.
func lacksRead(ns string, err error) error {
	if ae, ok := client.AsAPIError(err); ok && (ae.Status == 401 || ae.Status == 403) {
		return &errGrantLacks{ns: ns, err: err}
	}
	return err
}

// fstate is what the index keeps to compute checkpoints: caches only, of
// state that never changes once read (namespace documents at an ns_id,
// checkpoints).
type fstate struct {
	mu   sync.Mutex
	docs lru.Cache[string, map[string]any] // ns \0 ns_id → namespace document
	cps  lru.Cache[string, *fcp]           // ns \0 at → checkpoint, for URLs at older ats
}

const (
	fsDocsMax = 4096
	fsCPsMax  = 256
)

func (st *fstate) init() {
	st.docs.MaxEntries, st.cps.MaxEntries = fsDocsMax, fsCPsMax
}

// seedDoc keeps cfg's document as its namespace's at the ns_id the grant
// checker read it at, so docAt needn't read it again.
func (ix *Index) seedDoc(cfg *grantcheck.Config) {
	if cfg.Head == "" || cfg.Doc == nil {
		return
	}
	ix.fs.mu.Lock()
	if _, ok := ix.fs.docs.Get(cfg.NS + "\x00" + cfg.Head); !ok {
		ix.fs.docs.Put(cfg.NS+"\x00"+cfg.Head, cfg.Doc, 1)
	}
	ix.fs.mu.Unlock()
}

// docAt is ns's namespace document in force at ns_id id (immutable).
func (ix *Index) docAt(ctx context.Context, ns, id string) (map[string]any, error) {
	k := ns + "\x00" + id
	ix.fs.mu.Lock()
	d, ok := ix.fs.docs.Get(k)
	ix.fs.mu.Unlock()
	if ok {
		return d, nil
	}
	doc, err := ix.c.NSDoc(ctx, ns, id)
	if err != nil {
		return nil, lacksRead(ns, fmt.Errorf("the document of %s at %s: %w", ns, id, err))
	}
	if doc.Value == nil {
		doc.Value = map[string]any{}
	}
	ix.fs.mu.Lock()
	ix.fs.docs.Put(k, doc.Value, 1)
	ix.fs.mu.Unlock()
	return doc.Value, nil
}

// fsOpen reports whether a namespace with document doc can be covered:
// not public, not e2e (§7.9 Where; sealed ones since v0.89).
func fsOpen(doc map[string]any) bool {
	read, _ := doc["read"].(string)
	return read != "public" && derived.InfoOf(doc).Level != derived.LevelE2E
}

// coverage is ns's checkpoint at z, the index's checkpoint of it (§7.9
// Where), nil if it isn't covered, as nothing is while the core's
// authentication is off.
func (ix *Index) coverage(ctx context.Context, ns, z string) (*fcp, error) {
	if cfg, err := ix.checker.Config(ctx, ns); err == nil {
		ix.seedDoc(cfg) // read by the read check already, as a rule
	}
	doc, err := ix.docAt(ctx, ns, z)
	if err != nil {
		return nil, err
	}
	if !coverable(doc) {
		return nil, nil
	}
	// Nothing is covered while the core's authentication is off (§7.9
	// Where: "only while authentication is on (§1)").
	if off, err := ix.authOff(ctx); err != nil {
		return nil, err
	} else if off {
		return nil, nil
	}
	return &fcp{ns: ns, at: z, ids: map[string]string{ns: z}}, nil
}

// coverable reports whether a namespace with document doc is covered
// while authentication is on: neither a branch (§7.6), public nor
// end-to-end (§7.9 Where).
func coverable(doc map[string]any) bool {
	_, branch := doc["base"]
	return fsOpen(doc) && !branch
}

// checkpoint is ns's checkpoint with ns at z, the index's checkpoint of
// it, nil if ns isn't covered (§7.9 URLs, §A.4). It keeps the result
// by at.
func (ix *Index) checkpoint(ctx context.Context, ns, z string) (*fcp, error) {
	cp, err := ix.coverage(ctx, ns, z)
	if err != nil || cp == nil {
		return nil, err
	}
	ix.fs.mu.Lock()
	ix.fs.cps.Put(cp.ns+"\x00"+cp.at, cp, 1)
	ix.fs.mu.Unlock()
	return cp, nil
}

// keptCP is the checkpoint at of ns computed earlier, nil if none is
// held: a reader's view at an older at is computed there (§7.9: a
// grant reads at its own view as of the URL's at).
func (ix *Index) keptCP(ns, at string) *fcp {
	ix.fs.mu.Lock()
	defer ix.fs.mu.Unlock()
	if cp, ok := ix.fs.cps.Get(ns + "\x00" + at); ok {
		return cp
	}
	return nil
}

// fview is one view's reading of a covered namespace at a checkpoint
// (§7.9 Visible): its read filter decides, per revision (revAllow).
type fview struct {
	cp       *fcp
	vid      string // the §7.9 view of subjects
	subjects []string
	filter   *grantcheck.ReadFilter
	visible  allowFunc
}

func (ix *Index) newFview(cp *fcp, subjects []string, filter *grantcheck.ReadFilter) *fview {
	return &fview{cp: cp, vid: grantcheck.ViewID(subjects), subjects: subjects, filter: filter, visible: ix.revAllow(cp.ns, filter)}
}

// grantFview is a partial reader's view at cp (§7.9 view): its subjects
// are grantcheck.FilteredSubjects of its ReadsScope digest and key, as
// the origin's; its filter the grant's (grantcheck.FilterOf). A grant
// whose key-scope or block rules refer to /now, or whose roles all do,
// can't read this way: 403 (§C.2 item 5).
func (ix *Index) grantFview(cp *fcp, v *grant.Verified, steps int) (*fview, error) {
	digest, ok := grantcheck.ReadsScope(v)
	if !ok {
		return nil, &grant.AuthError{Status: 403, Msg: "a rule limiting the grant's reads refers to /now"}
	}
	pub, _ := v.Key.Raw["pub"].(string)
	f := grantcheck.FilterOf(v)
	f.Steps = steps
	return ix.newFview(cp, grantcheck.ViewSubjects(digest, v.Key.Kid, pub, true), f), nil
}

// errRulesChanged refuses a cookie for a marker reads:{ns}:g:{view} at a
// checkpoint it doesn't stand for (§7.9 view): the reader exchanges its
// grant again; errUncovered one for a namespace no longer covered.
var (
	errRulesChanged = &grant.AuthError{Status: 403, Msg: "the rules this subject set was issued under have changed: exchange the grant again (§7.9)"}
	errUncovered    = &grant.AuthError{Status: 403, Msg: "the namespace is no longer read filtered: exchange the grant again (§7.9)"}
)

// storedFview is the view of the cookie for marker m, reads:{ns}:g:{view},
// that expires at exp, at cp, judged from what the exchanges recorded
// alone (rec, viewKeysAt), never from a grant the request doesn't carry:
// 403 where, for any key that cookie came from (viewKeysAt: those of one
// exchange with several grants, each of which must hold), its whole entry or
// one of its roles' whole definitions in ns's document as of cp differs
// in any member from what the exchange recorded (entryHolds; §7.9 view,
// v0.82), the scope digest of its kid's scope rules and
// its roles' definitions, read from ns's document as of cp (a branch's
// keys follow its base, §C.4), with rec's block rules and principal,
// differs from the one rec's subjects carry (a kid or role gone, or no
// longer listing read, counts as differing), or the key with its kid no
// longer has the pub it had (§7.9 view: a key "no longer accepted" as
// §C.4 judges a base's keys, "only while the base has it with the same
// pub"; a record without one, from before migration 006, never does),
// or where m has no such key recorded (from before migration 011);
// otherwise visibility from its filter. Readers with the same subjects
// and rules share m, but a cookie only with exchanges through the same
// keys with the same entries (recordCookies): never a cookie read under
// a key no longer accepted, nor one vouched for again by an exchange
// that isn't its own.
func (ix *Index) storedFview(ctx context.Context, cp *fcp, m string, rec *markerRec, exp int64) (*fview, error) {
	recorded, err := ix.viewKeysAt(ctx, m, exp)
	if err != nil {
		return nil, err
	}
	if len(recorded) == 0 {
		return nil, errRulesChanged
	}
	doc, err := ix.docAt(ctx, cp.ns, cp.at)
	if err != nil {
		return nil, err
	}
	cfg, err := grantcheck.ParseConfig(cp.ns, "", doc)
	if err != nil {
		return nil, errRulesChanged
	}
	for _, k := range recorded {
		// The key's whole entry and its roles' whole definitions, as
		// the exchange recorded them (entryHolds, v0.82).
		key, ok, err := ix.entryHolds(ctx, cfg, k)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, errRulesChanged
		}
		// §A.4's marker digest, as grantFview has it. A marker recorded
		// with the rules' digest alone (before this release) never holds:
		// its cookies are 403 until the reader exchanges again.
		holds := func(d string) bool {
			return slices.Contains(rec.subjects, grantcheck.ScopePrefix+scopeKeyDigest(d, k.kid, k.pub))
		}
		if !viewKeyHolds(cfg, []grant.Key{key}, rec.f, k, holds) {
			return nil, errRulesChanged
		}
	}
	return ix.newFview(cp, rec.subjects, rec.f), nil
}

// viewKeyHolds reports whether k, a key a cookie of a marker came from, is
// still accepted with the pub it had, among keys (cfg's, or for a branch
// its effective ones, §C.4), and lists read, and whether its scope rules
// and its roles' definitions in cfg, each role still listing read, with
// f's block rules and principal, still digest to what the marker stands
// for (holds: for a g: marker, the scope subject its subjects carry,
// storedFview; for a scope marker, the marker's own digest,
// scopeKeysHold). §7.9 view ends a view cookie so, and §A.4 a scope cookie
// "where a marker's key, rules or roles would end a view cookie".
func viewKeyHolds(cfg *grantcheck.Config, keys []grant.Key, f *grantcheck.ReadFilter, k viewKey, holds func(digest string) bool) bool {
	i := slices.IndexFunc(keys, func(key grant.Key) bool { return key.Kid == k.kid })
	if i < 0 || !keys[i].Lists("read") || k.pub == "" || keyPub(keys[i]) != k.pub {
		return false
	}
	in := grantcheck.ScopeInput{ReadScopeResource: keys[i].ReadScopeResource, KeyRules: keys[i].Rules,
		BlockRules: f.BlockRules, Roles: map[string][]any{}, Principal: f.Principal}
	for _, r := range k.roles {
		// A role that no longer lists read counts as gone, as at the
		// origin (core viewDigestHolds): a cookie never reads where its
		// grant couldn't (§2.1, §A.4).
		def, ok := cfg.Roles[r]
		if !ok || !def.Lists("read") {
			return false
		}
		in.Roles[r] = def.Rules
	}
	d, ok := grantcheck.ScopeDigest(in)
	return ok && holds(d)
}

// gMarker is the marker of a partial reader of covered ns with §7.9
// view view (§A.4).
func gMarker(ns, vid string) string { return "reads:" + ns + ":g:" + vid }

// cover computes a's view of covered namespace ns at the checkpoint with
// ns at z ("" for the index's committed one), and with a grant (not a
// cookie) sets a's marker and view to it (§A.4). It is errUncovered for a
// namespace not covered there (a grant's access is then that of an
// uncovered namespace, a cookie's 403), errNotReached before the index's
// first checkpoint of ns and errPurgedNS once ns is purged.
func (ix *Index) cover(ctx context.Context, a *access, ns, z string) error {
	if z == "" {
		id, purged, err := ix.committed(ctx, ns)
		switch {
		case err != nil:
			return err
		case purged:
			return errPurgedNS
		case id == "":
			return errNotReached
		}
		z = id
	}
	if a.cov != nil && a.cov.cp.ids[ns] == z {
		return nil
	}
	cp, err := ix.checkpoint(ctx, ns, z)
	if err != nil {
		return err
	}
	if cp == nil {
		return errUncovered
	}
	fv, err := a.derive(ctx, cp)
	if err != nil {
		return err
	}
	a.setView(ns, fv)
	return nil
}

// setView makes fv a's view; with a grant, a's marker and view are fv's.
func (a *access) setView(ns string, fv *fview) {
	a.cov, a.allow, a.filter = fv, fv.visible, fv.filter
	if !a.cookie {
		a.marker = gMarker(ns, fv.vid)
		marked(a)
	}
}

// at is a copy of a with its view at cp instead, nil if it can't be
// computed there.
func (a *access) at(ctx context.Context, ns string, cp *fcp) *access {
	fv, err := a.derive(ctx, cp)
	if err != nil {
		return nil
	}
	b := *a
	b.setView(ns, fv)
	return &b
}

// mayBeCovered reports whether ns, which the index hasn't reached, may be
// covered once it has, by its current document: then its coverage, and
// so a partial reader's marker, can't be told yet.
func (ix *Index) mayBeCovered(ctx context.Context, ns string) (bool, error) {
	cfg, err := ix.checker.Config(ctx, ns)
	if err != nil {
		return false, err
	}
	return coverable(cfg.Doc), nil
}

// authReuse bounds how long a successful read of the core's root is
// reused (§7.9 Where, v0.85: "reusing a successful read for at most a
// minute and none once a later read has failed").
const authReuse = time.Minute

// authOff reports whether the core runs with authentication disabled
// (§1), as its root says, read again once CheckerTTL, a minute at most
// (authReuse), has passed since it was last read. A read that fails
// leaves nothing to reuse: what an earlier one said is forgotten.
func (ix *Index) authOff(ctx context.Context) (bool, error) {
	a := &ix.auth
	a.mu.Lock()
	if !a.at.IsZero() && time.Since(a.at) < min(ix.opt.CheckerTTL, authReuse) {
		off := a.off
		a.mu.Unlock()
		return off, nil
	}
	a.mu.Unlock()
	off, err := ix.c.AuthDisabled(ctx)
	if err != nil {
		a.mu.Lock()
		a.at = time.Time{}
		a.mu.Unlock()
		return false, &rootErr{err}
	}
	a.mu.Lock()
	a.at, a.off = time.Now(), off
	a.mu.Unlock()
	return off, nil
}

// rootErr is a failure to read the core's root (authOff). One for now (a
// transport error, a deadline, a 5xx, 408 or 429) is 503 behind, with
// Retry-After; any other is 502 upstream (writeUpstreamErr). Neither names
// a namespace.
type rootErr struct{ err error }

func (e *rootErr) Error() string { return "the core's root: " + e.err.Error() }
func (e *rootErr) Unwrap() error { return e.err }

// transient reports whether the root couldn't be read for now.
func (e *rootErr) transient() bool {
	if ae, ok := client.AsAPIError(e.err); ok && ae.Status == http.StatusRequestTimeout {
		return true
	}
	return client.Transient(e.err)
}

// coverTags are the Cache-Tags of an answer at cp besides its hits':
// idx:{ns} (§A.4).
func coverTags(cp *fcp) []string {
	return []string{"idx:" + cp.ns}
}
