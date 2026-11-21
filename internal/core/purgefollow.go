package core

// Purges follow imports (§G.1, FED-26).
//
// A namespace imported from another deployment records that deployment's
// origin in its import batches' source (§7.5, §G.4.4 step 7): a batch
// whose source names a bundle and an origin. Any writer can assert a
// source (§7.5), so only import batches by a principal the operator names
// as that origin's importer count, under a grant that may purge the names
// they write (§G.1, v0.88). Where the operator trusts the origin
// (FollowPurgesOptions.Origins, with its Importers), the deployment
// follows the origin's namespace log from the first such batch's
// source.at and applies each purge there of a name such a batch wrote, and
// each purge-ns to every such name, as §8.3 does locally: its own chains
// for the name and its branches, with their cache tags. The
// upstream namespace's chains (§G.4.4) are reached the same way, as the
// import's batches into it carry the same source. Nothing here is the
// importer's doing: the server writes these entries itself, without grant
// or via (§7.4), as FollowAuthor.
//
// State, per namespace imported into, origin and source namespace there (a
// follow):
//
//   - purge_follows: the follow and its cursor, the origin's ns_id up to
//     which every purge is applied. A follow starts at the source.at of the
//     first import batch that records it (recordImport), whether or not
//     the origin is trusted then, so trusting it later follows from there.
//   - purge_follow_names: the names imported, those the batch itself wrote
//     (never source.ids' keys alone, which a writer may fill with names of
//     resources the batch didn't touch, VEC-87) under a grant that may
//     purge them, each with the principal that wrote it, the importer,
//     and the source.at that brought it first. Only those an importer the
//     operator names for the origin wrote are followed. A name an import brings after the follow
//     started is pending: the cursor may have passed a purge of it already
//     (an older bundle imported late), so the origin's log is read once more
//     from that source.at for it (FollowPurges). Purges are idempotent: a
//     purged name is skipped.
//   - purge_follow_waiting: purges §6.1 refuses as in_use (the last copy of
//     a schema revision referenced from elsewhere). Each waits for an
//     operator, who removes the references or purges the name with
//     ?force=1, and is tried again at every follow; the purges after it
//     don't wait for it.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/telemetry"
	"github.com/middle-management/patchlog/internal/verify"
)

// FollowAuthor is the author recorded on the purges the server follows from
// an origin (§G.1); they carry no grant (§7.4).
const FollowAuthor = "system:purge-follow"

// FollowPurgesOptions configure following the purges of trusted origins
// after imports (§G.1).
type FollowPurgesOptions struct {
	// Origins are the origins the operator trusts, as source.origin records
	// them (canonical, sig.CanonicalOrigin), with how each is reached. An
	// origin not listed purges nothing here (VEC-87).
	Origins map[string]PurgeOrigin
	// Interval is how often the leader follows them. Zero means five
	// minutes; negative disables the loop (FollowPurges still runs).
	Interval time.Duration
	// Timeout bounds one origin's reads within a follow. Zero means one
	// minute.
	Timeout time.Duration
}

// PurgeOrigin is how a trusted origin is reached, and who imports from it.
type PurgeOrigin struct {
	// Importers are the principals (root sub, as a namespace entry's
	// author records it) that import from the origin (§G.1): only names
	// their import batches wrote are followed. None follows nothing.
	Importers []string
	// BaseURL is where the origin answers; empty means the origin itself.
	BaseURL string
	// Bearer is a grant read with the origin's namespace logs (§C.5).
	Bearer string
	// HTTPClient, if set, makes the requests (tests); no redirect is
	// followed either way.
	HTTPClient *http.Client
}

// followKey names a follow: the namespace imported into, the origin and the
// source namespace there.
type followKey struct {
	ns     int64
	nsName string
	origin string
	srcNS  string
}

func (k followKey) String() string {
	return fmt.Sprintf("%s from %s/ns/%s", k.nsName, k.origin, k.srcNS)
}

// recordImport records an import batch's source (§G.4.4), as the batch
// commits: a source with a bundle and another deployment's origin starts a
// follow of n from source.at, if none exists, and adds the names the batch
// wrote whose purge a's grant allows (§C.2 step 1), with a's principal as
// their importer. A batch whose grant may purge none of them records
// nothing (§G.1, v0.88). Whether the origin is trusted, and the principal
// its importer, is decided only when following.
func (t *tx) recordImport(n *nsRow, a *actor, src any, st []*itemState) {
	m, ok := src.(map[string]any)
	if !ok {
		return
	}
	origin, _ := m["origin"].(string)
	srcNS, _ := m["ns"].(string)
	at, _ := m["at"].(string)
	if _, imported := m["bundle"]; !imported || origin == "" || len(st) == 0 {
		return
	}
	// The at goes into the origin's URLs: only an id is kept (checkSource
	// checked ns already).
	if _, err := ids.Parse(at); err != nil {
		return
	}
	st = t.mayPurgeAll(a, st)
	if len(st) == 0 {
		return
	}
	importer := a.id()
	_, err := t.Exec(`INSERT INTO purge_follows (ns, origin, src_ns, upto) VALUES (?,?,?,?) ON CONFLICT DO NOTHING`, n.id, origin, srcNS, at)
	t.must(err)
	var cursor string
	t.must(t.QueryRow(`SELECT upto FROM purge_follows WHERE ns = ? AND origin = ? AND src_ns = ?`, n.id, origin, srcNS).Scan(&cursor))
	pending := 0
	if cursor != at {
		pending = 1
	}
	// A statement per hundred names, not per name: the batch holds its
	// namespace's lock.
	for i := 0; i < len(st); i += 100 {
		chunk := st[i:min(i+100, len(st))]
		q := `INSERT INTO purge_follow_names (ns, origin, src_ns, name, importer, from_at, pending) VALUES `
		args := make([]any, 0, 7*len(chunk))
		for j, s := range chunk {
			if j > 0 {
				q += `,`
			}
			q += `(?,?,?,?,?,?,?)`
			args = append(args, n.id, origin, srcNS, s.Resource, importer, at, pending)
		}
		_, err := t.Exec(q+` ON CONFLICT DO NOTHING`, args...)
		t.must(err)
	}
}

// mayPurgeAll is the items of st whose resource a's grant may purge, as
// step 1 of a purge judges it (authorize, §C.2), each check with a budget
// of its own; one that runs out may not.
func (t *tx) mayPurgeAll(a *actor, st []*itemState) []*itemState {
	prev := t.meter
	t.meter = nil
	defer func() { t.meter = prev }()
	var out []*itemState
	for _, s := range st {
		if t.authorize(a, "purge", s.Resource) == nil {
			out = append(out, s)
		}
	}
	return out
}

// importerArgs is the condition on purge_follow_names that keeps the
// names origin's importers wrote, and its arguments: none at all where it
// names none.
func importerArgs(po PurgeOrigin) (string, []any) {
	if len(po.Importers) == 0 {
		return ` AND 1 = 0`, nil
	}
	q := ` AND importer IN (?` + strings.Repeat(`,?`, len(po.Importers)-1) + `)`
	args := make([]any, len(po.Importers))
	for i, p := range po.Importers {
		args[i] = p
	}
	return q, args
}

// followRow is a follow as stored.
type followRow struct {
	followKey
	cursor string
	// rescans are the pending names by the source.at that brought them,
	// read from once more.
	rescans map[string][]string
}

// FollowPurges follows, once, the namespace log of every trusted origin
// imported from (§G.1): it retries the purges waiting for an operator, then
// applies each purge after a follow's cursor of a name imported, and each
// purge-ns to every such name, and moves the cursor. Errors of one follow
// don't stop the others; they are returned together.
func (e *Engine) FollowPurges(ctx context.Context) error {
	trusted := e.opt.FollowPurges.Origins
	if len(trusted) == 0 {
		return nil
	}
	var rows []*followRow
	if err := e.read(ctx, func(t *tx) error {
		rows = nil
		q, err := t.Query(`SELECT f.ns, n.name, f.origin, f.src_ns, f.upto FROM purge_follows f JOIN namespaces n ON n.ns = f.ns
			WHERE n.purged = 0 ORDER BY n.name, f.origin, f.src_ns`)
		t.must(err)
		for q.Next() {
			r := &followRow{}
			t.must(q.Scan(&r.ns, &r.nsName, &r.origin, &r.srcNS, &r.cursor))
			if _, ok := trusted[r.origin]; ok {
				rows = append(rows, r)
			}
		}
		t.must(q.Err())
		q.Close()
		for _, r := range rows {
			cond, args := importerArgs(trusted[r.origin])
			q, err := t.Query(`SELECT DISTINCT from_at, name FROM purge_follow_names WHERE ns = ? AND origin = ? AND src_ns = ? AND pending = 1`+cond+` ORDER BY from_at, name`,
				append([]any{r.ns, r.origin, r.srcNS}, args...)...)
			t.must(err)
			for q.Next() {
				var at, name string
				t.must(q.Scan(&at, &name))
				if r.rescans == nil {
					r.rescans = map[string][]string{}
				}
				r.rescans[at] = append(r.rescans[at], name)
			}
			t.must(q.Err())
			q.Close()
		}
		return nil
	}); err != nil {
		return err
	}
	var errs []error
	for _, r := range rows {
		if err := e.jobStep(ctx); err != nil {
			return errors.Join(append(errs, err)...)
		}
		if err := e.followOne(ctx, r, trusted[r.origin]); err != nil {
			errs = append(errs, fmt.Errorf("following the purges of %s: %w", r.followKey, err))
		}
	}
	return errors.Join(errs...)
}

// followOne follows one follow: the waiting purges first, then the log
// after the cursor, then once more from each pending name's source.at.
func (e *Engine) followOne(ctx context.Context, r *followRow, po PurgeOrigin) error {
	timeout := e.opt.FollowPurges.Timeout
	if timeout <= 0 {
		timeout = time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	errs := []error{e.retryWaiting(ctx, r.followKey)}
	c, err := purgeOriginClient(r.origin, po)
	if err != nil {
		return errors.Join(append(errs, err)...)
	}
	// The log after the cursor. A cursor the origin doesn't know (404), as
	// an asserted source's made-up at would be, is moved to the head a
	// rescan below reaches, so a later genuine import is followed.
	unknown := false
	entries, head, err := originLog(ctx, c, r.srcNS, r.cursor)
	if err == nil {
		err = e.applyFollowed(ctx, r.followKey, po, entries, func(id string) error { return e.moveCursor(ctx, r.followKey, r.cursor, id, &r.cursor) })
	}
	if err == nil && head != r.cursor {
		err = e.moveCursor(ctx, r.followKey, r.cursor, head, &r.cursor)
	}
	if err != nil {
		ae, ok := client.AsAPIError(err)
		unknown = ok && ae.Status == http.StatusNotFound
		errs = append(errs, fmt.Errorf("reading after %s: %w", r.cursor, err))
	}
	ats := make([]string, 0, len(r.rescans))
	for at := range r.rescans {
		ats = append(ats, at)
	}
	sort.Strings(ats)
	for _, at := range ats {
		entries, head, err := originLog(ctx, c, r.srcNS, at)
		if err == nil {
			err = e.applyFollowed(ctx, r.followKey, po, entries, nil)
		}
		if err == nil {
			// Exactly the names read for: one a batch of the same bundle
			// added meanwhile stays pending.
			cond, iargs := importerArgs(po)
			err = e.update(ctx, func(t *tx) error {
				for _, name := range r.rescans[at] {
					_, err := t.Exec(`UPDATE purge_follow_names SET pending = 0 WHERE ns = ? AND origin = ? AND src_ns = ? AND name = ? AND from_at = ?`+cond,
						append([]any{r.ns, r.origin, r.srcNS, name, at}, iargs...)...)
					t.must(err)
				}
				return nil
			})
		}
		if err == nil && unknown {
			if err = e.moveCursor(ctx, r.followKey, r.cursor, head, &r.cursor); err == nil {
				unknown = false
			}
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("reading again from %s for the names imported from there: %w", at, err))
		}
	}
	return errors.Join(errs...)
}

// purgeOriginClient is a client of a trusted origin, carrying its bearer
// and following no redirect: the origin would pick where the grant goes.
func purgeOriginClient(origin string, po PurgeOrigin) (*client.Client, error) {
	base := po.BaseURL
	if base == "" {
		base = origin
	}
	hc := telemetry.DefaultClient
	if po.HTTPClient != nil {
		hc = po.HTTPClient
	}
	h := *hc
	h.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	opts := []client.Option{client.WithHTTPClient(&h)}
	if po.Bearer != "" {
		opts = append(opts, client.WithBearer(po.Bearer))
	}
	return client.New(base, opts...)
}

// originLog reads and verifies the origin's namespace log after from, up to
// its head. A log the origin answers 410 purged for, as a sealed one is
// once purged (§8.5), stands for its purge-ns entry, its head.
func originLog(ctx context.Context, c *client.Client, ns, from string) ([]client.NSEntry, string, error) {
	entries, head, err := verify.Namespace(ctx, c, ns, from)
	if ae, ok := client.AsAPIError(err); ok && ae.Status == http.StatusGone && ae.Code == "purged" {
		h := ae.Head()
		if h == "" {
			return nil, "", err
		}
		if h == from {
			return nil, from, nil
		}
		return []client.NSEntry{{ID: h, Kind: "purge-ns"}}, h, nil
	}
	return entries, head, err
}

// moveCursor moves a follow's cursor from old to id, unless another follow
// moved it meanwhile; *cur is set to id.
func (e *Engine) moveCursor(ctx context.Context, k followKey, old, id string, cur *string) error {
	err := e.update(ctx, func(t *tx) error {
		_, err := t.Exec(`UPDATE purge_follows SET upto = ? WHERE ns = ? AND origin = ? AND src_ns = ? AND upto = ?`, id, k.ns, k.origin, k.srcNS, old)
		t.must(err)
		return nil
	})
	if err == nil {
		*cur = id
	}
	return err
}

// applyFollowed applies the purges among entries, in order: a purge of a
// name imported, and a purge-ns to every name imported. After each such
// entry, done (if set) is called with its id.
func (e *Engine) applyFollowed(ctx context.Context, k followKey, po PurgeOrigin, entries []client.NSEntry, done func(id string) error) error {
	for _, en := range entries {
		if en.Kind != "purge" && en.Kind != "purge-ns" {
			continue
		}
		if err := e.jobStep(ctx); err != nil {
			return err
		}
		names, err := e.importedNames(ctx, k, po, en)
		if err != nil {
			return err
		}
		for _, name := range names {
			if err := e.applyFollowedPurge(ctx, k, en.ID, name); err != nil {
				return err
			}
		}
		if done != nil {
			if err := done(en.ID); err != nil {
				return err
			}
		}
	}
	return nil
}

// importedNames are the names an origin's purge entry reaches here: its
// resource, if one of po's importers imported it, or for a purge-ns every
// name they imported.
func (e *Engine) importedNames(ctx context.Context, k followKey, po PurgeOrigin, en client.NSEntry) ([]string, error) {
	var names []string
	err := e.read(ctx, func(t *tx) error {
		names = nil
		cond, iargs := importerArgs(po)
		q := `SELECT DISTINCT name FROM purge_follow_names WHERE ns = ? AND origin = ? AND src_ns = ?` + cond
		args := append([]any{k.ns, k.origin, k.srcNS}, iargs...)
		if en.Kind == "purge" {
			q += ` AND name = ?`
			args = append(args, en.Resource)
		}
		rows, err := t.Query(q+` ORDER BY name`, args...)
		t.must(err)
		for rows.Next() {
			var s string
			t.must(rows.Scan(&s))
			names = append(names, s)
		}
		t.must(rows.Err())
		rows.Close()
		return nil
	})
	return names, err
}

// errInUse carries the in_use refusal of a followed purge out of its
// transaction, which it rolls back.
type errInUse struct{ refusal *Error }

func (e *errInUse) Error() string { return e.refusal.Error() }

// applyFollowedPurge purges name in k's namespace as §8.3 does (purgeApply:
// its branches and cache tags too), as the server, in a transaction of its
// own. One §6.1 refuses as in_use waits (purge_follow_waiting); any other
// failure is returned.
func (e *Engine) applyFollowedPurge(ctx context.Context, k followKey, entry, name string) error {
	err := e.update(ctx, func(t *tx) error {
		return t.followedPurge(k, name)
	})
	var iu *errInUse
	if errors.As(err, &iu) {
		body, _ := json.Marshal(iu.refusal.Body)
		log.Printf("purge-follow: the purge of %s/%s followed from %s/ns/%s (entry %s) waits for an operator: %s", k.nsName, name, k.origin, k.srcNS, entry, body)
		return e.update(ctx, func(t *tx) error {
			_, err := t.Exec(`INSERT INTO purge_follow_waiting (ns, origin, src_ns, name, entry, refusal, since) VALUES (?,?,?,?,?,?,?)
				ON CONFLICT (ns, origin, src_ns, name) DO UPDATE SET refusal = excluded.refusal`,
				k.ns, k.origin, k.srcNS, name, entry, string(body), t.now.UnixMilli())
			t.must(err)
			return nil
		})
	}
	return err
}

// followedPurge is the purge of name in k's namespace, followed from an
// origin, or *errInUse.
func (t *tx) followedPurge(k followKey, name string) error {
	n := t.nsByID(k.ns)
	if n == nil || n.purged {
		// A purged namespace has nothing left to purge (§8.5).
		return nil
	}
	// As Purge does: a name purged already, or never written here, has
	// nothing to purge (an operator may have purged it with ?force=1).
	if v := t.resolve(n, name, nil); v.state == Purged || v.state == NotFound {
		_, err := t.Exec(`DELETE FROM purge_follow_waiting WHERE ns = ? AND origin = ? AND src_ns = ? AND name = ?`, k.ns, k.origin, k.srcNS, name)
		t.must(err)
		return nil
	}
	plan := t.purgePlan(n, name)
	gone := func(ns *nsRow, res string) bool { return res == name && plan.covers(t, ns) }
	// The referencing namespaces are the operator's to see, whoever may
	// read them (refsInUse lists a caller's only).
	ch := refChange{exclude: gone, removed: gone, name: name}
	var referencing []any
	more := false
	t.brokenEach(&ch, func(m *nsRow) bool {
		if len(referencing) == t.e.opt.Maximums.LogPageSize {
			more = true
			return false
		}
		referencing = append(referencing, m.name)
		return true
	})
	if len(referencing) > 0 {
		refusal := apiErr(409, "in_use", "referencing", referencing, "message",
			"the purge followed from "+k.origin+" would remove the last available copy of a referenced schema revision (§6.1, §G.1)")
		if more {
			refusal.Body["more"] = true
		}
		return &errInUse{refusal}
	}
	author := t.authorID(FollowAuthor)
	t.asServer(func() { t.purgeApply(plan, author, false) })
	_, err := t.Exec(`DELETE FROM purge_follow_waiting WHERE ns = ? AND origin = ? AND src_ns = ? AND name = ?`, k.ns, k.origin, k.srcNS, name)
	t.must(err)
	return nil
}

// retryWaiting tries again the purges of k waiting for an operator.
func (e *Engine) retryWaiting(ctx context.Context, k followKey) error {
	type waiting struct{ name, entry string }
	var ws []waiting
	if err := e.read(ctx, func(t *tx) error {
		rows, err := t.Query(`SELECT name, entry FROM purge_follow_waiting WHERE ns = ? AND origin = ? AND src_ns = ? ORDER BY name`, k.ns, k.origin, k.srcNS)
		t.must(err)
		for rows.Next() {
			var w waiting
			t.must(rows.Scan(&w.name, &w.entry))
			ws = append(ws, w)
		}
		t.must(rows.Err())
		rows.Close()
		return nil
	}); err != nil {
		return err
	}
	var errs []error
	for _, w := range ws {
		if err := e.jobStep(ctx); err != nil {
			return errors.Join(append(errs, err)...)
		}
		errs = append(errs, e.applyFollowedPurge(ctx, k, w.entry, w.name))
	}
	return errors.Join(errs...)
}

// FollowedPurgeWaiting is a followed purge that waits for an operator.
type FollowedPurgeWaiting struct {
	NS, Origin, SourceNS, Name string
	// Entry is the origin's purge or purge-ns entry.
	Entry string
	// Refusal is the in_use answer's body (§6.1).
	Refusal map[string]any
}

// FollowedPurgesWaiting lists the followed purges waiting for an operator,
// by namespace and name.
func (e *Engine) FollowedPurgesWaiting(ctx context.Context) ([]FollowedPurgeWaiting, error) {
	var out []FollowedPurgeWaiting
	err := e.read(ctx, func(t *tx) error {
		out = nil
		rows, err := t.Query(`SELECT n.name, w.origin, w.src_ns, w.name, w.entry, w.refusal FROM purge_follow_waiting w JOIN namespaces n ON n.ns = w.ns`)
		t.must(err)
		for rows.Next() {
			var w FollowedPurgeWaiting
			var body string
			t.must(rows.Scan(&w.NS, &w.Origin, &w.SourceNS, &w.Name, &w.Entry, &body))
			_ = json.Unmarshal([]byte(body), &w.Refusal)
			out = append(out, w)
		}
		t.must(rows.Err())
		rows.Close()
		return nil
	})
	sort.Slice(out, func(i, j int) bool {
		if out[i].NS != out[j].NS {
			return out[i].NS < out[j].NS
		}
		return out[i].Name < out[j].Name
	})
	return out, err
}

// purgeFollowLoop runs FollowPurges every interval on the leader until
// Close.
func (e *Engine) purgeFollowLoop(interval time.Duration) {
	defer e.bg.Done()
	tk := time.NewTicker(interval)
	defer tk.Stop()
	for {
		select {
		case <-e.stop:
			return
		case <-tk.C:
			ctx, cancel := context.WithCancel(context.Background())
			go func() {
				select {
				case <-e.stop:
				case <-ctx.Done():
				}
				cancel()
			}()
			if e.leader(ctx) {
				if err := e.FollowPurges(leaderJob(ctx)); err != nil && ctx.Err() == nil {
					log.Printf("purge-follow: %v", err)
				}
			}
			cancel()
		}
	}
}
