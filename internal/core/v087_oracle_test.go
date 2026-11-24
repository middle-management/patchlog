package core

import (
	"context"
	"fmt"
	"math/rand"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/grant"
	"github.com/middle-management/patchlog/internal/jsonv"
)

// The oracle of §7.9 Log entries, /heads and a resource's own log: random
// histories (heads, tombstones, restores, multi-step batches with and
// without config changes, prunes, purges and config changes) are read by
// a partial reader whose one block rule is
//
//	{ "all": [ { test /resource pattern ^[a-m] }, { test /doc/team "a" } ] }
//
// and what the engine serves is compared, entry by entry, with a naive
// filter written from the text of §7.9 over the unfiltered log, which
// knows each revision's document from what the test wrote, never from the
// engine. Every revision is read before any prune, so the engine's kept
// answers stand for pruned documents (§7.9 Cost), and the engine is
// reopened partway, so they are read back from read_judged.
//
// Since v0.90 it runs in a public namespace too, where the grant filters
// only under its view prefix (§7.9 Where, §7 step 1) and a resource's own
// URLs ignore it; and some documents carry $schema, which every head
// entry of the unfiltered log carries as schema (§7.4) and the filter
// keeps on the entries it shows.

var oracleNames = []string{"alpha", "beta", "kilo", "mike", "nina", "zed"}

var oracleRe = regexp.MustCompile(`^[a-m]`)

// oracleRule is the partial reader's block rule; purgeShown is its half
// that doesn't refer to /doc, all flattened.
var oracleRule = map[string]any{"all": []any{
	map[string]any{"op": "test", "path": "/resource", "schema": map[string]any{"pattern": "^[a-m]"}},
	map[string]any{"op": "test", "path": "/doc/team", "value": "a"},
}}

type oracleWorld struct {
	*v75World
	t      *testing.T
	public bool
	schema string // the schema revision some documents carry as $schema
	rng    *rand.Rand
	admin  Credentials
	reader Credentials
	docs   map[string]map[string]any // revision or tombstone id → its document (a tombstone's: the deleted one)
	heads  map[string]string         // name → head id, "" for none
	tomb   map[string]bool
	purged map[string]bool
	hor    map[string]string // name → horizon id
	n      int
}

func newOracleWorld(t *testing.T, seed int64, public bool) *oracleWorld {
	w := &oracleWorld{v75World: newV75World(t, v75Opts{file: true}), t: t, rng: rand.New(rand.NewSource(seed)), public: public,
		docs: map[string]map[string]any{}, heads: map[string]string{}, tomb: map[string]bool{}, purged: map[string]bool{}, hor: map[string]string{}}
	read := "grant"
	if public {
		read = "public"
	}
	w.mkNS("orc", map[string]any{"read": read, "keys": []any{w.kEntry(),
		map[string]any{"kid": "rd", "alg": "ed25519", "pub": w.catPub, "can": []any{"read"}}}})
	w.admin = w.cred(w.kPriv, map[string]any{"kid": "k", "sub": "user:root", "ns": []any{"orc"},
		"can": []any{"read", "create", "append", "delete", "restore", "purge", "prune", "config"}, "exp": w.now().Add(24 * 365 * time.Hour).UTC().Format(time.RFC3339)})
	w.v75World.admin = w.admin
	w.reader = w.cred(w.catPriv, map[string]any{"kid": "rd", "sub": "user:r", "ns": []any{"orc"}, "can": []any{"read"},
		"rules": []any{oracleRule}, "exp": w.now().Add(24 * 365 * time.Hour).UTC().Format(time.RFC3339)})
	// A schema some documents name; its name never passes the reader's
	// rule, so the oracle never shows it.
	res, err := w.e.WriteResource(context.Background(), Request{NS: "orc", Cred: w.admin}, Item{Resource: "sch", IfNoneMatch: true,
		Steps: []Step{{Patches: patchTo(map[string]any{"$schema": "https://json-schema.org/draft/2020-12/schema", "type": "object"})}}})
	if err != nil {
		t.Fatal(err)
	}
	w.schema = "/r/orc/sch/rev/" + res.Items[0].IDs[0]
	return w
}

func (w *oracleWorld) team() string { return []string{"a", "b"}[w.rng.Intn(2)] }

func (w *oracleWorld) doc() map[string]any {
	w.n++
	d := map[string]any{"team": w.team(), "n": float64(w.n)}
	if w.rng.Intn(2) == 0 {
		d["$schema"] = w.schema
	}
	return d
}

// checkSchemas is §7.4's schema over the unfiltered log es: a head entry,
// a batch's included, carries its revision's $schema, as the oracle wrote
// it, and no other entry carries one (v0.90).
func (w *oracleWorld) checkSchemas(what string, es []map[string]any) {
	one := func(e map[string]any) {
		name, _ := e["resource"].(string)
		target, _ := e["target"].(string)
		sc, has := e["schema"]
		if name == "sch" {
			// A schema's own $schema is its dialect.
			if sc != "https://json-schema.org/draft/2020-12/schema" {
				w.t.Fatalf("after %s, the schema's own head carries schema %v", what, sc)
			}
			return
		}
		var want any
		if e["kind"] == "head" {
			if d := w.docs[target]; d != nil {
				want = d["$schema"]
			}
		}
		if want == nil && has || want != nil && sc != want {
			w.t.Fatalf("after %s, %s entry of %s at %s: schema %v, want %v", what, e["kind"], name, target, sc, want)
		}
	}
	for _, e := range es {
		if e["kind"] != "batch" {
			one(e)
			continue
		}
		if _, has := e["schema"]; has {
			w.t.Fatalf("after %s, a batch entry carries schema: %v", what, e)
		}
		if _, has := e["schemas"]; has {
			w.t.Fatalf("after %s, a batch entry carries schemas: %v", what, e)
		}
		for _, x := range e["entries"].([]any) {
			one(x.(map[string]any))
		}
	}
}

// patchTo is a patch set taking any document to d.
func patchTo(d map[string]any) []any {
	return []any{map[string]any{"op": "add", "path": "", "value": d}}
}

// item is a random write of name: a create, an append, a delete, a
// restore, or several steps; it returns the documents its steps leave
// (nil for a delete).
func (w *oracleWorld) item(name string, maxSteps int) (Item, []map[string]any) {
	it := Item{Resource: name}
	var docs []map[string]any
	steps := 1 + w.rng.Intn(maxSteps)
	cur := w.heads[name]
	switch {
	case cur == "":
		it.IfNoneMatch = true
	default:
		it.IfMatch = cur
	}
	live := cur != "" && !w.tomb[name]
	for i := 0; i < steps; i++ {
		if live && w.rng.Intn(3) == 0 {
			it.Steps = append(it.Steps, Step{Delete: true})
			docs = append(docs, nil)
			live = false
			continue
		}
		d := w.doc()
		it.Steps = append(it.Steps, Step{Patches: patchTo(d)})
		docs = append(docs, d)
		live = true
	}
	return it, docs
}

// record notes the ids an item produced, with their documents.
func (w *oracleWorld) record(name string, ids []string, docs []map[string]any) {
	var last map[string]any
	if w.heads[name] != "" && !w.tomb[name] {
		last = w.docs[w.heads[name]]
	}
	if w.heads[name] != "" && w.tomb[name] {
		last = w.docs[w.heads[name]] // a tombstone's deleted document
	}
	for i, id := range ids {
		if docs[i] == nil {
			w.docs[id], w.tomb[name] = last, true
		} else {
			w.docs[id], w.tomb[name], last = docs[i], false, docs[i]
		}
		w.heads[name] = id
	}
}

func (w *oracleWorld) step() string {
	ctx := context.Background()
	req := Request{NS: "orc", Cred: w.admin}
	var live []string
	for _, n := range oracleNames {
		if !w.purged[n] {
			live = append(live, n)
		}
	}
	if len(live) == 0 {
		return "none"
	}
	name := live[w.rng.Intn(len(live))]
	switch r := w.rng.Intn(20); {
	case r < 7:
		it, docs := w.item(name, 1)
		res, err := w.e.WriteResource(ctx, req, it)
		if err != nil {
			w.t.Fatalf("write %s %+v: %v", name, it, err)
		}
		w.record(name, res.Items[0].IDs, docs)
		return "write " + name
	case r < 12:
		var items []Item
		var docs [][]map[string]any
		seen := map[string]bool{}
		for k := 1 + w.rng.Intn(3); k > 0; k-- {
			n := live[w.rng.Intn(len(live))]
			if seen[n] {
				continue
			}
			seen[n] = true
			it, d := w.item(n, 3)
			items, docs = append(items, it), append(docs, d)
		}
		var cc *ConfigChange
		if w.rng.Intn(4) == 0 {
			info, err := w.e.NamespaceHead(ctx, "orc", w.admin)
			if err != nil {
				w.t.Fatal(err)
			}
			cc = &ConfigChange{IfMatch: info.Config, Patches: []any{map[string]any{"op": "add", "path": "/x-note", "value": fmt.Sprint(w.n)}}}
		}
		res, err := w.e.Batch(ctx, req, items, cc, nil, false)
		if err != nil {
			w.t.Fatalf("batch: %v", err)
		}
		for i, ir := range res.Items {
			w.record(items[i].Resource, ir.IDs, docs[i])
		}
		return "batch"
	case r < 14:
		w.patchConfig("orc", map[string]any{"op": "add", "path": "/x-note", "value": fmt.Sprint(w.rng.Int())})
		return "config"
	case r < 17:
		if w.heads[name] == "" {
			return "none"
		}
		// Past the retry window, which a horizon never passes (§8.6).
		w.clock.Add((10 * time.Minute).Milliseconds())
		res, err := w.e.Prune(ctx, req, name, PruneRequest{Horizon: w.heads[name]})
		if err != nil {
			w.t.Fatalf("prune %s: %v", name, err)
		}
		w.hor[name] = res.Horizon
		return "prune " + name
	default:
		if w.heads[name] == "" || w.rng.Intn(3) != 0 {
			return "none"
		}
		if _, err := w.e.Purge(ctx, req, name, w.heads[name], false); err != nil {
			w.t.Fatalf("purge %s: %v", name, err)
		}
		w.purged[name] = true
		return "purge " + name
	}
}

// visible is the oracle's §7.9 Visible: the reader's rule with the
// revision's read envelope, null for a purged resource's.
func (w *oracleWorld) visible(name, id string) bool {
	if w.purged[name] {
		return false
	}
	d, ok := w.docs[id]
	return ok && d != nil && oracleRe.MatchString(name) && d["team"] == "a"
}

// filterLog is §7.9 Log entries, applied to the unfiltered log es (from
// genesis): each entry as the reader is shown it, nil where dropped.
func (w *oracleWorld) filterLog(es []map[string]any) []map[string]any {
	out := make([]map[string]any, len(es))
	lastShown := map[string]bool{} // name → its previous head or tombstone entry was shown as itself
	for i, e := range es {
		e = jsonv.MustParse(jsonv.Canonical(e)).(map[string]any) // a copy
		name, _ := e["resource"].(string)
		target, _ := e["target"].(string)
		switch e["kind"] {
		case "config", "purge-ns":
			out[i] = e
		case "head", "tombstone":
			shown := w.visible(name, target)
			switch {
			case shown:
				out[i] = e
			case lastShown[name]:
				out[i] = map[string]any{"id": e["id"], "prev": e["prev"], "kind": "hidden", "resource": name}
			}
			lastShown[name] = shown
		case "prune":
			if w.visible(name, target) {
				out[i] = e
			}
		case "purge":
			if oracleRe.MatchString(name) {
				out[i] = e
			}
		case "batch":
			var kept []any
			names := map[string]bool{}
			for _, x := range e["entries"].([]any) {
				em := x.(map[string]any)
				en, _ := em["resource"].(string)
				et, _ := em["target"].(string)
				switch em["kind"] {
				case "config":
					kept = append(kept, em)
				case "head", "tombstone":
					shown := w.visible(en, et)
					switch {
					case shown:
						kept = append(kept, em)
						names[en] = true
					case lastShown[en]:
						kept = append(kept, map[string]any{"kind": "hidden", "resource": en})
					}
					lastShown[en] = shown
				}
			}
			if len(kept) == 0 {
				continue
			}
			e["entries"] = kept
			for _, k := range []string{"gestures"} {
				if g, ok := e[k].(map[string]any); ok {
					narrowNames(e, k, g, names)
				}
			}
			out[i] = e
		}
	}
	return out
}

// served reads the reader's filtered log from genesis to at, page by
// page, and checks that pages chain.
func (w *oracleWorld) served(view, at string) []map[string]any {
	var out []map[string]any
	since := ""
	for {
		lg, info, err := w.e.FilteredLog(context.Background(), "orc", view, at, since, 3, w.reader)
		if err != nil || lg.Status != 200 || info.At != at {
			w.t.Fatalf("FilteredLog since %q: %+v %+v %v", since, lg, info, err)
		}
		out = append(out, lg.Entries...)
		if !lg.More {
			return out
		}
		if lg.Last == since {
			w.t.Fatal("a page that moves nothing")
		}
		since = lg.Last
	}
}

func (w *oracleWorld) check(what string) {
	ctx := context.Background()
	var view string
	w.inTx(func(t2 *tx) {
		n := t2.nsByName("orc")
		fs := t2.filteredScope(n)
		a, kind, err := t2.viewAccess(n, w.reader)
		if err != nil || kind != accessPartial || fs == nil {
			w.t.Fatalf("the reader isn't partial: %v %v", kind, err)
		}
		if _, kind, _, err := t2.nsAccess(n, w.reader); err != nil || (kind == accessPartial) == w.public {
			// In a public namespace an unfiltered URL ignores the grant.
			w.t.Fatalf("the reader at an unfiltered URL: %v %v", kind, err)
		}
		fv, err := t2.grantView(fs, t2.filteredCurrent(fs), a)
		if err != nil {
			w.t.Fatal(err)
		}
		view = fv.view
	})
	at := w.v75World.head("orc")
	all, err := w.e.NamespaceLog(ctx, "orc", at, "", 0, w.admin)
	if err != nil || all.Status != 200 {
		w.t.Fatalf("the unfiltered log: %v", err)
	}
	w.checkSchemas(what, all.Entries)
	var want []map[string]any
	for _, e := range w.filterLog(all.Entries) {
		if e != nil {
			want = append(want, e)
		}
	}
	got := w.served(view, at)
	if !reflect.DeepEqual(canonAll(got), canonAll(want)) {
		w.t.Fatalf("after %s, the filtered log:\n got  %s\n want %s", what, canonAll(got), canonAll(want))
	}
	// Ranges that start mid-log show what the whole one shows from there.
	filtered := w.filterLog(all.Entries)
	for i := 0; i < len(all.Entries); i += 1 + w.rng.Intn(4) {
		since := all.Entries[i]["id"].(string)
		lg, _, err := w.e.FilteredLog(ctx, "orc", view, at, since, 0, w.reader)
		if err != nil {
			w.t.Fatal(err)
		}
		var wantFrom []map[string]any
		for _, e := range filtered[i+1:] {
			if e != nil {
				wantFrom = append(wantFrom, e)
			}
		}
		if !reflect.DeepEqual(canonAll(lg.Entries), canonAll(wantFrom)) {
			w.t.Fatalf("after %s, the range since %s:\n got  %s\n want %s", what, since, canonAll(lg.Entries), canonAll(wantFrom))
		}
	}
	// /heads: a row where its head is visible, a tombstone as its deleted
	// document, a purge as its entry is shown.
	heads, err := w.e.NamespaceHeads(ctx, "orc", at, "", w.admin)
	if err != nil {
		w.t.Fatal(err)
	}
	var wantRows []map[string]any
	for _, h := range heads.Items {
		name, target := h["resource"].(string), fmt.Sprint(h["target"])
		show := false
		switch h["kind"] {
		case "purge":
			show = oracleRe.MatchString(name)
		default:
			show = w.visible(name, target)
		}
		if show {
			wantRows = append(wantRows, h)
		}
	}
	page, _, err := w.e.FilteredHeads(ctx, "orc", view, at, "", "", w.reader)
	if err != nil {
		w.t.Fatal(err)
	}
	if !reflect.DeepEqual(canonAll(page.Items), canonAll(wantRows)) {
		w.t.Fatalf("after %s, /heads:\n got  %s\n want %s", what, canonAll(page.Items), canonAll(wantRows))
	}
	// Each resource's own log, from its horizon: its visible revisions,
	// without patches where the parent is hidden, and a hidden one whose
	// parent is visible as { id, parent, kind: "hidden" }.
	for _, name := range oracleNames {
		if w.heads[name] == "" || w.purged[name] {
			continue
		}
		full, err := w.e.ResourceLog(ctx, "orc", name, "", w.hor[name], 0, w.admin)
		if err != nil || full.Status != 200 {
			w.t.Fatalf("%s's log: %+v %v", name, full, err)
		}
		fullLog := canonAll(full.Entries)
		var wantLog []map[string]any
		for _, e := range full.Entries {
			id, parent := e["id"].(string), e["parent"].(string)
			vis, pvis := w.visible(name, id), parent != "" && w.visible(name, parent)
			switch {
			case vis:
				if parent != "" && !pvis {
					delete(e, "patches")
				}
				wantLog = append(wantLog, e)
			case pvis:
				wantLog = append(wantLog, map[string]any{"id": id, "parent": parent, "kind": "hidden"})
			}
		}
		lg, err := w.e.ResourceLog(ctx, "orc", name, "", w.hor[name], 0, w.reader)
		if w.public {
			// A public namespace's resource URLs ignore the grant (§7
			// step 1): the reader reads the unfiltered log.
			if err != nil || lg.Status != 200 || canonAll(lg.Entries) != fullLog {
				w.t.Fatalf("after %s, %s's log to the reader in a public namespace: %+v %v", what, name, lg, err)
			}
			continue
		}
		if !oracleRe.MatchString(name) {
			// Its name never passes: a read-rule failure, 404 (§7).
			if v75Status(err) != 404 {
				w.t.Fatalf("after %s, %s's log to a reader whose rules refuse the name: %v", what, name, err)
			}
			continue
		}
		if err != nil || lg.Status != 200 {
			w.t.Fatalf("after %s, %s's log to the reader: %+v %v", what, name, lg, err)
		}
		if !reflect.DeepEqual(canonAll(lg.Entries), canonAll(wantLog)) {
			w.t.Fatalf("after %s, %s's log:\n got  %s\n want %s", what, name, canonAll(lg.Entries), canonAll(wantLog))
		}
	}
}

func canonAll(es []map[string]any) string {
	var b strings.Builder
	for _, e := range es {
		b.Write(jsonv.Canonical(jsonv.FromGo(e)))
		b.WriteByte('\n')
	}
	return b.String()
}

func TestV087FilteredOracle(t *testing.T) {
	seeds := 24
	if testing.Short() {
		seeds = 4
	}
	for i := 1; i <= 2*seeds; i++ {
		// Odd runs in a private namespace, even ones in a public one
		// (v0.90).
		seed, public := int64((i+1)/2), i%2 == 0
		t.Run(fmt.Sprintf("%d-public=%v", seed, public), func(t *testing.T) {
			t.Parallel()
			w := newOracleWorld(t, seed, public)
			for i := 0; i < 40; i++ {
				what := w.step()
				w.check(fmt.Sprintf("step %d (%s)", i, what))
				if i == 20 {
					// The answers kept so far are read back from
					// read_judged, documents pruned since included.
					w.e.Close()
					w.open(nil)
					w.check("reopening")
				}
			}
		})
	}
}

var _ = grant.Principal{}

// An unrestricted reader's /ns/{ns} cookie at a view's long-poll reads
// unfiltered, and its page is never the view's readers': a partial reader
// polling after it, at the same view, since and checkpoint, sees only its
// own entries.
func TestV087UnrestrictedCookieNotShared(t *testing.T) {
	w := newV75World(t, v75Opts{})
	w.seed()
	ctx := context.Background()
	li := w.li()
	view := v075ViewID(t, w, li)
	since := w.head("matches")
	w.put("matches", "opener", map[string]any{"v": 2})
	w.put("matches", "derby", map[string]any{"v": 2})
	nsCookie := Credentials{Edge: &EdgeGrant{NS: "matches", Prefix: "/ns/matches", Exp: w.now().Add(10 * time.Minute)}}
	names := func(lg *Log) []string {
		var out []string
		for _, e := range lg.Entries {
			out = append(out, fmt.Sprint(e["resource"]))
		}
		return out
	}
	all, info, err := w.e.FilteredLiveLog(ctx, "matches", view, since, 100, nsCookie)
	if err != nil || !info.Private || !reflect.DeepEqual(names(all), []string{"opener", "derby"}) {
		t.Fatalf("the /ns cookie: %v %+v %v", names(all), info, err)
	}
	mine, info, err := w.e.FilteredLiveLog(ctx, "matches", view, since, 100, li)
	if err != nil || info.Private || !reflect.DeepEqual(names(mine), []string{"derby"}) {
		t.Fatalf("li after it: %v %+v %v", names(mine), info, err)
	}
}
