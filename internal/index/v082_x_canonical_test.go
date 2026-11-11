package index_test

import (
	"bytes"
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/derived"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/seal"
)

// v82xWorld is an index of two sealed private namespaces, sec and, padded,
// secp, each holding a and b of a schema in the public namespace schemas
// whose title is indexed as text and tag as a facet. a's title carries
// U+2028, "<" and "&", which Go's encoder escapes and canonical JSON
// (RFC 8785) doesn't. w writes both; rd reads both whole, fixed reads a
// alone; logs are the lines the index logged.
type v82xWorld struct {
	s         *clienttest.Server
	k         clienttest.Key
	w         *client.Client
	x         *svc
	rd, fixed string
	ref       string
	logs      func() []string
}

const v82xTitle = "secret a <b> & é"

func newV82XWorld(t *testing.T, mods ...func(*indexOpts)) *v82xWorld {
	t.Helper()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{Auth: true, KeyStore: keyStore(t), LongPoll: 150 * time.Millisecond})
	k := clienttest.NewKey("k")
	for ns, enc := range map[string]map[string]any{"sec": {"level": "sealed"}, "secp": {"level": "sealed", "pad": true}, "schemas": nil} {
		doc := map[string]any{"read": "public", "keys": []any{k.Entry("*")}}
		if enc != nil {
			doc["read"], doc["encryption"] = "grant", enc
		}
		must(s.Client(t, client.WithBearer(s.OperatorGrant(t, ns))).CreateNamespace(ctx, ns, doc))
	}
	nss := []string{"sec", "secp"}
	v := &v82xWorld{s: s, k: k}
	v.w = s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:w", []string{"sec", "secp", "schemas"}, []string{"read", "create", "append"})), client.WithKeys(client.NewKeys(nil)))
	sch := must(v.w.CreateDoc(ctx, "schemas", "item", map[string]any{"$schema": d2020, "type": "object",
		"properties": map[string]any{"title": map[string]any{"type": "string", "x-index": "text"}, "tag": map[string]any{"type": "string", "x-index": "facet"}}}))
	v.ref = "/r/schemas/item/rev/" + sch.ID
	for _, ns := range nss {
		must(createNonced(v.w, ns, "a", map[string]any{"$schema": v.ref, "title": v82xTitle, "tag": "ta"}))
		must(createNonced(v.w, ns, "b", map[string]any{"$schema": v.ref, "title": "secret b", "tag": "tb"}))
	}
	v.rd = k.Grant(t, s.Now(), "user:r", nss, []string{"read"})
	v.fixed = k.Grant(t, s.Now(), "user:li", nss, []string{"read"}, map[string]any{"rules": []any{map[string]any{"op": "test", "path": "/resource", "value": "a"}}})
	ic := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "svc:indexer", nss, []string{"read"})), client.WithKeys(client.NewKeys(nil)))
	var mu sync.Mutex
	var lines []string
	mods = append([]func(*indexOpts){func(o *indexOpts) {
		logf := o.Logf
		o.Logf = func(f string, a ...any) {
			logf(f, a...)
			mu.Lock()
			lines = append(lines, fmt.Sprintf(f, a...))
			mu.Unlock()
		}
	}}, mods...)
	v.logs = func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), lines...)
	}
	v.x = startSvcWith(t, ic, svcOpts{db: filepath.Join(t.TempDir(), "i.db"), ns: nss, now: s.Now}, mods...)
	for _, ns := range nss {
		v.x.caughtUp(ns)
	}
	return v
}

// XT-1 (1), SVC-03 through the index (SERVICES §E.2.6 What gets sealed,
// v0.82: "Each plaintext sealed here is canonical JSON (§3.1), before any
// padding"; "a whole-response JWE's plaintext is the response body ... a
// per-entry JWE's the members it replaces"): what the index's handlers
// seal for a reader, opened as a reader opens it (derived.OpenView and
// OpenItem under the keys the origin gives), is canonical(parsed) byte
// for byte, for a query with fields and counts, whole and per
// entry, padded and not; the padding is spaces after it, to the bucket
// seal.Pad gives. The view each is bound to is the target it was served
// at. Before v0.82 the plaintext was the body as Go's encoder wrote it:
// members in struct order and U+2028 escaped.
func TestV082XIndexSealsCanonicalJSON(t *testing.T) {
	t.Parallel()
	v := newV82XWorld(t)
	canonical := func(what string, pt []byte, padded bool) map[string]any {
		t.Helper()
		body := pt
		if padded {
			body = bytes.TrimRight(pt, " ")
			if !bytes.Equal(seal.Pad(body), pt) {
				t.Errorf("%s: %d bytes of plaintext aren't its %d bytes padded to their bucket", what, len(pt), len(body))
			}
		}
		parsed, err := jsonv.Parse(body)
		if err != nil {
			t.Fatalf("%s: %v: %s", what, err, body)
		}
		if c := jsonv.Canonical(parsed); !bytes.Equal(c, body) {
			t.Errorf("%s: the plaintext isn't canonical JSON:\n%s\nwant\n%s", what, body, c)
		}
		if !bytes.Contains(body, []byte(" a <b> & é")) {
			t.Errorf("%s: a's title isn't written as canonical JSON writes it: %s", what, body)
		}
		return parsed.(map[string]any)
	}
	for _, ns := range []string{"sec", "secp"} {
		padded := ns == "secp"
		keys := epochKeys(t, v.w, ns)
		// Whole response: the reader reads ns whole.
		f := v.x.fetch("/"+ns+"?q=secret&fields=%2Ftitle&counts=%2Ftag", v.rd)
		if ct := f.header.Get("Content-Type"); ct != seal.ContentType {
			t.Fatalf("%s: content type %q: %s", ns, ct, f.body)
		}
		h := must(seal.ParseHeader(string(f.body)))
		if h.Kid != ns+"#1" || h.PL["view"] != f.path || h.PL["ns"] != ns || len(h.PL) != 2 || strings.Contains(f.path, "min=") {
			t.Errorf("%s: header %+v, served at %s", ns, h, f.path)
		}
		pt := must(derived.OpenView(string(f.body), keys, derived.View{NS: ns, Target: f.path}))
		b := canonical(ns+", the whole response", pt, padded)
		if got := strings.Join(resources(b), ","); got != "a,b" || b["counts"] == nil || b["at"] != v.x.ix.Checkpoint(ns) {
			t.Errorf("%s: the body %s", ns, pt)
		}
		// Per entry: the reader reads a alone.
		pf := v.x.fetch("/"+ns+"?q=secret&fields=%2Ftitle", v.fixed)
		hits := decodeJSON(t, pf.body)["hits"].([]any)
		if ct := pf.header.Get("Content-Type"); ct != "application/json" || len(hits) != 1 {
			t.Fatalf("%s per entry: %q %s", ns, ct, pf.body)
		}
		hit := hits[0].(map[string]any)
		jwe, _ := hit["sealed"].(string)
		ih := must(seal.ParseHeader(jwe))
		if ih.Kid != ns+"#1" || ih.PL["view"] != pf.path || ih.PL["name"] != "a" || ih.PL["ns"] != ns || len(ih.PL) != 3 {
			t.Errorf("%s per entry: header %+v, served at %s", ns, ih, pf.path)
		}
		ipt := must(derived.OpenItem(jwe, derived.ItemKey(keys, ns, "a"), derived.View{NS: ns, Target: pf.path}, ns, "a"))
		vals := canonical(ns+", a's sealed values", ipt, padded)
		// The members it replaces: none of them is also served clear.
		for m := range vals {
			if _, clear := hit[m]; clear {
				t.Errorf("%s per entry: %s is sealed and served clear", ns, m)
			}
		}
		if vals["/title"] == nil || vals["score"] == nil {
			t.Errorf("%s per entry: the sealed values %s", ns, ipt)
		}
	}
}
