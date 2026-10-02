package bundle_test

import (
	"bytes"
	"context"
	"net/http/httptest"
	"testing"

	"github.com/middle-management/patchlog/internal/bundle"
	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/core"
	"github.com/middle-management/patchlog/internal/pgtest"
	"github.com/middle-management/patchlog/internal/schema"
	"github.com/middle-management/patchlog/internal/server"
	"github.com/middle-management/patchlog/internal/testenv"
)

var ctx = context.Background()

const (
	stagingOrigin = "https://staging.example"
	cmsOrigin     = "https://cms.example"
)

type nopPurger struct{}

func (nopPurger) PurgeTags([]string) {}

// deployment is an in-process server with its own origin (clienttest has
// a fixed origin, and two deployments need two).
type deployment struct {
	t      *testing.T
	origin string
	url    string
	c      *client.Client
}

func newDeployment(t *testing.T, origin string, opts ...func(*core.Options)) *deployment {
	t.Helper()
	o := core.Options{Path: pgtest.DB(t), BlobDir: t.TempDir(), Origin: origin, AuthDisabled: true, Purger: nopPurger{}}
	for _, f := range opts {
		f(&o)
	}
	testenv.Apply(&o)
	e, err := core.Open(o)
	if err != nil {
		t.Fatal(err)
	}
	hs := httptest.NewServer(clienttest.CountPages(server.New(e)))
	t.Cleanup(func() {
		hs.CloseClientConnections()
		hs.Close()
		e.Close()
	})
	c, err := client.New(hs.URL, client.WithAuthor("alice"))
	if err != nil {
		t.Fatal(err)
	}
	return &deployment{t: t, origin: origin, url: hs.URL, c: c}
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

func noErr(t testing.TB, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func op(o, path string, v any) map[string]any {
	return map[string]any{"op": o, "path": path, "value": v}
}

func ops(o ...map[string]any) []any {
	out := make([]any, len(o))
	for i, x := range o {
		out[i] = x
	}
	return out
}

func (d *deployment) ns(name string, doc map[string]any) {
	d.t.Helper()
	if doc == nil {
		doc = map[string]any{"read": "public"}
	}
	must(d.c.CreateNamespace(ctx, name, doc))
}

func (d *deployment) create(ns, name string, doc any) string {
	d.t.Helper()
	return must(d.c.CreateDoc(ctx, ns, name, doc)).ID
}

func (d *deployment) head(ns, name string) *client.Head {
	d.t.Helper()
	return must(d.c.Head(ctx, ns, name))
}

func (d *deployment) append(ns, name string, patches ...map[string]any) string {
	d.t.Helper()
	h := d.head(ns, name)
	return must(d.c.Append(ctx, ns, name, h.ID, ops(patches...))).ID
}

func (d *deployment) doc(ns, name string) map[string]any {
	d.t.Helper()
	_, doc := must2(d.c.Load(ctx, ns, name))
	if doc == nil {
		return nil
	}
	m, _ := doc.Value.(map[string]any)
	return m
}

func must2[A, B any](a A, b B, err error) (A, B) {
	if err != nil {
		panic(err)
	}
	return a, b
}

func rev(ns, name, id string) string { return "/r/" + ns + "/" + name + "/rev/" + id }

// fixture is a source deployment with schemas, media and matches:
//
//	schemas/common        a string schema
//	schemas/match         $ref common; x-ref: hero (pinned), related (live), trigger (pinned, key /triggers)
//	media/photo           untyped, two revisions
//	matches/layout        typed, with triggers [{id: t-42}]
//	matches/cup           typed
//	matches/derby         typed: first under match v1, then v2; hero → photo head,
//	                      related → cup (live), trigger → layout#t-42 (pinned)
type fixture struct {
	src                         *deployment
	common, matchV1, matchV2    string
	photo1, photo2, layout, cup string
	derby                       string
}

func newFixture(t *testing.T) *fixture {
	f := &fixture{src: newDeployment(t, stagingOrigin)}
	s := f.src
	s.ns("schemas", nil)
	s.ns("media", nil)
	s.ns("matches", nil)
	f.common = s.create("schemas", "common", map[string]any{"$schema": schema.Dialect2020, "type": "string", "maxLength": 200})
	matchSchema := func(extra map[string]any) map[string]any {
		props := map[string]any{
			"title":    map[string]any{"$ref": rev("schemas", "common", f.common)},
			"hero":     map[string]any{"type": "string", "x-ref": map[string]any{"pinned": true}},
			"related":  map[string]any{"type": "array", "items": map[string]any{"type": "string", "x-ref": map[string]any{}}},
			"trigger":  map[string]any{"type": "string", "x-ref": map[string]any{"pinned": true, "key": "/triggers"}},
			"triggers": map[string]any{"type": "array"},
		}
		for k, v := range extra {
			props[k] = v
		}
		return map[string]any{"$schema": schema.Dialect2020, "type": "object", "properties": props}
	}
	f.matchV1 = s.create("schemas", "match", matchSchema(nil))
	f.matchV2 = must(s.c.Append(ctx, "schemas", "match", f.matchV1,
		ops(op("add", "/properties/score", map[string]any{"type": "string"})))).ID

	f.photo1 = s.create("media", "photo", map[string]any{"url": "https://img.example/1.jpg"})
	f.photo2 = s.append("media", "photo", op("replace", "/url", "https://img.example/2.jpg"))
	f.layout = s.create("matches", "layout", map[string]any{"$schema": rev("schemas", "match", f.matchV2), "title": "Layout",
		"triggers": []any{map[string]any{"id": "t-42", "name": "door"}}})
	f.cup = s.create("matches", "cup", map[string]any{"$schema": rev("schemas", "match", f.matchV2), "title": "Cup"})
	s.create("matches", "derby", map[string]any{"$schema": rev("schemas", "match", f.matchV1), "title": "Derby"})
	f.derby = s.append("matches", "derby",
		op("replace", "/$schema", rev("schemas", "match", f.matchV2)),
		op("add", "/score", "0-0"),
		op("add", "/hero", rev("media", "photo", f.photo2)),
		op("add", "/related", []any{"/r/matches/cup"}),
		op("add", "/trigger", rev("matches", "layout", f.layout)+"#t-42"))
	return f
}

func (f *fixture) export(t *testing.T, opt bundle.ExportOptions) ([]byte, *bundle.ExportPlan, *bundle.Summary) {
	t.Helper()
	var buf bytes.Buffer
	p, s, err := bundle.Export(ctx, f.src.c, &buf, opt)
	if err != nil {
		t.Fatal(err)
	}
	return buf.Bytes(), p, s
}

func importB(t *testing.T, d *deployment, b []byte, opt bundle.ImportOptions) *bundle.Report {
	t.Helper()
	if opt.Mode == "" {
		opt.Mode = bundle.Atomic
	}
	opt.CreateNamespaces = true
	rep, err := bundle.Import(ctx, d.c, bundle.BytesOpener(b), opt)
	if err != nil {
		t.Fatalf("import: %v\nreport: %+v", err, rep)
	}
	return rep
}
