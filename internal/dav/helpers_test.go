package dav_test

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/dav"
	"github.com/middle-management/patchlog/internal/jsonv"
)

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

// env is a core (clienttest) and a WebDAV server in front of it.
type env struct {
	t    *testing.T
	ctx  context.Context
	s    *clienttest.Server
	c    *client.Client // writes "as someone else", straight to the core
	dav  *httptest.Server
	pw   string // the Basic password requests send
	opt  dav.Options
	flat []string
}

// newEnv starts a development core (no authentication) with namespaces
// created as public, and a local-mode WebDAV server serving flat and
// catalogs.
func newEnv(t *testing.T, flat, catalogs []string, nsDocs map[string]map[string]any, with ...func(*clienttest.Options, *dav.Options)) *env {
	t.Helper()
	var copt clienttest.Options
	var dopt dav.Options
	for _, f := range with {
		f(&copt, &dopt)
	}
	s := clienttest.New(t, copt)
	e := &env{t: t, ctx: context.Background(), s: s, c: s.Client(t, client.WithAuthor("other")), pw: "secret"}
	for _, ns := range append(append([]string{}, flat...), catalogs...) {
		doc := map[string]any{"read": "public"}
		for k, v := range nsDocs[ns] {
			doc[k] = v
		}
		if _, err := e.c.CreateNamespace(e.ctx, ns, doc); err != nil {
			t.Fatal(err)
		}
	}
	dopt.Client, dopt.Namespaces, dopt.Catalogs, dopt.Password = s.Client(t, client.WithAuthor("dav")), flat, catalogs, e.pw
	if dopt.Logf == nil {
		dopt.Logf = t.Logf
	}
	srv, err := dav.New(dopt)
	if err != nil {
		t.Fatal(err)
	}
	e.dav = httptest.NewServer(srv)
	t.Cleanup(e.dav.Close)
	e.opt = dopt
	return e
}

// another is a second WebDAV server over e's core, as e's was set up: its
// user isn't e's, so it reads what e's user wrote as everyone does.
func (e *env) another() *env {
	e.t.Helper()
	srv, err := dav.New(e.opt)
	if err != nil {
		e.t.Fatal(err)
	}
	o := *e
	o.dav = httptest.NewServer(srv)
	e.t.Cleanup(o.dav.Close)
	return &o
}

type resp struct {
	status int
	header http.Header
	body   string
}

// do sends a WebDAV request with e's password; hdr are name, value pairs.
func (e *env) do(method, p, body string, hdr ...string) resp {
	return e.doAs(e.pw, method, p, body, hdr...)
}

func (e *env) doAs(pw, method, p, body string, hdr ...string) resp {
	e.t.Helper()
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, e.dav.URL+p, r)
	if err != nil {
		e.t.Fatal(err)
	}
	if pw != "" {
		req.SetBasicAuth("someone", pw)
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		v := hdr[i+1]
		if hdr[i] == "Destination" && strings.HasPrefix(v, "/") {
			v = e.dav.URL + v
		}
		req.Header.Set(hdr[i], v)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return resp{status: res.StatusCode, header: res.Header, body: string(b)}
}

// expect fails unless r has status.
func (e *env) expect(r resp, status int, what string) resp {
	e.t.Helper()
	if r.status != status {
		e.t.Fatalf("%s: %d %s, want %d", what, r.status, r.body, status)
	}
	return r
}

// entry is one response of a PROPFIND.
type entry struct {
	size, etag, ctype, modified string
	dir                         bool
}

type multistatus struct {
	Responses []struct {
		Href     string `xml:"href"`
		Propstat []struct {
			Prop struct {
				Length     string    `xml:"getcontentlength"`
				ETag       string    `xml:"getetag"`
				Type       string    `xml:"getcontenttype"`
				Modified   string    `xml:"getlastmodified"`
				Collection *struct{} `xml:"resourcetype>collection"`
			} `xml:"prop"`
			Status string `xml:"status"`
		} `xml:"propstat"`
	} `xml:"response"`
}

// propfind lists p (Depth 1 unless depth says otherwise) by path.
func (e *env) propfind(p string, depth ...string) map[string]entry {
	e.t.Helper()
	d := "1"
	if len(depth) > 0 {
		d = depth[0]
	}
	r := e.expect(e.do("PROPFIND", p, "", "Depth", d), 207, "PROPFIND "+p)
	var ms multistatus
	if err := xml.Unmarshal([]byte(r.body), &ms); err != nil {
		e.t.Fatalf("PROPFIND %s: %v\n%s", p, err, r.body)
	}
	out := map[string]entry{}
	for _, x := range ms.Responses {
		h, err := url.PathUnescape(x.Href)
		if err != nil {
			e.t.Fatal(err)
		}
		var en entry
		for _, ps := range x.Propstat {
			if !strings.Contains(ps.Status, "200") {
				continue
			}
			en.size, en.etag, en.ctype, en.modified = ps.Prop.Length, ps.Prop.ETag, ps.Prop.Type, ps.Prop.Modified
			en.dir = ps.Prop.Collection != nil
		}
		out[h] = en
	}
	return out
}

// names are the entries of a listing of dir, without dir itself.
func names(m map[string]entry, dir string) []string {
	var out []string
	for h := range m {
		if h != dir {
			out = append(out, strings.TrimPrefix(h, dir))
		}
	}
	sort.Strings(out)
	return out
}

// load reads ns/name's head and document from the core.
func (e *env) load(ns, name string) (*client.Head, any) {
	e.t.Helper()
	h, d, err := e.c.Load(e.ctx, ns, name)
	if err != nil {
		e.t.Fatal(err)
	}
	if d == nil {
		return h, nil
	}
	return h, d.Value
}

// lastEntry is the newest log entry of ns/name.
func (e *env) lastEntry(ns, name string) client.LogEntry {
	e.t.Helper()
	log := must(e.c.Log(e.ctx, ns, name, "", ""))
	return log[len(log)-1]
}

func (e *env) create(ns, name string, doc any) string {
	e.t.Helper()
	return must(e.c.CreateDoc(e.ctx, ns, name, doc)).ID
}

// rendered is how a document reads over WebDAV.
func rendered(v any) string {
	var b bytes.Buffer
	if err := json.Indent(&b, jsonv.Canonical(must(client.ToValue(v))), "", "  "); err != nil {
		panic(err)
	}
	return b.String() + "\n"
}

func sameJSON(t *testing.T, got, want any) {
	t.Helper()
	g, w := must(client.ToValue(got)), must(client.ToValue(want))
	if !jsonv.Equal(g, w) {
		t.Fatalf("got %s\nwant %s", jsonv.Canonical(g), jsonv.Canonical(w))
	}
}

func sameStrings(t *testing.T, what string, got, want []string) {
	t.Helper()
	if len(got) == 0 && len(want) == 0 {
		return
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%s: %q, want %q", what, got, want)
	}
}
