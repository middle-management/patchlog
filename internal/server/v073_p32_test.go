package server

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	plclient "github.com/middle-management/patchlog/internal/client"
)

// P32 REMOTE-LEVELS: a remote branch follows its base's level and read
// (§G.5.2), answers 502 upstream where its server lacks the level (§1),
// and judges its own config writes by the base's current document.

// keyed is a client of e that opens sealed answers (dev mode: raw keys).
func (e *tenv) keyed() *plclient.Client {
	e.t.Helper()
	c, err := plclient.New(e.srv.URL, plclient.WithKeys(plclient.NewKeys(nil)), plclient.WithAuthor("test"))
	if err != nil {
		e.t.Fatal(err)
	}
	return c
}

// configOf is a namespace's current document, opened if it is sealed.
func (e *tenv) configOf(ns string) map[string]any {
	e.t.Helper()
	d, err := e.keyed().NSDoc(context.Background(), ns, e.nsHead(ns))
	if err != nil {
		e.t.Fatalf("%s: %v", ns, err)
	}
	return d.Value
}

// lastEntry is a namespace's newest log entry, opened if it is sealed.
func (e *tenv) lastEntry(ns string) plclient.NSEntry {
	e.t.Helper()
	lg, err := e.keyed().NSLog(context.Background(), ns, e.nsHead(ns), "")
	if err != nil || len(lg) == 0 {
		e.t.Fatalf("%s: %v", ns, err)
	}
	return lg[len(lg)-1]
}

func levelOf(doc map[string]any) string {
	enc, _ := doc["encryption"].(map[string]any)
	l, _ := enc["level"].(string)
	return l
}

// proxyA serves A through a proxy: intercept answers a request itself when
// it returns true; rewrite, if set, rewrites the body of answers whose
// path is rewritePath.
func proxyA(t *testing.T, a *tenv, intercept func(w http.ResponseWriter, r *http.Request) bool, rewritePath string, rewrite func([]byte) []byte) string {
	t.Helper()
	p := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if intercept != nil && intercept(w, r) {
			return
		}
		hr, _ := http.NewRequest(r.Method, a.srv.URL+r.URL.RequestURI(), r.Body)
		hr.Header = r.Header.Clone()
		res, err := client.Do(hr)
		if err != nil {
			w.WriteHeader(502)
			return
		}
		defer res.Body.Close()
		body, _ := io.ReadAll(res.Body)
		if rewrite != nil && r.URL.Path == rewritePath {
			body = rewrite(body)
		}
		for k, v := range res.Header {
			if k != "Content-Length" {
				w.Header()[k] = v
			}
		}
		w.WriteHeader(res.StatusCode)
		w.Write(body)
	}))
	t.Cleanup(p.Close)
	return p.URL
}
