package main

// Queries of the derived services: patchlog search asks the search index
// (Addendum A), patchlog tree ls the tree or catalog service (Addendum B).
// Both are read-only HTTP APIs of their own, not the core's, so they go
// through a plain HTTP client (with the telemetry transport) instead of
// internal/client. A query is answered by a redirect from the head pointer
// to a result pinned at a checkpoint (§A.4, §A.5), which the client
// follows, keeping the grant: private namespaces redirect into the reader's
// own subject set, /{ns}/g/{gs}/at/{at}.
//
// Results of sealed and end-to-end namespaces are served sealed and are
// printed as served, without their keys.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/middle-management/patchlog/internal/telemetry"
)

// serviceArgs are the flags of the commands that read a derived service.
type serviceArgs struct {
	Bearer     string   `arg:"--bearer,env:PATCHLOG_BEARER" placeholder:"GRANT" help:"grant sent as Authorization: Bearer"`
	BearerFile string   `arg:"--bearer-file,env:PATCHLOG_BEARER_FILE" placeholder:"FILE" help:"file holding --bearer, so the grant is not in the process arguments or the shell history (exclusive with --bearer)"`
	Min        []string `arg:"--min,separate" placeholder:"NS:NS_ID" help:"wait until the service has reached this namespace entry (the id a write printed), for reading your own writes; repeatable"`
	JSON       bool     `arg:"--json" help:"print the answer as served"`
}

// serviceClient is the HTTP client of the derived services: redirects are
// followed (same host keeps the Authorization header), and there is no
// timeout beyond ctx, since ?min= waits for the service.
var serviceClient = &http.Client{Transport: telemetry.Transport(nil)}

// serviceGet reads path?query at the service at base, following redirects,
// and returns the answer's body. what names the service in errors.
func serviceGet(ctx context.Context, what, base, path string, q url.Values, bearer string) ([]byte, error) {
	u := strings.TrimRight(base, "/") + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", what, err)
	}
	req.Header.Set("Accept", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	r, err := serviceClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", what, err)
	}
	defer r.Body.Close()
	b, err := io.ReadAll(io.LimitReader(r.Body, 64<<20))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", what, err)
	}
	if r.StatusCode != http.StatusOK {
		return nil, serviceError(what, r, b)
	}
	return b, nil
}

// serviceError describes a non-200 answer: its message, with the status
// and code, and for a 400 refusing mins the mins it names.
func serviceError(what string, r *http.Response, body []byte) error {
	var e struct {
		Code    string   `json:"code"`
		Message string   `json:"message"`
		Min     []string `json:"min"`
	}
	msg := strings.TrimSpace(string(body))
	if json.Unmarshal(body, &e) == nil && e.Message != "" {
		msg = e.Message
		if len(e.Min) > 0 {
			msg += " (" + strings.Join(e.Min, ", ") + ")"
		}
	}
	if msg == "" {
		msg = http.StatusText(r.StatusCode)
	}
	code := ""
	if e.Code != "" {
		code = " " + e.Code
	}
	err := fmt.Errorf("%s: %s (%d%s)", what, msg, r.StatusCode, code)
	if r.StatusCode == http.StatusServiceUnavailable {
		err = fmt.Errorf("%w; try again shortly", err)
	}
	return err
}

// serviceURL is a service's base URL as given, with http:// if it has no
// scheme (localhost:8081).
func serviceURL(v string) string {
	if !strings.Contains(v, "://") {
		v = "http://" + v
	}
	return v
}

// printServed writes a served answer, with a final newline.
func printServed(out io.Writer, b []byte) error {
	_, err := fmt.Fprintln(out, strings.TrimRight(string(b), "\n"))
	return err
}

// searchCmd is patchlog search NS QUERY….
type searchCmd struct {
	serviceArgs
	Index  string   `arg:"--index,env:PATCHLOG_INDEX" default:"http://localhost:8081" placeholder:"URL" help:"search index service (patchlog index)"`
	Facet  []string `arg:"--facet,separate" placeholder:"PATH=VALUE" help:"only documents with this facet value at a JSON Pointer path, e.g. /league=allsvenskan; repeatable"`
	Sort   string   `arg:"--sort" placeholder:"[-]PATH[,…]" help:"order by these sort paths, a leading - descending, e.g. -/kickoff,/title"`
	Limit  int      `arg:"--limit" placeholder:"N" help:"hits a page (default: the service's, 20)"`
	At     string   `arg:"--at" placeholder:"NS_ID" help:"read the result at this checkpoint, as printed with a next page"`
	After  string   `arg:"--after" placeholder:"TOKEN" help:"the page after the one whose next this is, as printed on stderr (with --at)"`
	All    bool     `arg:"--all" help:"follow every page"`
	Counts []string `arg:"--counts,separate" placeholder:"PATH" help:"also count the hits by their values at these facet paths (repeatable or comma-separated)"`
	Fields []string `arg:"--fields,separate" placeholder:"PATH" help:"show these text-indexed fields in each hit (repeatable or comma-separated)"`
	Schema string   `arg:"--schema" placeholder:"REF" help:"only documents of this $schema, or /r/NS/NAME for any revision of it"`
	Ref    string   `arg:"--ref" placeholder:"/r/NS/NAME" help:"only documents that reference this resource through a schema's x-ref (who uses this?, §A.4)"`
	NS     string   `arg:"positional,required"`
	Query  []string `arg:"positional" placeholder:"QUERY" help:"words to search for in the text-indexed fields (as q: * is a wildcard)"`
}

func (a *searchCmd) run(string) { runClient(a) }

func (a *searchCmd) values() (url.Values, error) {
	q := url.Values{}
	if s := strings.Join(a.Query, " "); s != "" {
		q.Set("q", s)
	}
	for _, f := range a.Facet {
		path, val, ok := strings.Cut(f, "=")
		if !ok || path == "" {
			return nil, fmt.Errorf("--facet %q: want PATH=VALUE", f)
		}
		q.Add("facet["+path+"]", val)
	}
	set := func(k, v string) {
		if v != "" {
			q.Set(k, v)
		}
	}
	set("sort", a.Sort)
	set("after", a.After)
	set("schema", a.Schema)
	set("ref", a.Ref)
	set("counts", strings.Join(splitList(a.Counts...), ","))
	set("fields", strings.Join(splitList(a.Fields...), ","))
	if a.Limit < 0 {
		return nil, errors.New("--limit must be positive")
	}
	if a.Limit > 0 {
		q.Set("limit", fmt.Sprint(a.Limit))
	}
	for _, m := range a.Min {
		q.Add("min", m)
	}
	return q, nil
}

func (a *searchCmd) exec(ctx context.Context, out, errw io.Writer) error {
	q, err := a.values()
	if err != nil {
		return err
	}
	at := a.At
	for first := true; ; first = false {
		path := "/" + a.NS
		if at != "" {
			path += "/at/" + at
		}
		b, err := serviceGet(ctx, "index", serviceURL(a.Index), path, q, a.Bearer)
		if err != nil {
			return err
		}
		if a.JSON {
			if err := printServed(out, b); err != nil {
				return err
			}
		}
		var res struct {
			At     string                    `json:"at"`
			Hits   []map[string]any          `json:"hits"`
			Next   string                    `json:"next"`
			Counts map[string]map[string]int `json:"counts"`
		}
		if err := json.Unmarshal(b, &res); err != nil {
			return fmt.Errorf("index: answer isn't JSON: %w", err)
		}
		if !a.JSON {
			for _, h := range res.Hits {
				fmt.Fprintln(out, hitLine(h))
			}
			paths := make([]string, 0, len(res.Counts))
			for p := range res.Counts {
				paths = append(paths, p)
			}
			sort.Strings(paths)
			for _, p := range paths {
				if first { // over every hit, whatever the page
					fmt.Fprintf(out, "counts %s  %s\n", p, countsLine(res.Counts[p]))
				}
			}
		}
		if res.Next == "" {
			return nil
		}
		if !a.All {
			fmt.Fprintf(errw, "more: --at %s --after %s\n", res.At, res.Next)
			return nil
		}
		// The next page is read at the checkpoint of this one (§A.4).
		at = res.At
		q.Set("after", res.Next)
		q.Del("min")
	}
}

// hitFixed are the members of a hit that aren't values of its document.
var hitFixed = map[string]bool{"resource": true, "id": true, "url": true, "score": true, "schema": true, "refs": true, "self": true, "sealed": true}

// hitLine is a hit as one line: its resource name, then its values at the
// indexed paths, path=value[,value]….
func hitLine(h map[string]any) string {
	name, _ := h["resource"].(string)
	var keys []string
	for k := range h {
		if !hitFixed[k] {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	parts := []string{name}
	for _, k := range keys {
		parts = append(parts, k+"="+valueList(h[k]))
	}
	if refs, ok := h["refs"].([]any); ok {
		for _, r := range refs {
			if m, ok := r.(map[string]any); ok {
				parts = append(parts, fmt.Sprintf("ref %v=%v", m["path"], m["ref"]))
			}
		}
	}
	if h["self"] == true {
		parts = append(parts, "(self)")
	}
	if _, ok := h["sealed"]; ok {
		parts = append(parts, "(sealed)")
	}
	return strings.Join(parts, "  ")
}

// valueList is a hit's values at a path, comma-separated.
func valueList(v any) string {
	vs, ok := v.([]any)
	if !ok {
		return fmt.Sprint(v)
	}
	s := make([]string, len(vs))
	for i, x := range vs {
		if str, ok := x.(string); ok {
			s[i] = str
		} else {
			b, _ := json.Marshal(x)
			s[i] = string(b)
		}
	}
	return strings.Join(s, ",")
}

// countsLine is the counts of one path: value=hits, most hits first.
func countsLine(m map[string]int) string {
	vals := make([]string, 0, len(m))
	for v := range m {
		vals = append(vals, v)
	}
	sort.Slice(vals, func(i, j int) bool {
		if m[vals[i]] != m[vals[j]] {
			return m[vals[i]] > m[vals[j]]
		}
		return vals[i] < vals[j]
	})
	parts := make([]string, len(vals))
	for i, v := range vals {
		parts[i] = fmt.Sprintf("%s=%d", v, m[v])
	}
	return strings.Join(parts, " ")
}

// treeLsCmd is patchlog tree ls CATALOG [PATH].
type treeLsCmd struct {
	serviceArgs
	Tree    string `arg:"--tree,env:PATCHLOG_TREE" default:"http://localhost:8082" placeholder:"URL" help:"tree or catalog service (patchlog tree)"`
	Limit   int    `arg:"--limit" placeholder:"N" help:"children a page (default: the service's, 100; at most 1000)"`
	At      string `arg:"--at" placeholder:"NS_ID" help:"read at this combined checkpoint, as printed with a next page"`
	After   string `arg:"--after" placeholder:"TOKEN" help:"the page after the one whose next this is, as printed on stderr (with --at)"`
	All     bool   `arg:"--all" help:"follow every page"`
	Catalog string `arg:"positional,required" placeholder:"CATALOG"`
	Path    string `arg:"positional" placeholder:"PATH" help:"the folder to list: a node name, a reference (/r/CATALOG/NAME, /r/NS/NAME of an item), or a path of titles from the root of a file tree (docs/2026/notes); default the roots"`
}

func (a *treeLsCmd) run(string) { runClient(a) }

func (a *treeLsCmd) exec(ctx context.Context, out, errw io.Writer) error {
	base, cat, at := serviceURL(a.Tree), "/"+a.Catalog, a.At
	get := func(op string, q url.Values) ([]byte, error) {
		for _, m := range a.Min {
			q.Add("min", m)
		}
		path := cat
		if at != "" {
			path += "/at/" + at
		}
		return serviceGet(ctx, "tree", base, path+"/"+op, q, a.Bearer)
	}
	if a.Limit < 0 {
		return errors.New("--limit must be positive")
	}
	if a.Path == "" {
		b, err := get("roots", url.Values{})
		if err != nil {
			return err
		}
		if a.JSON {
			return printServed(out, b)
		}
		var res struct {
			Roots []map[string]any `json:"roots"`
		}
		if err := json.Unmarshal(b, &res); err != nil {
			return fmt.Errorf("tree: answer isn't JSON: %w", err)
		}
		for _, e := range res.Roots {
			fmt.Fprintln(out, entryLine(e))
		}
		return nil
	}
	node := a.Path
	if !strings.HasPrefix(node, "/r/") && strings.Contains(node, "/") {
		// A path of titles (§B.5 lookup).
		b, err := get("lookup", url.Values{"path": {strings.Trim(node, "/")}})
		if err != nil {
			return err
		}
		var res struct {
			Node map[string]any `json:"node"`
		}
		if err := json.Unmarshal(b, &res); err != nil {
			return fmt.Errorf("tree: answer isn't JSON: %w", err)
		}
		if node, _ = res.Node["name"].(string); node == "" {
			return fmt.Errorf("tree: no node at %s", a.Path)
		}
	}
	q := url.Values{"of": {node}}
	if a.Limit > 0 {
		q.Set("limit", fmt.Sprint(a.Limit))
	}
	if a.After != "" {
		q.Set("after", a.After)
	}
	for {
		b, err := get("children", q)
		if err != nil {
			return err
		}
		if a.JSON {
			if err := printServed(out, b); err != nil {
				return err
			}
		}
		var res struct {
			At       string           `json:"at"`
			Children []map[string]any `json:"children"`
			Total    int              `json:"total"`
			Next     string           `json:"next"`
		}
		if err := json.Unmarshal(b, &res); err != nil {
			return fmt.Errorf("tree: answer isn't JSON: %w", err)
		}
		if !a.JSON {
			for _, e := range res.Children {
				fmt.Fprintln(out, entryLine(e))
			}
		}
		if res.Next == "" {
			return nil
		}
		nq, err := url.ParseQuery(strings.TrimPrefix(res.Next, "?"))
		if err != nil {
			return fmt.Errorf("tree: malformed next %q", res.Next)
		}
		if !a.All {
			fmt.Fprintf(errw, "more (%d in all): --at %s --after %s\n", res.Total, res.At, nq.Get("after"))
			return nil
		}
		at = res.At // the next page is read at this one's checkpoint
		q = nq
	}
}

// entryLine is a listing entry as one line: its kind, name and title.
func entryLine(e map[string]any) string {
	kind, _ := e["kind"].(string)
	name, _ := e["name"].(string)
	title, _ := e["title"].(string)
	if _, ok := e["sealed"]; ok && title == "" {
		title = "(sealed)"
	}
	return strings.TrimRight(fmt.Sprintf("%-6s  %s  %s", kind, name, title), " ")
}
