package server

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/middle-management/patchlog/internal/core"
	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/sig"
)

// Request shape: reading bodies, media types, preconditions, gestures,
// names and batches (§3.1, §6.2, §7, §7.2, §7.5).

// sourceCreds are Source-Authorization's (§7.8): the grant a copy's or a
// batch's source is read with.
// The header may be repeated, or its values joined with commas by an
// intermediary (§6.1): every Bearer grant in it is kept.
func sourceCreds(r *http.Request) []core.Credentials {
	var out []core.Credentials
	for _, h := range r.Header.Values("Source-Authorization") {
		for _, a := range strings.Split(h, ",") {
			a = strings.TrimSpace(a)
			if strings.HasPrefix(a, "Bearer ") {
				if g := strings.TrimSpace(a[len("Bearer "):]); g != "" {
					out = append(out, core.Credentials{Bearer: g})
				}
			}
		}
	}
	return out
}

func creds(r *http.Request) core.Credentials {
	c := core.Credentials{Author: r.Header.Get("X-Author")}
	if a := r.Header.Get("Authorization"); strings.HasPrefix(a, "Bearer ") {
		c.Bearer = strings.TrimSpace(a[len("Bearer "):])
	}
	if eg, ok := r.Context().Value(edgeGrantKey{}).(*core.EdgeGrant); ok {
		c.Edge = eg // an edge-grant cookie (§C.5), GET and HEAD only
	}
	return c
}

// bodyLimit is what the refusal of an oversized body names (§6.6): the
// limit's key and its value. Without a key, the bound is no limit of §6.6.
type bodyLimit struct {
	key string
	max int
}

// noLimit bounds a body that no limit of §6.6 covers.
var noLimit = bodyLimit{}

// readJSON reads and strictly parses an I-JSON body (§3.1) of at most
// bound bytes, noncharacters refused (jsonv.ParseInput). A longer one is
// 413 limit, naming lim, with measured the bytes read, a lower bound
// (§6.6), or, for a body no limit covers, 400.
func readJSON(r *http.Request, bound int, lim bodyLimit) (any, error) {
	body, err := io.ReadAll(io.LimitReader(r.Body, int64(bound)+1))
	if err != nil {
		return nil, badInput("could not read body")
	}
	if len(body) > bound {
		return nil, tooLarge(len(body), lim)
	}
	v, err := jsonv.ParseInput(body)
	if err != nil {
		return nil, badInput(err.Error())
	}
	return v, nil
}

// tooLarge refuses a body the server stopped reading after n bytes.
func tooLarge(n int, lim bodyLimit) error {
	if lim.key == "" {
		return badInput(fmt.Sprintf("the body is larger than %d bytes", n-1))
	}
	return &core.Error{Status: 413, Body: map[string]any{"code": "limit", "message": "request too large",
		"limit": lim.key, "measured": int64(n), "max": int64(lim.max)}}
}

// patchBody bounds a PATCH-type body, read before step 1 of §6.2, so by
// the deployment's maximums (§6.6): four times the larger of patchSetSize
// and documentSize, room for JSON text laid out at length. A longer body
// names documentSize with the deployment's maximum, for a resource patch
// and equally for a config write, a namespace's creation and a branch's
// creation, whose bodies are cut off as a resource PATCH's are (§6.6).
func (s *Server) patchBody() (int, bodyLimit) {
	l := s.e.Limits()
	return 4 * max(l.PatchSetSize, l.DocumentSize), bodyLimit{"documentSize", l.DocumentSize}
}

// writeHeaders checks a write's request-shape headers before step 1
// (§6.2): while authentication is disabled, an X-Author (§7.2); and a
// Signature header only where signed, on a resource PATCH or DELETE,
// which signature() reads (§C.3.1). Each is 400.
func (s *Server) writeHeaders(r *http.Request, signed bool) error {
	if s.e.AuthMode() == "disabled" && strings.TrimSpace(r.Header.Get("X-Author")) == "" {
		return badInput("a write needs X-Author while authentication is disabled (§7.2)")
	}
	if _, has := r.Header["Signature"]; has && !signed {
		return badInput("the Signature header covers a single PATCH or DELETE of a resource, and is 400 on any other write (§C.3.1)")
	}
	return nil
}

// JSON request bodies' media types (§7.2): JSON Patch for resource and
// namespace patches, JSON for every other body.
const (
	jsonPatchType = "application/json-patch+json"
	jsonType      = "application/json"
)

// requireType answers 415 unsupported_type unless the request's
// Content-Type is want, compared as a media type (jsonv.MediaType): a
// request-shape error, checked before the body is read (§6.2, §7.2).
func requireType(r *http.Request, want string) error {
	if jsonv.MediaType(r.Header.Get("Content-Type"), want) {
		return nil
	}
	return &core.Error{Status: 415, Body: map[string]any{"code": "unsupported_type", "message": "use " + want + " (§7.2)"}}
}

// etag parses a single strong ETag from If-Match / If-None-Match.
func etag(h string) (string, bool) {
	h = strings.TrimSpace(h)
	if len(h) >= 2 && h[0] == '"' && h[len(h)-1] == '"' {
		return h[1 : len(h)-1], true
	}
	return "", false
}

// precond is a write's precondition (§7.2).
type precond struct {
	ifMatch     string
	ifNoneMatch bool
}

// sent reports whether the write carried a precondition.
func (p precond) sent() bool { return p.ifMatch != "" || p.ifNoneMatch }

// preconditions reads a write's If-Match and If-None-Match (§7, §7.2):
// each, if present, once; If-Match one strong entity tag around an id in
// text form, so never *, a weak tag, a list or a sealed ETag's "{id}.{e}";
// If-None-Match only *; never both. Anything else, an empty value
// included, is 400, a request-shape error answered before step 1 (§6.2).
// Whether the write takes the precondition it carries is the core's 428.
func preconditions(r *http.Request) (precond, error) {
	var p precond
	if vs := r.Header.Values("If-None-Match"); len(vs) > 0 {
		if len(vs) > 1 || strings.TrimSpace(vs[0]) != "*" {
			return p, badInput("If-None-Match must be * (§7.2)")
		}
		p.ifNoneMatch = true
	}
	if vs := r.Header.Values("If-Match"); len(vs) > 0 {
		t, ok := etag(vs[0])
		if len(vs) > 1 || !ok || !validID(t) {
			return p, badInput(`If-Match must be one strong entity tag around an id, "{id}" (§7, §7.2)`)
		}
		p.ifMatch = t
	}
	if p.ifMatch != "" && p.ifNoneMatch {
		return p, badInput("both If-Match and If-None-Match (§7.2)")
	}
	return p, nil
}

// errMessage is an error's message, as a 400 carries it.
func errMessage(err error) string {
	var ae *core.Error
	if errors.As(err, &ae) {
		if m, ok := ae.Body["message"].(string); ok {
			return m
		}
	}
	return err.Error()
}

// gestures reads a write's Gesture and Undoes headers (§7.2): each, if
// present, once, as a gesture id (26 base32 characters), otherwise 400.
func gestures(r *http.Request) (gesture, undoes string, err error) {
	read := func(h string) (string, error) {
		vs := r.Header.Values(h)
		switch {
		case len(vs) == 0:
			return "", nil
		case len(vs) > 1 || !core.ValidGesture(strings.TrimSpace(vs[0])):
			return "", badInput(h + " must be one gesture id: 26 base32 characters")
		}
		return strings.TrimSpace(vs[0]), nil
	}
	if gesture, err = read("Gesture"); err != nil {
		return "", "", err
	}
	undoes, err = read("Undoes")
	return gesture, undoes, err
}

// signature reads a single write's Signature header (§C.3.1): absent, or
// once, "<alg>:<kid>:<sig>" with an 86-character base64url sig. Anything
// else, an empty value included, is 400, a request-shape error answered
// before step 1 (§6.2).
func signature(r *http.Request) (string, error) {
	vs := r.Header.Values("Signature")
	switch {
	case len(vs) == 0:
		return "", nil
	case len(vs) > 1:
		return "", badInput("Signature given more than once (§C.3.1)")
	}
	if _, err := sig.ParseInput(vs[0]); err != nil {
		return "", badInput("malformed Signature: " + err.Error() + " (§C.3.1)")
	}
	return vs[0], nil
}

// setGestures sets a write response's Gesture and Undoes headers: what the
// entry recorded, which for an idempotent retry may differ from what the
// retry sent (§7.2).
func setGestures(w http.ResponseWriter, e *core.LogEntry) {
	if e == nil {
		return
	}
	if e.Gesture != "" {
		w.Header().Set("Gesture", e.Gesture)
	}
	if e.Undoes != "" {
		w.Header().Set("Undoes", e.Undoes)
	}
}

func validNames(ns, name string) error {
	if !core.ValidNSName(ns) {
		return badInput("invalid namespace name")
	}
	if name != "" && !core.ValidResourceName(name) {
		return badInput("invalid resource name")
	}
	return nil
}

// parseBatch reads a batch body (§7.5). hdr are the batch's Gesture and
// Undoes headers, which stand for its own gesture and undoes members.
func parseBatch(body any, hdr gestureDefaults) ([]core.Item, *core.ConfigChange, any, error) {
	m, ok := body.(map[string]any)
	if !ok {
		return nil, nil, nil, badInput("batch body must be an object")
	}
	// The batch's own gesture and undoes are defaults for every step
	// (§7.5), as an item's are for its steps; each may come as a member or
	// a header, not both (400).
	batchG := hdr
	for k, v := range m {
		switch k {
		case "items", "config", "source":
		case "gesture", "undoes":
			if k == "gesture" && hdr.gesture != "" || k == "undoes" && hdr.undoes != "" {
				return nil, nil, nil, badInput(fmt.Sprintf("the batch's %s is given both as a header and in the body (§7.5)", k))
			}
			if err := batchG.set(k, v, "batch"); err != nil {
				return nil, nil, nil, err
			}
		default:
			return nil, nil, nil, badInput("unknown member " + k)
		}
	}
	var items []core.Item
	if iv, has := m["items"]; has {
		arr, ok := iv.([]any)
		if !ok {
			return nil, nil, nil, badInput("items must be an array")
		}
		for i, x := range arr {
			o, ok := x.(map[string]any)
			if !ok {
				return nil, nil, nil, badInput(fmt.Sprintf("item %d must be an object", i))
			}
			it := core.Item{}
			itemG := batchG
			var steps []any
			for k, v := range o {
				switch k {
				case "resource":
					it.Resource, _ = v.(string)
				case "ifMatch":
					s, ok := v.(string)
					if !ok || !validID(s) {
						return nil, nil, nil, badInput(fmt.Sprintf("item %d: ifMatch must be an id in text form (§7, §7.5)", i))
					}
					it.IfMatch = s
				case "ifNoneMatch":
					if v != "*" {
						return nil, nil, nil, badInput(fmt.Sprintf("item %d: ifNoneMatch must be \"*\"", i))
					}
					it.IfNoneMatch = true
				case "steps":
					if steps, ok = v.([]any); !ok {
						return nil, nil, nil, badInput(fmt.Sprintf("item %d: steps must be an array", i))
					}
				case "gesture", "undoes":
					if err := itemG.set(k, v, fmt.Sprintf("item %d", i)); err != nil {
						return nil, nil, nil, err
					}
				default:
					return nil, nil, nil, badInput(fmt.Sprintf("item %d: unknown member %s", i, k))
				}
			}
			// Two preconditions are the batch's own 400, never an item's
			// report (§7.5, §6.2).
			if it.IfMatch != "" && it.IfNoneMatch {
				return nil, nil, nil, badInput(fmt.Sprintf("item %d: both ifMatch and ifNoneMatch (§7.5)", i))
			}
			// The steps after the item's members, whose defaults they take.
			for j, st := range steps {
				step, err := parseStep(st, itemG, fmt.Sprintf("item %d, step %d", i, j))
				if err != nil {
					return nil, nil, nil, err
				}
				it.Steps = append(it.Steps, step)
			}
			items = append(items, it)
		}
	}
	var cc *core.ConfigChange
	if cv, has := m["config"]; has {
		o, ok := cv.(map[string]any)
		if !ok {
			return nil, nil, nil, badInput("config must be an object")
		}
		cc = &core.ConfigChange{Patches: o["patches"]}
		if v, has := o["ifMatch"]; has {
			s, ok := v.(string)
			if !ok || !validID(s) {
				return nil, nil, nil, badInput("config: ifMatch must be a config id in text form (§7, §7.5)")
			}
			cc.IfMatch = s
		}
		if cc.Patches == nil {
			return nil, nil, nil, badInput("config needs patches")
		}
	}
	if sv, has := m["source"]; has {
		if err := checkSource(sv, items); err != nil {
			return nil, nil, nil, err
		}
	}
	return items, cc, m["source"], nil
}

// checkSource answers 400 bad_input, a request-shape error, for a batch
// source of any shape but { origin?, ns, at, bundle?, ids? } (§3.5): ns a
// namespace name; at an ns_id and bundle a digest, in text form; ids an
// object with at most one member per item, named by the item's resource,
// each a text id; origin a canonical origin in the form of §C.3, a
// non-canonical spelling refused rather than normalised, since the source
// is hashed as sent. Whether at is in the chain of ns, and an origin that
// is this deployment's own, are the core's 422 source (§7.5).
func checkSource(v any, items []core.Item) error {
	m, ok := v.(map[string]any)
	if !ok {
		return badInput("source must be an object (§3.5)")
	}
	resources := make(map[string]bool, len(items))
	for _, it := range items {
		resources[it.Resource] = true
	}
	ns, _ := m["ns"].(string)
	at, _ := m["at"].(string)
	if !core.ValidNSName(ns) || !validID(at) {
		return badInput("source needs ns, a namespace name, and at, an ns_id in text form (§3.5)")
	}
	for k, x := range m {
		switch k {
		case "ns", "at":
		case "origin":
			if o, ok := x.(string); !ok || !sig.CanonicalOrigin(o) {
				return badInput("source.origin must be an origin in the form of §C.3: scheme://host[:port], lowercase, default port omitted (§3.5)")
			}
		case "bundle":
			if b, ok := x.(string); !ok || !validID(b) {
				return badInput("source.bundle must be a bundle digest in text form (§3.5, §G.4.1)")
			}
		case "ids":
			o, ok := x.(map[string]any)
			if !ok {
				return badInput("source.ids must be an object (§3.5)")
			}
			for name, id := range o {
				if s, ok := id.(string); !resources[name] || !ok || !validID(s) {
					return badInput(fmt.Sprintf("source.ids member %q must name a resource of the batch's items, with an id in text form (§3.5)", name))
				}
			}
		default:
			return badInput(fmt.Sprintf("unknown source member %q (§3.5)", k))
		}
	}
	return nil
}

// gestureDefaults are the gesture and undoes a batch or item gives its
// steps (§7.5); a step's own values override each.
type gestureDefaults struct{ gesture, undoes string }

// set reads member k ("gesture" or "undoes") of where: a gesture id, or
// 400 (§7.2).
func (d *gestureDefaults) set(k string, v any, where string) error {
	g, ok := v.(string)
	if !ok || !core.ValidGesture(g) {
		return badInput(fmt.Sprintf("%s: %s must be a gesture id: 26 base32 characters", where, k))
	}
	if k == "gesture" {
		d.gesture = g
	} else {
		d.undoes = g
	}
	return nil
}

// parseStep reads one step of a batch item (§7.5): a patch set, "delete",
// or an object with exactly one of "patches" and "delete": true, and
// optional gesture and undoes, which override the defaults d.
func parseStep(v any, d gestureDefaults, where string) (core.Step, error) {
	switch x := v.(type) {
	case string:
		if x == "delete" {
			return core.Step{Delete: true, Gesture: d.gesture, Undoes: d.undoes}, nil
		}
	case []any:
		return core.Step{Patches: x, Gesture: d.gesture, Undoes: d.undoes}, nil
	case map[string]any:
		_, hasP := x["patches"]
		_, hasD := x["delete"]
		if hasP == hasD {
			return core.Step{}, badInput(where + ": a step object has exactly one of patches and delete")
		}
		var step core.Step
		for k, mv := range x {
			switch k {
			case "patches":
				if _, ok := mv.([]any); !ok {
					return core.Step{}, badInput(where + ": patches must be a patch set")
				}
				step.Patches = mv
			case "delete":
				if mv != true {
					return core.Step{}, badInput(where + ": delete must be true")
				}
				step.Delete = true
			case "gesture", "undoes":
				if err := d.set(k, mv, where); err != nil {
					return core.Step{}, err
				}
			case "signature":
				// The step's author signature (§7.5, §C.3.1), in the form
				// of the Signature header.
				sv, ok := mv.(string)
				if !ok || sv == "" {
					return core.Step{}, badInput(where + ": signature must be a string, \"<alg>:<kid>:<sig>\"")
				}
				if _, err := sig.ParseInput(sv); err != nil {
					return core.Step{}, badInput(fmt.Sprintf("%s: malformed signature: %v (§C.3.1)", where, err))
				}
				step.Signature = sv
			default:
				return core.Step{}, badInput(fmt.Sprintf("%s: unknown member %s", where, k))
			}
		}
		step.Gesture, step.Undoes = d.gesture, d.undoes
		return step, nil
	}
	return core.Step{}, badInput(where + ": a step is a patch set, \"delete\" or a step object")
}

// sinceParam is where an event stream starts (§7.3): a Last-Event-ID that
// is present and not empty, which wins over since, else since, empty for
// genesis. checkIDs has checked both.
func sinceParam(r *http.Request) string {
	if id := r.Header.Get("Last-Event-ID"); id != "" {
		return id
	}
	return r.URL.Query().Get("since")
}

// validID reports whether s is an id in text form (§3.2).
func validID(s string) bool {
	_, err := ids.Parse(s)
	return err == nil
}

// idSegments are the path wildcards that hold ids (§3.2): a revision's or
// namespace revision's {id}, a grant's {gid} and a blob's {bid}.
var idSegments = map[string]bool{"{id}": true, "{gid}": true, "{bid}": true}

// checkIDs answers 400 bad_input for an id not in text form (§3.2) in the
// URL routed to pattern, in since, or in an event stream's Last-Event-ID
// (§7): a request-shape error, answered before authentication, the read
// check and an unknown namespace's 404, and never cached (§6.2). A
// well-formed id the namespace lacks stays the core's 404. A gesture
// listing's after is a cursor, not an id, and stays the core's 404 too
// (§7.4). ServeHTTP calls it once the URL is known to be canonical, so its
// segments line up with the pattern's.
func checkIDs(pattern string, r *http.Request) error {
	_, path, _ := strings.Cut(pattern, " ")
	ps, rs := strings.Split(path, "/"), strings.Split(r.URL.Path, "/")
	if len(ps) == len(rs) {
		for i, seg := range ps {
			if idSegments[seg] && !validID(rs[i]) {
				return badInput(fmt.Sprintf("%s %q is not an id in text form (§3.2, §7)", seg, rs[i]))
			}
		}
	}
	if v := r.URL.Query().Get("since"); v != "" && !validID(v) {
		return badInput(fmt.Sprintf("since %q is not an id in text form (§3.2, §7)", v))
	}
	if strings.HasSuffix(pattern, "/events") {
		if v := r.Header.Get("Last-Event-ID"); v != "" && !validID(v) {
			return badInput(fmt.Sprintf("Last-Event-ID %q is not an id in text form (§3.2, §7.3)", v))
		}
	}
	return nil
}
