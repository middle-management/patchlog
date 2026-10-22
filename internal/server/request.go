package server

import (
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/middle-management/patchlog/internal/core"
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

// patchBody bounds the body of a resource or namespace patch set, read
// before step 1 of §6.2, so by the deployment's maximum (§6.6): four times
// its larger bound, room for JSON text laid out at length. lim names
// documentSize for resources, whose whole-document patch sets it bounds,
// and patchSetSize for namespace documents and branches.
func (s *Server) patchBody(resource bool) (int, bodyLimit) {
	l := s.e.Limits()
	lim := bodyLimit{"patchSetSize", l.PatchSetSize}
	if resource {
		lim = bodyLimit{"documentSize", l.DocumentSize}
	}
	return 4 * max(l.PatchSetSize, l.DocumentSize), lim
}

func mediaType(r *http.Request) string {
	ct := r.Header.Get("Content-Type")
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	return strings.TrimSpace(strings.ToLower(ct))
}

// etag parses a single strong ETag from If-Match / If-None-Match.
func etag(h string) (string, bool) {
	h = strings.TrimSpace(h)
	if len(h) >= 2 && h[0] == '"' && h[len(h)-1] == '"' {
		return h[1 : len(h)-1], true
	}
	return "", false
}

type precond struct {
	ifMatch     string
	ifNoneMatch bool
}

func preconditions(r *http.Request) (precond, error) {
	var p precond
	if v := r.Header.Get("If-None-Match"); v != "" {
		if strings.TrimSpace(v) != "*" {
			return p, badInput("If-None-Match must be *")
		}
		p.ifNoneMatch = true
	}
	if v := r.Header.Get("If-Match"); v != "" {
		t, ok := etag(v)
		if !ok {
			return p, badInput("If-Match must be one quoted id")
		}
		p.ifMatch = t
	}
	if p.ifMatch != "" && p.ifNoneMatch {
		return p, badInput("both If-Match and If-None-Match")
	}
	return p, nil
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
	if _, err := sig.Parse(vs[0]); err != nil {
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

func parseBatch(body any) ([]core.Item, *core.ConfigChange, any, error) {
	m, ok := body.(map[string]any)
	if !ok {
		return nil, nil, nil, badInput("batch body must be an object")
	}
	// The batch's own gesture and undoes are defaults for every step
	// (§7.5), as an item's are for its steps.
	var batchG gestureDefaults
	for k, v := range m {
		switch k {
		case "items", "config", "source":
		case "gesture", "undoes":
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
					if !ok {
						return nil, nil, nil, badInput(fmt.Sprintf("item %d: ifMatch must be an id", i))
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
		cc.IfMatch, _ = o["ifMatch"].(string)
		if cc.Patches == nil {
			return nil, nil, nil, badInput("config needs patches")
		}
	}
	return items, cc, m["source"], nil
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
				if _, err := sig.Parse(sv); err != nil {
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

func sinceParam(r *http.Request) string {
	if s := r.URL.Query().Get("since"); s != "" {
		return s
	}
	return r.Header.Get("Last-Event-ID")
}
