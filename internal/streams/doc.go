// Package streams is the stream proxy of TOOLS.md Addendum J (J.1–J.4): it
// forwards a request to an upstream HTTP API and keeps the streamed
// response as a resource of a namespace of its own, so a client that loses
// its connection reads on from the revision it last saw.
//
// The proxy writes what J.1 and J.2 say, with core requests only: one
// resource per upstream response, created before upstream is called, each
// flush one patch set adding to /chunks/-, a last one setting closed. It
// answers its caller with the resource's URL and its own grant narrowed to
// that stream (J.3); callers read, resume and abort against the core, not
// through the proxy (Follow, Abort). J.5–J.7 (shared sessions, MCP,
// recording model calls) are not here.
package streams

import (
	"errors"
	"fmt"
)

// Close reasons of J.1.
const (
	ReasonComplete = "complete"
	ReasonAborted  = "aborted"
	ReasonError    = "error"
	ReasonTimeout  = "timeout"
	ReasonSize     = "size"
)

// Upstream is the stream document's upstream member (J.1). Status is 0 and
// ContentType "" until the first append records them (J.2), and for a
// stream whose upstream call failed.
type Upstream struct {
	Method      string
	Status      int
	ContentType string
}

// Closed is the stream document's closed member (J.1): why the stream
// ended, with Error for "error" (and sometimes "timeout"), and Next, the
// resource that carries on the same upstream response, for "size".
type Closed struct {
	Reason string
	Error  string
	Next   string
}

// Doc is a stream document (J.1).
type Doc struct {
	Upstream Upstream
	Chunks   []string
	Closed   *Closed // nil while the stream is open
	Abort    bool    // a caller asked for the stream to stop (J.4)
}

// ParseDoc reads a stream document from parsed JSON (the jsonv model, as
// client.Doc.Value holds it).
func ParseDoc(v any) (*Doc, error) {
	m, ok := v.(map[string]any)
	if !ok {
		return nil, errors.New("streams: the document is not an object")
	}
	d := &Doc{}
	up, ok := m["upstream"].(map[string]any)
	if !ok {
		return nil, errors.New("streams: the document has no upstream: not a stream")
	}
	d.Upstream = parseUpstream(up)
	arr, ok := m["chunks"].([]any)
	if !ok {
		return nil, errors.New("streams: the document has no chunks: not a stream")
	}
	for i, x := range arr {
		s, ok := x.(string)
		if !ok {
			return nil, fmt.Errorf("streams: chunk %d is not a string", i)
		}
		d.Chunks = append(d.Chunks, s)
	}
	d.Closed = parseClosed(m["closed"])
	d.Abort = m["abort"] == true
	return d, nil
}

func parseUpstream(m map[string]any) Upstream {
	u := Upstream{}
	u.Method, _ = m["method"].(string)
	if n, ok := m["status"].(float64); ok {
		u.Status = int(n)
	}
	u.ContentType, _ = m["contentType"].(string)
	return u
}

func parseClosed(v any) *Closed {
	m, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	c := &Closed{}
	c.Reason, _ = m["reason"].(string)
	c.Error, _ = m["error"].(string)
	c.Next, _ = m["next"].(string)
	return c
}

func (c *Closed) value() map[string]any {
	m := map[string]any{"reason": c.Reason}
	if c.Error != "" {
		m["error"] = c.Error
	}
	if c.Next != "" {
		m["next"] = c.Next
	}
	return m
}

// delta is what one log entry's patch set did to a stream document, as far
// as a reader or the proxy cares.
type delta struct {
	chunks   []string
	upstream *Upstream // set by a genesis; status and contentType by the first append
	status   int
	ctype    string
	closed   *Closed
	abort    bool
}

// readPatches reads the operations of a stream's patch set (parsed JSON).
// Only what J.1–J.4 write is understood: a genesis (add of the whole
// document), adds to /chunks/-, /upstream/status, /upstream/contentType,
// /closed and /abort; anything else is passed over.
func readPatches(patches any) delta {
	var d delta
	arr, _ := patches.([]any)
	for _, x := range arr {
		op, _ := x.(map[string]any)
		kind, _ := op["op"].(string)
		if kind != "add" && kind != "replace" {
			continue
		}
		path, _ := op["path"].(string)
		switch path {
		case "":
			if doc, err := ParseDoc(op["value"]); err == nil {
				up := doc.Upstream
				d.upstream = &up
				d.chunks = append(d.chunks, doc.Chunks...)
				d.closed = doc.Closed
				d.abort = d.abort || doc.Abort
			}
		case "/chunks/-":
			if s, ok := op["value"].(string); ok {
				d.chunks = append(d.chunks, s)
			}
		case "/upstream/status":
			if n, ok := op["value"].(float64); ok {
				d.status = int(n)
			}
		case "/upstream/contentType":
			d.ctype, _ = op["value"].(string)
		case "/closed":
			d.closed = parseClosed(op["value"])
		case "/abort":
			if op["value"] == true {
				d.abort = true
			}
		}
	}
	return d
}

// SegmentName is the resource name of segment n of the stream whose first
// resource is id: id itself for 0, and "{id}.{n}" for the continuations a
// stream closed with "size" names in next (J.1).
func SegmentName(id string, n int) string {
	if n == 0 {
		return id
	}
	return fmt.Sprintf("%s.%d", id, n)
}
