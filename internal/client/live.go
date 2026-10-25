package client

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/seal"
)

// LongPollResult is one answer of a long-poll read (§7.7).
type LongPollResult struct {
	Entries []NSEntry // oldest first; empty on timeout
	Since   string    // the next since: the last entry returned, or the request's since on timeout
	Cursor  string    // X-Cursor, to echo in the next request
	Timeout bool      // 204: no entry arrived within the interval
}

// LongPoll waits for namespace entries after since (§7.7). Echo the
// returned Cursor and Since in the next call. It returns at once when
// entries exist, and otherwise at the server's interval boundary with
// Timeout set; without a cursor, or with one behind the server's, at once.
// Errors are as for NSLog (404 since not in chain, …). A cursor more than
// an hour's worth of intervals behind or ahead of the server's, after a
// long pause or a clock change, is 400 bad_input (IsBadInput): poll again
// once without it, as a follower does.
func (c *Client) LongPoll(ctx context.Context, ns, since, cursor string) (*LongPollResult, error) {
	if err := checkNS(ns); err != nil {
		return nil, err
	}
	r, err := c.longPoll(ctx, "/ns/"+ns+"/log", since, cursor)
	if err != nil {
		return nil, err
	}
	res := &LongPollResult{Since: r.header.Get("X-Namespace-Revision"), Cursor: r.header.Get("X-Cursor")}
	if r.status == 204 {
		res.Timeout = true
		if res.Since == "" {
			res.Since = since
		}
		return res, nil
	}
	body := r.value()
	if isJOSE(r) {
		if body, err = c.openRange(ctx, ns, since, res.Since, string(r.body)); err != nil {
			return nil, fmt.Errorf("client: namespace log %s: %w", ns, err)
		}
	}
	res.Entries, err = parseNSLog(body, r.path)
	if err != nil {
		return nil, err
	}
	if res.Since == "" && len(res.Entries) > 0 {
		res.Since = res.Entries[len(res.Entries)-1].ID
	}
	return res, nil
}

// ResourceLongPollResult is one answer of a resource long-poll read.
type ResourceLongPollResult struct {
	Entries []LogEntry
	Since   string
	Cursor  string
	Timeout bool
}

// ResourceLongPoll waits for resource log entries after since (§7.7), as
// LongPoll does; a resource with no entries waits as for an empty since.
func (c *Client) ResourceLongPoll(ctx context.Context, ns, name, since, cursor string) (*ResourceLongPollResult, error) {
	if err := checkRes(ns, name); err != nil {
		return nil, err
	}
	r, err := c.longPoll(ctx, "/r/"+ns+"/"+name+"/log", since, cursor)
	if err != nil {
		return nil, err
	}
	res := &ResourceLongPollResult{Since: r.header.Get("X-Revision"), Cursor: r.header.Get("X-Cursor")}
	if r.status == 204 {
		res.Timeout = true
		if res.Since == "" {
			res.Since = since
		}
		return res, nil
	}
	res.Entries, err = c.openLog(ctx, ns, name, since, res.Since, r)
	if err != nil {
		return nil, err
	}
	if res.Since == "" && len(res.Entries) > 0 {
		res.Since = res.Entries[len(res.Entries)-1].ID
	}
	return res, nil
}

// IsBadInput reports a 400 bad_input: a request-shape error (§12.1), such
// as a long-poll cursor more than an hour's worth of intervals behind or
// ahead of the server's (§7.7), after which a follower polls again without
// the cursor.
func IsBadInput(err error) bool { return statusIs(err, 400, "bad_input") }

func (c *Client) longPoll(ctx context.Context, path, since, cursor string) (*response, error) {
	if err := checkOptID("since", since); err != nil {
		return nil, err
	}
	q := url.Values{"live": {"long-poll"}}
	if since != "" {
		q.Set("since", since)
	}
	if cursor != "" {
		q.Set("cursor", cursor)
	}
	r, err := c.do(ctx, "GET", path, q, nil)
	if err != nil {
		return nil, err
	}
	if r.status != 200 && r.status != 204 {
		return nil, r.apiError()
	}
	return r, nil
}

// Event is one server-sent event.
type Event struct {
	Type string // the entry's kind (namespace streams) or revision/tombstone/purge/prune
	// ID is the event's id: field, the entry's id; a resource stream's
	// purge and prune events have none (§7.3).
	ID   string
	Data any // parsed data (jsonv model); decrypted in a sealed namespace
	// JWE is the data as served in a sealed namespace (Addendum E.2).
	JWE string
}

// NSEvents streams namespace entries after since over SSE (§7.4) and calls
// fn for each, in order, until ctx is done, the stream ends, or fn returns
// an error (which NSEvents returns). A clean end of stream returns nil;
// callers usually reconnect from the last id they processed.
func (c *Client) NSEvents(ctx context.Context, ns, since string, fn func(NSEntry) error) error {
	if err := checkNS(ns); err != nil {
		return err
	}
	prev := since
	return c.events(ctx, "/ns/"+ns+"/events", since, func(ev Event) error {
		if ev.JWE != "" {
			// One entry per event, sealed as the range (prev, id] (§E.2.2).
			v, err := c.openRange(ctx, ns, prev, ev.ID, ev.JWE)
			if err != nil {
				return fmt.Errorf("client: event %s: %w", ev.ID, err)
			}
			arr, _ := v.([]any)
			if len(arr) != 1 {
				return fmt.Errorf("client: event %s: sealed data is not one entry", ev.ID)
			}
			ev.Data = arr[0]
		}
		e, err := ParseNSEntry(ev.Data)
		if err != nil {
			return err
		}
		if ev.JWE != "" && e.ID != ev.ID {
			return fmt.Errorf("client: event %s carries entry %s: %w", ev.ID, e.ID, seal.ErrMismatch)
		}
		prev = ev.ID
		return fn(e)
	})
}

// ResourceEvents streams a resource's events after since over SSE (§7.3):
// revision and tombstone events, whose Data is the resource log entry and
// ID its id, and purge and prune events, whose Data is the namespace entry
// that records them, without id and prev, and which have no ID. A stream
// ends after its purge event. To resume, pass the ID of the last revision
// or tombstone event as since.
//
// A server older than v0.73 sends purge and prune events with the
// namespace entry's id as their id: and, in a sealed namespace, sealed as
// the namespace range of that one entry under K_e; ResourceEvents opens
// that form too, and delivers those events as a current server sends them.
func (c *Client) ResourceEvents(ctx context.Context, ns, name, since string, fn func(Event) error) error {
	if err := checkRes(ns, name); err != nil {
		return err
	}
	return c.events(ctx, "/r/"+ns+"/"+name+"/events", since, func(ev Event) error {
		if ev.JWE == "" {
			if m, ok := ev.Data.(map[string]any); ok && (ev.Type == "purge" || ev.Type == "prune") {
				ev.ID, ev.Data = "", withoutIDPrev(m)
			}
			return fn(ev)
		}
		switch ev.Type {
		case "revision", "tombstone":
			e, err := c.openEntry(ctx, ns, name, ev.JWE)
			if err != nil {
				return fmt.Errorf("client: event %s: %w", ev.ID, err)
			}
			if e.ID != ev.ID {
				return fmt.Errorf("client: event %s carries entry %s: %w", ev.ID, e.ID, seal.ErrMismatch)
			}
			ev.Data = e.Raw
		case "purge", "prune":
			m, err := c.openResourceEvent(ctx, ns, name, ev)
			if err != nil {
				return err
			}
			if m["kind"] != ev.Type || m["resource"] != name {
				return fmt.Errorf("client: %s event carries a %v entry of %v: %w", ev.Type, m["kind"], m["resource"], seal.ErrMismatch)
			}
			ev.ID, ev.Data = "", withoutIDPrev(m)
		default:
			return fmt.Errorf("client: sealed event of type %q", ev.Type)
		}
		return fn(ev)
	})
}

// openResourceEvent opens a sealed purge or prune event ev of resource name.
func (c *Client) openResourceEvent(ctx context.Context, ns, name string, ev Event) (map[string]any, error) {
	h, err := seal.ParseHeader(ev.JWE)
	if err != nil {
		return nil, fmt.Errorf("client: %s event: %w", ev.Type, err)
	}
	if rg, old := h.PL["range"]; old {
		// A server older than v0.73: the namespace range (prev, id] of
		// the one entry, under K_e, with the entry's id as the event's
		// id:. The range pl binds both, and the entry must match them.
		pair, _ := rg.([]any)
		var from string
		if len(pair) == 2 {
			from, _ = pair[0].(string)
		}
		if len(pair) != 2 || ev.ID == "" {
			return nil, fmt.Errorf("client: %s event: %w", ev.Type, seal.ErrMismatch)
		}
		v, err := c.openRange(ctx, ns, from, ev.ID, ev.JWE)
		if err != nil {
			return nil, fmt.Errorf("client: %s event %s: %w", ev.Type, ev.ID, err)
		}
		arr, _ := v.([]any)
		var m map[string]any
		if len(arr) == 1 {
			m, _ = arr[0].(map[string]any)
		}
		if m == nil {
			return nil, fmt.Errorf("client: %s event %s: sealed data is not one entry", ev.Type, ev.ID)
		}
		if m["id"] != ev.ID || m["prev"] != from {
			return nil, fmt.Errorf("client: %s event %s carries entry %v after %v: %w", ev.Type, ev.ID, m["id"], m["prev"], seal.ErrMismatch)
		}
		return m, nil
	}
	// The namespace entry that records it, without id and prev, sealed
	// under the resource's K_r of the current epoch with pl { ns, name,
	// kind }: a grant for this resource alone opens it (§7.3, §E.2.2).
	pt, err := c.open(ctx, ns, name, ev.JWE, fixedPL(seal.ResourceEventPL(ns, name, ev.Type)))
	if err != nil {
		return nil, fmt.Errorf("client: %s event: %w", ev.Type, err)
	}
	v, err := jsonv.Parse(pt)
	m, _ := v.(map[string]any)
	if err != nil || m == nil {
		return nil, fmt.Errorf("client: %s event: sealed data is not an entry", ev.Type)
	}
	return m, nil
}

// withoutIDPrev is a resource stream's purge or prune event data m, the
// namespace entry recording it, without its id and prev (§7.3).
func withoutIDPrev(m map[string]any) map[string]any {
	if _, ok := m["id"]; !ok {
		if _, ok := m["prev"]; !ok {
			return m
		}
	}
	d := make(map[string]any, len(m))
	for k, v := range m {
		if k != "id" && k != "prev" {
			d[k] = v
		}
	}
	return d
}

func (c *Client) events(ctx context.Context, path, since string, fn func(Event) error) error {
	if err := checkOptID("since", since); err != nil {
		return err
	}
	u := c.base + path
	if since != "" {
		u += "?since=" + since
	}
	hr, err := http.NewRequestWithContext(ctx, "GET", u, nil)
	if err != nil {
		return err
	}
	hr.Header.Set("Accept", "text/event-stream")
	c.setAuth(hr)
	res, err := c.hc.Do(hr)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		r := &response{status: res.StatusCode, header: res.Header, method: "GET", path: path}
		r.body, _ = io.ReadAll(io.LimitReader(res.Body, 1<<20))
		return r.apiError()
	}
	sc := bufio.NewScanner(res.Body)
	sc.Buffer(make([]byte, 64<<10), 64<<20)
	var ev Event
	var data strings.Builder
	for sc.Scan() {
		line := sc.Text()
		switch {
		case line == "":
			if data.Len() > 0 {
				if d := data.String(); d[0] != '{' && d[0] != '[' {
					ev.JWE = d // sealed (Addendum E.2)
				} else {
					v, err := jsonv.Parse([]byte(d))
					if err != nil {
						return fmt.Errorf("client: bad event data: %w", err)
					}
					ev.Data = v
				}
				if err := fn(ev); err != nil {
					return err
				}
			}
			ev = Event{}
			data.Reset()
		case strings.HasPrefix(line, ":"):
		case strings.HasPrefix(line, "event:"):
			ev.Type = strings.TrimSpace(line[len("event:"):])
		case strings.HasPrefix(line, "id:"):
			ev.ID = strings.TrimSpace(line[len("id:"):])
		case strings.HasPrefix(line, "data:"):
			if data.Len() > 0 {
				data.WriteByte('\n')
			}
			data.WriteString(strings.TrimPrefix(line[len("data:"):], " "))
		}
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return sc.Err()
}
