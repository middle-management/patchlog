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
// Timeout set. Errors are as for NSLog (404 since not in chain, …).
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
	res.Entries, err = parseNSLog(r.value(), r.path)
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

// ResourceLongPoll waits for resource log entries after since (§7.7).
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
	res.Entries, err = parseLog(r)
	if err != nil {
		return nil, err
	}
	if res.Since == "" && len(res.Entries) > 0 {
		res.Since = res.Entries[len(res.Entries)-1].ID
	}
	return res, nil
}

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
	ID   string
	Data any // parsed data (jsonv model)
}

// NSEvents streams namespace entries after since over SSE (§7.4) and calls
// fn for each, in order, until ctx is done, the stream ends, or fn returns
// an error (which NSEvents returns). A clean end of stream returns nil;
// callers usually reconnect from the last id they processed.
func (c *Client) NSEvents(ctx context.Context, ns, since string, fn func(NSEntry) error) error {
	if err := checkNS(ns); err != nil {
		return err
	}
	return c.events(ctx, "/ns/"+ns+"/events", since, func(ev Event) error {
		e, err := ParseNSEntry(ev.Data)
		if err != nil {
			return err
		}
		return fn(e)
	})
}

// ResourceEvents streams a resource's events after since over SSE (§7.3).
func (c *Client) ResourceEvents(ctx context.Context, ns, name, since string, fn func(Event) error) error {
	if err := checkRes(ns, name); err != nil {
		return err
	}
	return c.events(ctx, "/r/"+ns+"/"+name+"/events", since, fn)
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
				v, err := jsonv.Parse([]byte(data.String()))
				if err != nil {
					return fmt.Errorf("client: bad event data: %w", err)
				}
				ev.Data = v
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
