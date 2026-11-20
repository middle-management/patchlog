package vectors_test

// Addendum I, §I.25 (v0.86): long-poll phases (§7.7; CONFORMANCE CONF-5,
// VEC-25). The four rows are in testdata/addendum_i.json as docs/SPEC.md
// prints them, and each is derived here through server.LongPollPhase, the
// function the server takes every log's interval boundaries from.

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/grantcheck"
	"github.com/middle-management/patchlog/internal/server"
	"github.com/middle-management/patchlog/internal/vectors/golden"
)

// addendumI25 is the I.25 group of testdata/addendum_i.json.
type addendumI25 struct {
	I25 struct {
		IntervalMs int64
		Rows       []struct {
			Path, First8 string
			PhaseMs      int64
		}
	} `json:"I.25"`
}

func loadI25(t *testing.T) (time.Duration, []struct {
	Path, First8 string
	PhaseMs      int64
}) {
	t.Helper()
	var f addendumI25
	if !golden.Load(t, "addendum_i", &f) {
		t.Fatal("testdata/addendum_i.json is missing")
	}
	if f.I25.IntervalMs != 20000 || len(f.I25.Rows) != 4 {
		t.Fatalf("I.25 in addendum_i.json: interval %d ms and %d rows, want 20000 and 4", f.I25.IntervalMs, len(f.I25.Rows))
	}
	return time.Duration(f.I25.IntervalMs) * time.Millisecond, f.I25.Rows
}

// §I.25: at the default 20 s interval, each path's phase is the first 8
// bytes of its SHA-256, big-endian, modulo 20,000 ms; interval n of the
// log starts at epoch + phase + n × interval (§7.7), which is where its
// cursor changes. The last path's gs is I.8's.
func TestI25LongPollPhases(t *testing.T) {
	t.Parallel()
	interval, rows := loadI25(t)
	for _, r := range rows {
		if h := sha256.Sum256([]byte(r.Path)); hex.EncodeToString(h[:8]) != r.First8 {
			t.Errorf("%s: first 8 bytes of its SHA-256 %x, want %s", r.Path, h[:8], r.First8)
		}
		want := time.Duration(r.PhaseMs) * time.Millisecond
		if got := server.LongPollPhase(r.Path, interval); got != want {
			t.Errorf("%s: phase %v, want %v", r.Path, got, want)
		}
		// The cursor is the interval number: n from epoch + phase + n ×
		// interval on, n − 1 until then.
		for _, n := range []int64{0, 1, 89_000_000} {
			start := time.UnixMilli(r.PhaseMs + n*interval.Milliseconds())
			if got := server.LongPollCursor(r.Path, interval, start); got != n {
				t.Errorf("%s: cursor %d at the start of interval %d", r.Path, got, n)
			}
			if got := server.LongPollCursor(r.Path, interval, start.Add(interval-time.Nanosecond)); got != n {
				t.Errorf("%s: cursor %d at the end of interval %d", r.Path, got, n)
			}
			if got := server.LongPollCursor(r.Path, interval, start.Add(interval)); got != n+1 {
				t.Errorf("%s: cursor %d at the start of interval %d", r.Path, got, n+1)
			}
		}
	}
	gs := grantcheck.ViewID([]string{"group:match-desk", "user:anna"}) // I.8's
	if want := "/ns/matches/view/" + gs + "/log"; rows[3].Path != want {
		t.Errorf("the last path %s, want I.8's gs: %s", rows[3].Path, want)
	}
}

// §I.25 as served: a deployment at the default 20 s interval answers a
// long-poll of each of the first three paths with the X-Cursor of the
// interval the instant falls in, counted from the spec's phase for that
// path: the cursor c with epoch + phase + c × 20 s at or before the
// answer, and the next boundary after the request.
func TestI25LongPollPhasesServed(t *testing.T) {
	t.Parallel()
	interval, rows := loadI25(t)
	s := clienttest.New(t, clienttest.Options{LongPoll: interval})
	c, err := client.New(s.URL, client.WithAuthor("vectors"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.CreateNamespace(ctx, "docs", map[string]any{"read": "public"}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"a", "b"} {
		if _, err := c.CreateDoc(ctx, "docs", name, map[string]any{}); err != nil {
			t.Fatal(err)
		}
	}
	// Without a cursor each is answered at once (§7.7).
	polls := []func() (string, error){
		func() (string, error) {
			r, err := c.ResourceLongPoll(ctx, "docs", "a", "", "")
			return cursorOf(r, err)
		},
		func() (string, error) {
			r, err := c.ResourceLongPoll(ctx, "docs", "b", "", "")
			return cursorOf(r, err)
		},
		func() (string, error) {
			r, err := c.LongPoll(ctx, "docs", "", "")
			if err != nil {
				return "", err
			}
			return r.Cursor, nil
		},
	}
	for i, poll := range polls {
		r := rows[i]
		before := time.Now()
		got, err := poll()
		after := time.Now()
		if err != nil {
			t.Fatalf("%s: %v", r.Path, err)
		}
		cur, err := strconv.ParseInt(got, 10, 64)
		if err != nil {
			t.Fatalf("%s: X-Cursor %q", r.Path, got)
		}
		start := time.UnixMilli(r.PhaseMs + cur*interval.Milliseconds())
		if start.After(after) || !start.Add(interval).After(before) {
			t.Errorf("%s: X-Cursor %d, whose interval is %v to %v by the phase %d ms, answered between %v and %v",
				r.Path, cur, start, start.Add(interval), r.PhaseMs, before, after)
		}
	}
}

func cursorOf(r *client.ResourceLongPollResult, err error) (string, error) {
	if err != nil {
		return "", err
	}
	return r.Cursor, nil
}
