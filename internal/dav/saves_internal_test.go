package dav

import (
	"testing"
	"time"
)

// The base an If header names (§H.4): the first entity tag, not negated,
// of the first list that applies to the resource; a tagged list applies
// to the resource its tag names, and the lists after a tag are its own.
func TestIfHeaderETag(t *testing.T) {
	const p = "/docs/x.json"
	for _, c := range []struct{ h, want string }{
		{`(["r1"])`, "r1"},
		{`([W/"r1"])`, "r1"},
		{`(Not ["r9"] ["r1"])`, "r1"},
		{`(<opaquelocktoken:a> ["r1"])`, "r1"},
		{`(<opaquelocktoken:a>) (["r2"])`, "r2"},
		{`(Not <DAV:no-lock> ["r1"])`, "r1"},
		{`<http://h/docs/other.json> (["r9"]) <http://h/docs/x.json> (["r1"])`, "r1"},
		{`<http://h/docs/x.json> (<opaquelocktoken:a>) (["r3"])`, "r3"},
		{`</docs/x.json> (["r4"])`, "r4"},
		{`<http://h/docs/other.json> (["r9"])`, ""},
		{`(Not ["r9"])`, ""},
		{`(<opaquelocktoken:a>)`, ""},
		{``, ""},
		{`(["r1"`, ""},
	} {
		if got := ifHeaderETag(c.h, p); got != c.want {
			t.Errorf("ifHeaderETag(%q) = %q, want %q", c.h, got, c.want)
		}
	}
}

// splitIf takes out the lists of entity tags only, which x/net/webdav
// can't check (a list without a lock token always fails there), keeping
// the lock tokens' lists under their resource tags.
func TestSplitIf(t *testing.T) {
	for _, c := range []struct{ h, want string }{
		{`(["r1"])`, ``},
		{`(Not <DAV:no-lock> ["r1"])`, ``},
		{`(<opaquelocktoken:a> ["r1"])`, `(<opaquelocktoken:a> ["r1"])`},
		{`(<opaquelocktoken:a>) (["r1"])`, `(<opaquelocktoken:a>)`},
		{`<http://h/x> (["r1"]) (<opaquelocktoken:a>)`, `<http://h/x> (<opaquelocktoken:a>)`},
		{`<http://h/x> (<opaquelocktoken:a>) <http://h/y> (["r2"])`, `<http://h/x> (<opaquelocktoken:a>)`},
		{`<http://h/x> (Not ["r1"])`, ``},
		{`(Not ["r9"] ["r1"])`, ``},
		{`(Not <opaquelocktoken:a>)`, `(Not <opaquelocktoken:a>)`},
		{`garbage`, `garbage`},
	} {
		if got := splitIf(c.h); got != c.want {
			t.Errorf("splitIf(%q) = %q, want %q", c.h, got, c.want)
		}
	}
}

// Only a revision served whole is a base (§H.4): a 206's range must be
// the whole file.
func TestWholeRange(t *testing.T) {
	for cr, want := range map[string]bool{
		"bytes 0-9/10": true, "bytes 0-0/1": true, "bytes 0-0/10": false, "bytes 1-9/10": false,
		"bytes 0-9/*": false, "": false, "bytes 0-x/10": false,
	} {
		if got := wholeRange(cr); got != want {
			t.Errorf("wholeRange(%q) = %v", cr, got)
		}
	}
}

// Guards (§H.6): one per refusal, used up one per DELETE, ending only by
// time, at most maxGuards, the oldest going first.
func TestGuards(t *testing.T) {
	s := &Server{opt: Options{Now: time.Now}}
	p := s.newPrincipal("p", nil, &account{})
	now := time.Now()
	for i := 0; i < 3; i++ {
		p.noteRefusedSave("/a", 400, now)
	}
	for left := 2; left >= 0; left-- {
		if _, l, ok := p.takeRefusedSave("/a", now); !ok || l != left {
			t.Fatalf("take: %v, %d left, want %d", ok, l, left)
		}
	}
	if _, _, ok := p.takeRefusedSave("/a", now); ok {
		t.Fatal("a fourth DELETE refused after three refusals")
	}
	p.noteRefusedSave("/b", 400, now)
	p.noteRefusedSave("/b", 409, now.Add(5*time.Second))
	if _, l, ok := p.takeRefusedSave("/b", now.Add(11*time.Second)); !ok || l != 0 {
		t.Fatalf("after the first guard's time: %v, %d left", ok, l)
	}
	if p.guarded("/b", now.Add(11*time.Second)) {
		t.Fatal("guarded after both were used up or ended")
	}
	for i := 0; i < maxGuards+10; i++ {
		p.noteRefusedSave("/c", 400, now.Add(time.Duration(i)*time.Microsecond))
	}
	if p.nguards != maxGuards || len(p.guards["/c"]) != maxGuards {
		t.Fatalf("%d guards kept, %d of /c, want %d", p.nguards, len(p.guards["/c"]), maxGuards)
	}
	if g := p.guards["/c"][0]; !g.at.Equal(now.Add(10 * time.Microsecond)) {
		t.Fatalf("the oldest kept is from %v", g.at.Sub(now))
	}
}
