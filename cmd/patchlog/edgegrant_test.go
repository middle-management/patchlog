package main

import (
	"flag"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/core"
	"github.com/middle-management/patchlog/internal/edge"
)

// -exchange-rate is RATE,BURST (§6.6).
func TestParseRate(t *testing.T) {
	for s, want := range map[string]core.Rate{"10,100": {Rate: 10, Burst: 100}, "0.5, 1": {Rate: 0.5, Burst: 1}} {
		if got, err := parseRate(s); err != nil || got != want {
			t.Errorf("%q: %v %v", s, got, err)
		}
	}
	for _, s := range []string{"", "10", "10,", ",100", "0,100", "-1,100", "10,0.5", "x,1", "10,100,1", "NaN,1", "Inf,1", "1,Inf"} {
		if got, err := parseRate(s); err == nil {
			t.Errorf("%q accepted: %v", s, got)
		}
	}
}

// -edge-grant-key is repeatable, [KID=]FILE, a plain FILE named by
// -edge-grant-kid: cookies are minted under the last and accepted under
// any (§C.5 "Format"). Without one, the key derived from -edge-secret is
// named -edge-grant-kid, as before.
func TestEdgeGrantKeyFlags(t *testing.T) {
	dir := t.TempDir()
	file := func(name, key string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(key+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	k1 := file("k1", "the first key, sixteen bytes or more")
	k2 := file("k2", "the second key, sixteen bytes or more")
	short := file("short", "too short")
	cors := addCORSFlags(flag.NewFlagSet("t", flag.ContinueOnError))
	now := time.Unix(1790000000, 0)
	cl := edge.Claims{Prefix: "/r/demo", Exp: now.Add(time.Minute).Unix()}

	for _, c := range []struct {
		name, kid string
		keys      []string
		mints     string
		accepts   string
	}{
		{"one plain file", "origin", []string{k1}, "origin", "origin"},
		{"one plain file, named", "o1", []string{k1}, "o1", "o1"},
		{"one named file", "origin", []string{"k1=" + k1}, "k1", "k1"},
		{"rotating", "origin", []string{"k1=" + k1, "k2=" + k2}, "k2", "k1 k2"},
		{"plain then named", "origin", []string{k1, "k2=" + k2}, "k2", "origin k2"},
		{"named then plain", "origin", []string{"k2=" + k2, k1}, "origin", "k2 origin"},
	} {
		ck, err := edgeGrantCookies(c.kid, c.keys, nil, cors)
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if ck.Kid() != c.mints || strings.Join(ck.Kids(), " ") != c.accepts {
			t.Errorf("%s: mints %s, accepts %v", c.name, ck.Kid(), ck.Kids())
		}
		if ck.SameSite != http.SameSiteLaxMode {
			t.Errorf("%s: SameSite %v", c.name, ck.SameSite)
		}
	}

	// The key is the file's bytes, trimmed: a cookie minted under k1 by a
	// deployment holding it alone verifies after k2 is added as the newest.
	before, err := edgeGrantCookies("origin", []string{"k1=" + k1}, nil, cors)
	if err != nil {
		t.Fatal(err)
	}
	after, err := edgeGrantCookies("origin", []string{"k1=" + k1, "k2=" + k2}, nil, cors)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := after.Verify(before.Issue(cl, now).Value, now); err != nil {
		t.Errorf("k1's cookie after rotation: %v", err)
	}
	if got := edge.NewCookies("k1", []byte("the first key, sixteen bytes or more")).Issue(cl, now).Value; got != before.Issue(cl, now).Value {
		t.Errorf("key not the trimmed file: %s", got)
	}

	// Without -edge-grant-key, the key derived from -edge-secret, named
	// -edge-grant-kid.
	ev, err := edge.New([]byte("s3cret"), "", "")
	if err != nil {
		t.Fatal(err)
	}
	ck, err := edgeGrantCookies("o1", nil, ev, cors)
	if err != nil || ck.Kid() != "o1" || len(ck.Kids()) != 1 {
		t.Fatalf("derived: %v %v", ck, err)
	}
	if got, want := ck.Issue(cl, now).Value, edge.NewCookies("o1", edge.KeyFromSecret([]byte("s3cret"))).Issue(cl, now).Value; got != want {
		t.Errorf("derived key: %s, want %s", got, want)
	}
	// Given -edge-grant-key, the derived key isn't held.
	if ck, err := edgeGrantCookies("origin", []string{k1}, ev, cors); err != nil || len(ck.Kids()) != 1 {
		t.Errorf("with an edge secret: %v %v", ck, err)
	}

	for _, c := range []struct {
		name, kid string
		keys      []string
	}{
		{"empty kid", "", nil},
		{"empty KID=", "origin", []string{"=" + k1}},
		{"empty FILE", "origin", []string{"k1="}},
		{"missing file", "origin", []string{filepath.Join(dir, "nope")}},
		{"short key", "origin", []string{short}},
		{"a kid twice", "origin", []string{"k1=" + k1, "k1=" + k2}},
		{"a plain file and its kid", "origin", []string{k1, "origin=" + k2}},
		{"two plain files", "origin", []string{k1, k2}},
	} {
		if ck, err := edgeGrantCookies(c.kid, c.keys, nil, cors); err == nil {
			t.Errorf("%s: accepted, kids %v", c.name, ck.Kids())
		}
	}
}
