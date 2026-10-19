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
// any (§C.5.3). Without one, a random key named -edge-grant-kid,
// never the key derived from -edge-secret, which every service holding
// the secret could derive and mint core cookies with; FILE edge-secret
// opts in to it next to key files, with a warning, so a deployment on it
// rotates to them. A path with '=' in it is a plain FILE unless no '/'
// comes before the '='.
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
	eq := file("edge=v3.key", "the third key, sixteen bytes or more")
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
		{"a plain path with =", "origin", []string{eq}, "origin", "origin"},
		{"a named path with =", "origin", []string{"k3=" + eq}, "k3", "k3"},
	} {
		ck, _, err := edgeGrantCookies(c.kid, c.keys, nil, cors)
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
	before, _, err := edgeGrantCookies("origin", []string{"k1=" + k1}, nil, cors)
	if err != nil {
		t.Fatal(err)
	}
	after, _, err := edgeGrantCookies("origin", []string{"k1=" + k1, "k2=" + k2}, nil, cors)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := after.Verify(before.Issue(cl, now).Value, now); err != nil {
		t.Errorf("k1's cookie after rotation: %v", err)
	}
	if got := edge.NewCookies("k1", []byte("the first key, sixteen bytes or more")).Issue(cl, now).Value; got != before.Issue(cl, now).Value {
		t.Errorf("key not the trimmed file: %s", got)
	}

	// Without -edge-grant-key, a random key named -edge-grant-kid, with
	// or without -edge-secret: never the key derived from the secret, so a
	// cookie minted with it is refused. With -edge-secret, a warning says
	// an edge verifying cookies needs key files.
	ev, err := edge.New([]byte("s3cret"), "", "")
	if err != nil {
		t.Fatal(err)
	}
	derived := edge.NewCookies("o1", edge.KeyFromSecret([]byte("s3cret")))
	for _, v := range []*edge.Verifier{nil, ev} {
		ck, warn, err := edgeGrantCookies("o1", nil, v, cors)
		if err != nil || ck.Kid() != "o1" || len(ck.Kids()) != 1 {
			t.Fatalf("no key, edge %v: %v %v", v != nil, ck, err)
		}
		if _, err := ck.Verify(derived.Issue(cl, now).Value, now); err == nil {
			t.Errorf("no key, edge %v: a cookie under the derived key verifies", v != nil)
		}
		if again, _, _ := edgeGrantCookies("o1", nil, v, cors); again.Issue(cl, now).Value == ck.Issue(cl, now).Value {
			t.Errorf("no key, edge %v: the key isn't random", v != nil)
		}
		if got := strings.Join(warn, "\n"); (v != nil) != strings.Contains(got, "-edge-grant-key") {
			t.Errorf("no key, edge %v: warnings %q", v != nil, got)
		}
		// Several origin instances no longer share a key, and an edge must
		// stop deriving one.
		if got := strings.Join(warn, "\n"); v != nil && (!strings.Contains(got, "only at this instance") ||
			!strings.Contains(got, "several origin instances") || !strings.Contains(got, "must drop the key derived from the edge secret")) {
			t.Errorf("no key, edge: warnings %q", got)
		}
	}
	// Given -edge-grant-key, the derived key isn't held, unless named by
	// FILE edge-secret: then a cookie minted under it alone verifies once
	// a key file is added as the newest, and drops with it. Holding it
	// warns that every holder of the edge secret can mint with it.
	if ck, warn, err := edgeGrantCookies("origin", []string{k1}, ev, cors); err != nil || len(ck.Kids()) != 1 || len(warn) != 0 {
		t.Errorf("with an edge secret: %v %v %q", ck, err, warn)
	}
	ck, warn, err := edgeGrantCookies("o1", []string{"edge-secret"}, ev, cors)
	if err != nil || ck.Kid() != "o1" || len(ck.Kids()) != 1 {
		t.Fatalf("derived: %v %v", ck, err)
	}
	if got, want := ck.Issue(cl, now).Value, derived.Issue(cl, now).Value; got != want {
		t.Errorf("derived key: %s, want %s", got, want)
	}
	if len(warn) != 1 || !strings.Contains(warn[0], "migrate") {
		t.Errorf("derived key: warnings %q", warn)
	}
	for _, c := range []struct {
		name, kid string
		keys      []string
		accepts   string
	}{
		{"derived, plain", "o1", []string{"edge-secret", "k2=" + k2}, "o1 k2"},
		{"derived, named", "origin", []string{"o1=edge-secret", "k2=" + k2}, "o1 k2"},
	} {
		rot, _, err := edgeGrantCookies(c.kid, c.keys, ev, cors)
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if rot.Kid() != "k2" || strings.Join(rot.Kids(), " ") != c.accepts {
			t.Errorf("%s: mints %s, accepts %v", c.name, rot.Kid(), rot.Kids())
		}
		if _, err := rot.Verify(ck.Issue(cl, now).Value, now); err != nil {
			t.Errorf("%s: the derived key's cookie: %v", c.name, err)
		}
	}
	if _, _, err := edgeGrantCookies("origin", []string{"./edge-secret"}, ev, cors); err == nil || !strings.Contains(err.Error(), "no such file") {
		t.Errorf("./edge-secret is a file: %v", err)
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
		{"the derived key without -edge-secret", "origin", []string{"edge-secret"}},
		{"a relative path with = and no /", "origin", []string{filepath.Base(eq)}},
	} {
		if ck, _, err := edgeGrantCookies(c.kid, c.keys, nil, cors); err == nil {
			t.Errorf("%s: accepted, kids %v", c.name, ck.Kids())
		}
	}
}
