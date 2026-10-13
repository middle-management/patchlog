package edge

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// §9: a private response gets edge lifetimes only for a read the edge
// verified itself: the secret and a prefix covering the URL, each as
// exactly one header line without a comma, and no other credential.
// Everything else private is no-store, with or without a Verifier.
func TestVerifierPrivate(t *testing.T) {
	v, err := New([]byte("s3cret"), "", "")
	if err != nil {
		t.Fatal(err)
	}
	if v.Header() != "X-Edge-Verified" || v.PrefixHeader() != "X-Edge-Prefix" {
		t.Fatalf("headers %q %q", v.Header(), v.PrefixHeader())
	}
	const lifetime = "max-age=0, s-maxage=1"
	for _, tc := range []struct {
		name, path string
		hdr        http.Header
		verified   bool
	}{
		{"verified", "/r/demo/derby", http.Header{"X-Edge-Verified": {"s3cret"}, "X-Edge-Prefix": {"/r/demo/derby"}}, true},
		{"below the prefix", "/r/demo/derby/rev/x", http.Header{"X-Edge-Verified": {"s3cret"}, "X-Edge-Prefix": {"/r/demo"}}, true},
		{"no headers", "/r/demo/derby", nil, false},
		{"wrong secret", "/r/demo/derby", http.Header{"X-Edge-Verified": {"s3cretx"}, "X-Edge-Prefix": {"/r/demo"}}, false},
		{"secret only", "/r/demo/derby", http.Header{"X-Edge-Verified": {"s3cret"}}, false},
		{"prefix only", "/r/demo/derby", http.Header{"X-Edge-Prefix": {"/r/demo"}}, false},
		{"empty prefix", "/r/demo/derby", http.Header{"X-Edge-Verified": {"s3cret"}, "X-Edge-Prefix": {""}}, false},
		{"two prefixes", "/r/demo/derby", http.Header{"X-Edge-Verified": {"s3cret"}, "X-Edge-Prefix": {"/r/demo", "/r/demo/derby"}}, false},
		// Each header is exactly one line without a comma (§9, §C.5).
		{"the same prefix twice", "/r/demo/derby", http.Header{"X-Edge-Verified": {"s3cret"}, "X-Edge-Prefix": {"/r/demo", "/r/demo"}}, false},
		{"prefixes in one line", "/r/demo/derby", http.Header{"X-Edge-Verified": {"s3cret"}, "X-Edge-Prefix": {"/r/demo,/r/demo/derby"}}, false},
		{"a prefix and a comma", "/r/demo/derby", http.Header{"X-Edge-Verified": {"s3cret"}, "X-Edge-Prefix": {"/r/demo/derby,"}}, false},
		{"the secret twice", "/r/demo/derby", http.Header{"X-Edge-Verified": {"s3cret", "s3cret"}, "X-Edge-Prefix": {"/r/demo"}}, false},
		{"the secret and another", "/r/demo/derby", http.Header{"X-Edge-Verified": {"s3cret", "x"}, "X-Edge-Prefix": {"/r/demo"}}, false},
		{"secrets in one line", "/r/demo/derby", http.Header{"X-Edge-Verified": {"s3cret, s3cret"}, "X-Edge-Prefix": {"/r/demo"}}, false},
		{"the secret and a comma", "/r/demo/derby", http.Header{"X-Edge-Verified": {"s3cret,"}, "X-Edge-Prefix": {"/r/demo"}}, false},
		{"another resource", "/r/demo/derby", http.Header{"X-Edge-Verified": {"s3cret"}, "X-Edge-Prefix": {"/r/demo/other"}}, false},
		{"not by segment", "/r/demo-x/a", http.Header{"X-Edge-Verified": {"s3cret"}, "X-Edge-Prefix": {"/r/demo"}}, false},
		{"another kind", "/ns/demo", http.Header{"X-Edge-Verified": {"s3cret"}, "X-Edge-Prefix": {"/r/demo"}}, false},
		{"Authorization", "/r/demo/derby", http.Header{"X-Edge-Verified": {"s3cret"}, "X-Edge-Prefix": {"/r/demo"}, "Authorization": {"Bearer g"}}, false},
		{"empty Authorization", "/r/demo/derby", http.Header{"X-Edge-Verified": {"s3cret"}, "X-Edge-Prefix": {"/r/demo"}, "Authorization": {""}}, false},
		{"Source-Authorization", "/r/demo/derby", http.Header{"X-Edge-Verified": {"s3cret"}, "X-Edge-Prefix": {"/r/demo"}, "Source-Authorization": {"Bearer g"}}, false},
	} {
		r := httptest.NewRequest("GET", tc.path, nil)
		for k, vs := range tc.hdr {
			r.Header[k] = vs
		}
		if got := v.VerifiedRead(r); got != tc.verified {
			t.Errorf("%s: verified %v", tc.name, got)
		}
		h := http.Header{}
		v.Private(h, r, lifetime)
		if tc.verified && (h.Get("CDN-Cache-Control") != lifetime || h.Get("Surrogate-Control") != "") ||
			!tc.verified && (h.Get("CDN-Cache-Control") != "no-store" || h.Get("Surrogate-Control") != "no-store") {
			t.Errorf("%s: %v", tc.name, h)
		}
		// Without a Verifier, every private response is no-store.
		h = http.Header{}
		(*Verifier)(nil).Private(h, r, lifetime)
		if h.Get("CDN-Cache-Control") != "no-store" || h.Get("Surrogate-Control") != "no-store" {
			t.Errorf("%s without a Verifier: %v", tc.name, h)
		}
	}

	// The headers are the deployment's.
	v, err = New([]byte("s3cret"), "x-cdn-secret", "x-cdn-prefix")
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("GET", "/ns/demo/log", nil)
	r.Header.Set("X-Edge-Verified", "s3cret")
	r.Header.Set("X-Edge-Prefix", "/ns/demo")
	if v.VerifiedRead(r) {
		t.Error("verified with the default headers")
	}
	r.Header.Set("X-Cdn-Secret", "s3cret")
	r.Header.Set("X-Cdn-Prefix", "/ns/demo")
	if !v.VerifiedRead(r) {
		t.Error("not verified with the configured headers")
	}
	// A secret with a comma could never come as one line without one.
	for _, tc := range [][3]string{{"", "", ""}, {"s", "x-a", "X-A"}, {"s3,cret", "", ""}} {
		if _, err := New([]byte(tc[0]), tc[1], tc[2]); err == nil {
			t.Errorf("New(%q, %q, %q) accepted", tc[0], tc[1], tc[2])
		}
	}
}
