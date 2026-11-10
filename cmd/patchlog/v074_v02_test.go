package main

import (
	"strings"
	"testing"
)

// -remote-origin-url ORIGIN=URL said where the deployment at ORIGIN itself
// answers, for the start times of a source's epochs from before its e2e
// raise (§G.5.2, v0.74). Nothing reads them since v0.81 (Addendum E
// Levels), so the flag is ignored: still accepted, so command lines keep
// working, with a warning at start, and with no effect on the endpoint.
// Malformed pairs are still refused as for the other -remote-* flags.
func TestV074RemoteOriginURL(t *testing.T) {
	const origin = "https://a.example"
	opt, warn, err := remoteOptions(nil, []string{origin + "=http://a:8080"}, nil, []string{origin + "=http://a:8080"})
	if err != nil {
		t.Fatal(err)
	}
	if len(warn) != 1 || !strings.Contains(warn[0], "-remote-origin-url is ignored since v0.81") {
		t.Fatalf("warnings %q", warn)
	}
	ep, _ := opt.Resolve(origin)
	if ep.BaseURL != "http://a:8080" {
		t.Fatalf("endpoint %+v", ep)
	}
	// Only -remote-origin-url: accepted, and the endpoint stays the default.
	opt, warn, err = remoteOptions(nil, nil, nil, []string{origin + "=http://a:8080"})
	if err != nil || len(warn) != 1 {
		t.Fatalf("-remote-origin-url alone: %v %q", err, warn)
	}
	if ep, _ := opt.Resolve(origin); ep.BaseURL != "" || ep.Bearer != "" || ep.Identity != nil {
		t.Fatalf("endpoint %+v", ep)
	}
	// Without it, no warning.
	if _, warn, err := remoteOptions(nil, []string{origin + "=http://mirror:8080"}, nil, nil); err != nil || len(warn) != 0 {
		t.Fatalf("without -remote-origin-url: %v %q", err, warn)
	}
	for _, bad := range []string{"http://a:8080", origin + "=", "http://a.example=http://a:8080"} {
		if _, _, err := remoteOptions(nil, nil, nil, []string{bad}); err == nil {
			t.Errorf("-remote-origin-url %q accepted", bad)
		}
	}
}
