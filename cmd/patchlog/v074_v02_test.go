package main

import "testing"

// §G.5.2 Epoch start times: -remote-origin-url ORIGIN=URL says where the
// deployment at ORIGIN itself answers, so a -remote-url naming an internal
// address of the origin isn't taken for a mirror; without it the origin's
// own URL is (RemoteEndpoint.OriginURL ""). Malformed pairs are refused as
// for the other -remote-* flags.
func TestV074RemoteOriginURL(t *testing.T) {
	const origin = "https://a.example"
	opt, err := remoteOptions(nil, []string{origin + "=http://a:8080"}, nil, []string{origin + "=http://a:8080"})
	if err != nil {
		t.Fatal(err)
	}
	ep, _ := opt.Resolve(origin)
	if ep.BaseURL != "http://a:8080" || ep.OriginURL != "http://a:8080" {
		t.Fatalf("endpoint %+v", ep)
	}
	opt, err = remoteOptions(nil, []string{origin + "=http://mirror:8080"}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if ep, _ := opt.Resolve(origin); ep.OriginURL != "" {
		t.Fatalf("OriginURL %q without -remote-origin-url", ep.OriginURL)
	}
	for _, bad := range []string{"http://a:8080", origin + "=", "http://a.example=http://a:8080"} {
		if _, err := remoteOptions(nil, nil, nil, []string{bad}); err == nil {
			t.Errorf("-remote-origin-url %q accepted", bad)
		}
	}
}
