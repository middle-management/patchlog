package client

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// v0.26.1 review, round 3 (ddb03a6, "follow no redirect of a
// remote base, anywhere"): getBlobRef still follows a base's 302 by hand,
// checking only that Location starts with …/blob/{bid}/e/. A Location of
// …/blob/{bid}/e/../../../../../../other is sent as is (Go doesn't resolve
// dot segments), with the grant, so a base reached under a path prefix
// (a gateway, RemoteEndpoint.BaseURL with a path) points B's request, and
// its Authorization, anywhere on that host.
func TestV0261BlobRedirectDotSegments(t *testing.T) {
	bid := BlobID("text/plain", "", []byte("hi"))
	var mu sync.Mutex
	var got []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		got = append(got, r.URL.Path+" auth="+r.Header.Get("Authorization"))
		mu.Unlock()
		if strings.HasSuffix(r.URL.Path, "/blob/"+bid) {
			w.Header().Set("Location", "/r/m/x/blob/"+bid+"/e/../../../../../../tenant-b/secret")
			w.WriteHeader(http.StatusFound)
			return
		}
		w.WriteHeader(404)
	}))
	t.Cleanup(srv.Close)
	c, err := New(srv.URL+"/tenant-a", WithBearer("grant-for-a"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.GetBlobRef(context.Background(), "m", "x", BlobRef(bid, "text/plain", 2, ""))
	t.Logf("GetBlobRef: %v; requests: %q", err, got)
	for _, g := range got {
		if strings.Contains(g, "/../") {
			t.Fatalf("the base's 302 sent B to %s, outside the base URL's path", g)
		}
	}
}
