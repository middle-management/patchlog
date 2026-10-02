package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// The servers speak h2c (§7.7: long-poll over HTTP/2) and HTTP/1.1.
func TestH2C(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, r.Proto)
	}))
	allowH2C(srv.Config)
	srv.Start()
	defer srv.Close()

	var p http.Protocols
	p.SetUnencryptedHTTP2(true)
	h2 := &http.Client{Transport: &http.Transport{Protocols: &p}}
	for _, c := range []struct {
		client *http.Client
		want   string
	}{{h2, "HTTP/2.0"}, {http.DefaultClient, "HTTP/1.1"}} {
		r, err := c.client.Get(srv.URL)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(r.Body)
		r.Body.Close()
		if string(b) != c.want {
			t.Errorf("proto %q, want %q", b, c.want)
		}
	}
}
