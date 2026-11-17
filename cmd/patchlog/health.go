package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/middle-management/patchlog/internal/telemetry"
)

// healthCmd checks a health endpoint, for container healthchecks (the image
// has no curl):
//
//	patchlog health [--timeout 2s] [URL]
//
// URL defaults to http://localhost:8080/_health; a bare port (":8081") or
// host:port gets http:// and /_health. Exit status 0 on 200, 1 otherwise
// (503 while draining, connection refused, …), with the reason on stderr.
type healthCmd struct {
	Timeout time.Duration `arg:"--timeout" default:"2s" placeholder:"DURATION" help:"request timeout"`
	URL     string        `arg:"positional" default:"http://localhost:8080/_health" help:"health endpoint; a bare port (:8081) or host:port gets http:// and /_health"`
}

func (a *healthCmd) run(string) {
	url := healthURL(a.URL)
	c := &http.Client{Timeout: a.Timeout, Transport: telemetry.Transport(nil)}
	r, err := c.Get(url)
	if err != nil {
		fmt.Fprintln(os.Stderr, "health:", err)
		os.Exit(1)
	}
	defer r.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1024))
	if r.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "health: %s: %s %s\n", url, r.Status, strings.TrimSpace(string(body)))
		os.Exit(1)
	}
}

// healthURL completes a bare port or host:port to a /_health URL.
func healthURL(s string) string {
	if strings.Contains(s, "://") {
		return s
	}
	if strings.HasPrefix(s, ":") {
		s = "localhost" + s
	}
	if !strings.Contains(s, "/") {
		s += "/_health"
	}
	return "http://" + s
}
