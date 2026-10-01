package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/middle-management/patchlog/internal/lifecycle"
)

// shutdownFlags are the -shutdown-* flags of serve, index and tree.
type shutdownFlags struct {
	timeout, delay *time.Duration
}

func addShutdownFlags(fs *flag.FlagSet) *shutdownFlags {
	return &shutdownFlags{
		timeout: fs.Duration("shutdown-timeout", lifecycle.DefaultTimeout, "on SIGTERM/SIGINT, how long in-flight requests are waited for before they are cancelled (long-polls and event streams end at once)"),
		delay:   fs.Duration("shutdown-delay", 0, "on SIGTERM/SIGINT, how long to keep serving with "+lifecycle.HealthPath+" answering 503 before stopping, so load balancers take the instance out of rotation first"),
	}
}

// server wraps srv with the health endpoints (ready: /_ready's check, may
// be nil) and the phased shutdown the flags configure.
func (f *shutdownFlags) server(name string, srv *http.Server, ready func(context.Context) error) *lifecycle.Server {
	return lifecycle.New(srv, lifecycle.Options{Name: name, Timeout: *f.timeout, Delay: *f.delay, Ready: ready, Logf: log.Printf})
}

// shutdownSignals returns a context cancelled by the first SIGINT or
// SIGTERM, and the channel later signals arrive on (forceOnSecond).
func shutdownSignals(name string) (context.Context, <-chan os.Signal) {
	sigs := lifecycle.Signals()
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		sig := <-sigs
		log.Printf("%s: %v: shutting down (a second signal exits immediately)", name, sig)
		cancel()
	}()
	return ctx, sigs
}

// serveOn serves ls on ln in the background; a serve error is fatal.
func serveOn(ls *lifecycle.Server, ln net.Listener) {
	go func() {
		if err := ls.HTTP.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatal(err)
		}
	}()
}

// forceOnSecond makes the next signal exit the process at once.
func forceOnSecond(sigs <-chan os.Signal) { lifecycle.ForceOnSignal(sigs, log.Printf, nil) }
