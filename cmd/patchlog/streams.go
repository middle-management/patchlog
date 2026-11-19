package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/streams"
)

// streamsCmd is the stream proxy of TOOLS Addendum J.1–J.4
// (internal/streams), and with read a reader of one stream.
//
// A caller sends POST /streams with its own grant, the upstream's URL and
// headers, and the body; the proxy creates a resource in --ns, calls
// upstream and appends what it streams, and answers with the resource's
// URL and a grant narrowed to it. The caller reads, resumes and aborts
// against the core.
type streamsCmd struct {
	API            string        `arg:"--api,env:PATCHLOG_API" default:"http://localhost:8080" placeholder:"URL" help:"base URL of the patch-log API"`
	Addr           string        `arg:"--addr" default:"127.0.0.1:8091" help:"listen address of the proxy"`
	NS             string        `arg:"--ns" default:"streams" help:"namespace the streams are kept in: one of its own, with read: \"grant\" (§J.1)"`
	CallerNS       string        `arg:"--caller-ns" placeholder:"NS" help:"namespace callers' grants are verified in (GET /ns/{ns}/principal): a caller is who the core says its bearer is there. Required unless the core has authentication disabled"`
	Bearer         string        `arg:"--bearer,env:PATCHLOG_BEARER" placeholder:"GRANT" help:"the proxy's grant: create, append, read and purge in --ns; read grants are narrowed from it (§J.3)"`
	BearerFile     string        `arg:"--bearer-file,env:PATCHLOG_BEARER_FILE" placeholder:"FILE" help:"file holding --bearer (exclusive with it)"`
	Author         string        `arg:"--author,env:PATCHLOG_AUTHOR" placeholder:"NAME" help:"X-Author for a --dev server, which has no grants: callers then name themselves in X-Author and get no grant"`
	PublicURL      string        `arg:"--public-url" placeholder:"URL" help:"the core's base URL as callers reach it, for the url of an answer (default --api)"`
	Upstream       []string      `arg:"--upstream,separate" placeholder:"PREFIX" help:"allowed upstream: a URL prefix (scheme, host and path prefix) an Upstream-URL must fall under (repeatable; none refuses every request)"`
	Flush          time.Duration `arg:"--flush" default:"200ms" placeholder:"DURATION" help:"least time between two appends to a stream (§J.2)"`
	TTL            time.Duration `arg:"--ttl" default:"24h" placeholder:"DURATION" help:"how long a stream's read grants live from its creation; closed streams that old are purged (§J.4)"`
	IdleTimeout    time.Duration `arg:"--idle-timeout" default:"2m" placeholder:"DURATION" help:"a stream with no append for this long is closed with \"timeout\", by any proxy: the deployment's one time, so give every proxy of --ns the same (§J.2 Restarts)"`
	State          string        `arg:"--state" placeholder:"FILE" help:"file keeping the names of the open streams, so a proxy started again closes them with \"error\" (§J.2)"`
	MaxRequestBody byteSize      `arg:"--max-request-body" default:"1 MiB" placeholder:"SIZE" help:"largest request body forwarded upstream"`
	MaxSegments    int           `arg:"--max-segments" default:"8" placeholder:"N" help:"most resources one upstream response may fill, each up to the namespace's documentSize, or --segment-size (§J.1)"`
	SegmentSize    byteSize      `arg:"--segment-size" placeholder:"SIZE" help:"size at which a stream continues in its next resource, where below the namespace's documentSize: each append costs the stream's size so far, so 256 KiB keeps appends fast (§J.1); 0 is documentSize"`
	MaxStreams     int           `arg:"--max-streams" default:"64" placeholder:"N" help:"most streams carried at once (§J.2 Pace)"`
	CreateNS       bool          `arg:"--create-ns" help:"create --ns with read: \"grant\" if it doesn't exist; only over a --dev server (under grants a namespace is created with an operator grant and lists the key of the proxy's grant)"`
	Insecure       bool          `arg:"--insecure" help:"allow plain HTTP on an address other than loopback, so callers' grants and upstream credentials cross the network in the clear"`
	TLSCert        string        `arg:"--tls-cert" placeholder:"FILE" help:"serve HTTPS with this certificate (PEM), with --tls-key"`
	TLSKey         string        `arg:"--tls-key" placeholder:"FILE" help:"the private key of --tls-cert (PEM)"`
	shutdownArgs

	// Read is the one client command here: with it the proxy's flags
	// aren't used.
	Read *streamsReadCmd `arg:"subcommand:read" help:"print a stream's chunks, following it to its end (patchlog streams read NS/ID)"`
}

func (a *streamsCmd) run(string) {
	if (a.TLSCert == "") != (a.TLSKey == "") {
		log.Fatal("streams: --tls-cert and --tls-key go together")
	}
	tls := a.TLSCert != ""
	if !tls && !loopback(a.Addr) && !a.Insecure {
		log.Fatalf("streams: on %s, not a loopback address, the proxy needs --tls-cert and --tls-key (grants and upstream credentials must not cross plain HTTP), or --insecure", a.Addr)
	}
	if plainRemote(a.API) {
		log.Printf("patchlog streams: warning: --api %s is plain HTTP to another host: grants cross the network to it in the clear", a.API)
	}
	// --bearer-file was read into Bearer when the flags were
	// (resolveSecretFiles), as for every command.
	var copts []client.Option
	if a.Bearer != "" {
		copts = append(copts, client.WithBearer(a.Bearer))
	}
	if a.Author != "" {
		copts = append(copts, client.WithAuthor(a.Author))
	}
	c, err := client.New(a.API, copts...)
	if err != nil {
		log.Fatal(err)
	}
	if len(a.Upstream) == 0 {
		log.Printf("patchlog streams: warning: no --upstream: every request will be refused")
	}
	sctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	if a.CreateNS {
		if _, err := c.NSHead(sctx, a.NS); client.IsNotFound(err) {
			if disabled, derr := c.AuthDisabled(sctx); derr != nil {
				log.Fatalf("streams: %v", derr)
			} else if !disabled {
				log.Fatalf("streams: --create-ns: namespace %s doesn't exist, and under grants it is created with an operator grant, its document listing the key that signs the proxy's grant (§C.4): create it first", a.NS)
			}
			if _, err := c.CreateNamespace(sctx, a.NS, map[string]any{"read": "grant"}); err != nil {
				log.Fatalf("streams: --create-ns: %v", err)
			}
			log.Printf("patchlog streams: created namespace %s", a.NS)
		}
	}
	p, err := streams.New(sctx, streams.Options{Client: c, Grant: a.Bearer, NS: a.NS, CallerNS: a.CallerNS, PublicURL: a.PublicURL, Upstreams: a.Upstream,
		Flush: a.Flush, TTL: a.TTL, IdleTimeout: a.IdleTimeout, StateFile: a.State, MaxRequestBody: int64(a.MaxRequestBody), MaxSegments: a.MaxSegments, SegmentSize: int(a.SegmentSize),
		MaxStreams: a.MaxStreams, Logf: log.Printf})
	cancel()
	if err != nil {
		log.Fatal(err)
	}

	ctx, sigs := shutdownSignals("patchlog streams")
	go p.Run(ctx)
	// A request is small (at most --max-request-body) and answered as
	// soon as its stream exists.
	hs := &http.Server{Addr: a.Addr, Handler: p, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: time.Minute, IdleTimeout: 2 * time.Minute}
	ls := a.shutdownArgs.server("patchlog streams", hs, nil)
	ln, err := net.Listen("tcp", a.Addr)
	if err != nil {
		log.Fatal(err)
	}
	scheme := "http"
	if tls {
		scheme = "https"
	}
	log.Printf("patchlog streams: keeping streams in %s of %s, at %s://%s/streams", a.NS, a.API, scheme, ln.Addr())
	go func() {
		var err error
		if tls {
			err = ls.HTTP.ServeTLS(ln, a.TLSCert, a.TLSKey)
		} else {
			err = ls.HTTP.Serve(ln)
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatal(err)
		}
	}()
	<-ctx.Done()
	forceOnSecond(sigs)
	ls.Shutdown()
	// Upstream can't be resumed: the open streams are closed with "error".
	cctx, ccancel := context.WithTimeout(context.Background(), a.ShutdownTimeout)
	defer ccancel()
	if err := p.Close(cctx); err != nil {
		log.Printf("patchlog streams: closing the open streams: %v", err)
	}
}

// streamsReadCmd is patchlog streams read NS/ID: it prints a stream's
// chunks to stdout, following it until it closes (§J.3), from the
// beginning or after --since.
type streamsReadCmd struct {
	API        string `arg:"--api,env:PATCHLOG_API" default:"http://localhost:8080" placeholder:"URL" help:"base URL of the patch-log API"`
	Bearer     string `arg:"--bearer,env:PATCHLOG_BEARER" placeholder:"GRANT" help:"the stream's read grant, as POST /streams answered it"`
	BearerFile string `arg:"--bearer-file,env:PATCHLOG_BEARER_FILE" placeholder:"FILE" help:"file holding --bearer (exclusive with it)"`
	Author     string `arg:"--author,env:PATCHLOG_AUTHOR" placeholder:"NAME" help:"X-Author for a --dev server"`
	Since      string `arg:"--since" placeholder:"REV" help:"resume after this revision: the last one seen"`
	Resource   string `arg:"--resource" placeholder:"NAME" help:"with --since, the resource that revision is of, when the stream had continued in another (default the stream's id)"`
	Target     string `arg:"positional,required" placeholder:"NS/ID" help:"the stream: its namespace and id"`
}

func (a *streamsReadCmd) run(string) {
	ns, id, ok := strings.Cut(a.Target, "/")
	if !ok || !client.ValidNSName(ns) || !client.ValidResourceName(id) {
		log.Fatal("streams read: the stream is given as NS/ID")
	}
	var copts []client.Option
	if a.Bearer != "" {
		copts = append(copts, client.WithBearer(a.Bearer))
	}
	if a.Author != "" {
		copts = append(copts, client.WithAuthor(a.Author))
	}
	c, err := client.New(a.API, copts...)
	if err != nil {
		log.Fatal(err)
	}
	var pos streams.Position
	if a.Since != "" {
		pos = streams.Position{Resource: id, Rev: a.Since}
		if a.Resource != "" {
			pos.Resource = a.Resource
		}
	} else if a.Resource != "" {
		log.Fatal("streams read: --resource goes with --since")
	}
	ctx, sigs := shutdownSignals("patchlog streams read")
	forceOnSecond(sigs)
	closed, err := streams.Follow(ctx, c, ns, id, pos, func(b streams.Batch) error {
		for _, chunk := range b.Chunks {
			if _, err := os.Stdout.WriteString(chunk); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		log.Fatalf("streams read: %v", err)
	}
	msg := "closed: " + closed.Reason
	if closed.Error != "" {
		msg += ": " + closed.Error
	}
	fmt.Fprintln(os.Stderr, msg)
	if closed.Reason != streams.ReasonComplete {
		os.Exit(1)
	}
}
