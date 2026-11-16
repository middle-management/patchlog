package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/core"
	"github.com/middle-management/patchlog/internal/streams"
)

// streamsCmd is the stream proxy of TOOLS Addendum J.1–J.4
// (internal/streams):
//
//	patchlog streams -api URL -upstream PREFIX... [-addr 127.0.0.1:8091] [-ns streams] [-caller-ns NS]
//	                 (-grant GRANT | -grant-file FILE | -author NAME) [-public-url URL] [-flush 200ms] [-ttl 24h]
//	                 [-idle-timeout 2m] [-state FILE] [-max-request-body 1MiB] [-max-segments 8] [-max-streams 64]
//	                 [-create-ns] [-tls-cert FILE -tls-key FILE] [-insecure]
//	patchlog streams read -api URL [-grant TOKEN | -grant-file FILE] [-author NAME] [-since REV [-resource NAME]] NS/ID
//
// A caller sends POST /streams with its own grant, the upstream's URL and
// headers, and the body; the proxy creates a resource in -ns, calls
// upstream and appends what it streams, and answers with the resource's
// URL and a grant narrowed to it. The caller reads, resumes and aborts
// against the core. read prints a stream's chunks, following it to its
// end.
func streamsCmd(args []string) {
	if len(args) > 0 && args[0] == "read" {
		streamsReadCmd(args[1:])
		return
	}
	fs := flag.NewFlagSet("streams", flag.ExitOnError)
	api := fs.String("api", "http://localhost:8080", "base URL of the patch-log API")
	addr := fs.String("addr", "127.0.0.1:8091", "listen address of the proxy")
	ns := fs.String("ns", "streams", "namespace the streams are kept in: one of its own, with read: \"grant\" (§J.1)")
	callerNS := fs.String("caller-ns", "", "namespace callers' grants are verified in (GET /ns/{ns}/principal): a caller is who the core says its bearer is there. Required unless the core has authentication disabled")
	grantFlag := fs.String("grant", "", "the proxy's grant: create, append, read and purge in -ns; read grants are narrowed from it (§J.3)")
	grantFile := fs.String("grant-file", "", "file holding -grant")
	author := fs.String("author", "", "X-Author for a -dev server, which has no grants: callers then name themselves in X-Author and get no grant")
	publicURL := fs.String("public-url", "", "the core's base URL as callers reach it, for the url of an answer (default -api)")
	var upstreams multi
	fs.Var(&upstreams, "upstream", "allowed upstream: a URL prefix (scheme, host and path prefix) an Upstream-URL must fall under (repeatable; none refuses every request)")
	flush := fs.Duration("flush", 200*time.Millisecond, "least time between two appends to a stream (§J.2)")
	ttl := fs.Duration("ttl", 24*time.Hour, "how long a stream's read grants live from its creation; closed streams that old are purged (§J.4)")
	idle := fs.Duration("idle-timeout", 2*time.Minute, "a stream with no append for this long is closed with \"timeout\" (§J.2)")
	stateFile := fs.String("state", "", "file keeping the names of the open streams, so a proxy started again closes them with \"error\" (§J.2)")
	maxBody := fs.String("max-request-body", "1 MiB", "largest request body forwarded upstream")
	maxSegments := fs.Int("max-segments", 8, "most resources one upstream response may fill, each up to the namespace's documentSize (§J.1)")
	maxStreams := fs.Int("max-streams", 64, "most streams carried at once (§J.2 Pace)")
	createNS := fs.Bool("create-ns", false, "create -ns with read: \"grant\" if it doesn't exist; only over a -dev server (under grants a namespace is created with an operator grant and lists the key of the proxy's grant)")
	insecure := fs.Bool("insecure", false, "allow plain HTTP on an address other than loopback, so callers' grants and upstream credentials cross the network in the clear")
	tlsCert := fs.String("tls-cert", "", "serve HTTPS with this certificate (PEM), with -tls-key")
	tlsKey := fs.String("tls-key", "", "the private key of -tls-cert (PEM)")
	sdFlags := addShutdownFlags(fs)
	fs.Parse(args)

	if (*tlsCert == "") != (*tlsKey == "") {
		log.Fatal("streams: -tls-cert and -tls-key go together")
	}
	tls := *tlsCert != ""
	if !tls && !loopback(*addr) && !*insecure {
		log.Fatalf("streams: on %s, not a loopback address, the proxy needs -tls-cert and -tls-key (grants and upstream credentials must not cross plain HTTP), or -insecure", *addr)
	}
	if plainRemote(*api) {
		log.Printf("patchlog streams: warning: -api %s is plain HTTP to another host: grants cross the network to it in the clear", *api)
	}
	bodySize, err := core.ParseSize(*maxBody)
	if err != nil {
		log.Fatalf("streams: -max-request-body: %v", err)
	}
	grant := streamsGrant(*grantFlag, *grantFile)
	var copts []client.Option
	if grant != "" {
		copts = append(copts, client.WithBearer(grant))
	}
	if *author != "" {
		copts = append(copts, client.WithAuthor(*author))
	}
	c, err := client.New(*api, copts...)
	if err != nil {
		log.Fatal(err)
	}
	if len(upstreams) == 0 {
		log.Printf("patchlog streams: warning: no -upstream: every request will be refused")
	}
	sctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	if *createNS {
		if _, err := c.NSHead(sctx, *ns); client.IsNotFound(err) {
			if disabled, derr := c.AuthDisabled(sctx); derr != nil {
				log.Fatalf("streams: %v", derr)
			} else if !disabled {
				log.Fatalf("streams: -create-ns: namespace %s doesn't exist, and under grants it is created with an operator grant, its document listing the key that signs the proxy's grant (§C.4): create it first", *ns)
			}
			if _, err := c.CreateNamespace(sctx, *ns, map[string]any{"read": "grant"}); err != nil {
				log.Fatalf("streams: -create-ns: %v", err)
			}
			log.Printf("patchlog streams: created namespace %s", *ns)
		}
	}
	p, err := streams.New(sctx, streams.Options{Client: c, Grant: grant, NS: *ns, CallerNS: *callerNS, PublicURL: *publicURL, Upstreams: upstreams,
		Flush: *flush, TTL: *ttl, IdleTimeout: *idle, StateFile: *stateFile, MaxRequestBody: int64(bodySize), MaxSegments: *maxSegments,
		MaxStreams: *maxStreams, Logf: log.Printf})
	cancel()
	if err != nil {
		log.Fatal(err)
	}

	ctx, sigs := shutdownSignals("patchlog streams")
	go p.Run(ctx)
	// A request is small (at most -max-request-body) and answered as soon
	// as its stream exists.
	hs := &http.Server{Addr: *addr, Handler: p, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: time.Minute, IdleTimeout: 2 * time.Minute}
	ls := sdFlags.server("patchlog streams", hs, nil)
	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatal(err)
	}
	scheme := "http"
	if tls {
		scheme = "https"
	}
	log.Printf("patchlog streams: keeping streams in %s of %s, at %s://%s/streams", *ns, *api, scheme, ln.Addr())
	go func() {
		var err error
		if tls {
			err = ls.HTTP.ServeTLS(ln, *tlsCert, *tlsKey)
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
	cctx, ccancel := context.WithTimeout(context.Background(), *sdFlags.timeout)
	defer ccancel()
	if err := p.Close(cctx); err != nil {
		log.Printf("patchlog streams: closing the open streams: %v", err)
	}
}

// streamsGrant is -grant, or the content of -grant-file.
func streamsGrant(grant, file string) string {
	if file == "" {
		return grant
	}
	if grant != "" {
		log.Fatal("streams: -grant and -grant-file are exclusive")
	}
	b, err := os.ReadFile(file)
	if err != nil {
		log.Fatalf("streams: -grant-file: %v", err)
	}
	if fi, err := os.Stat(file); err == nil && loose(fi) {
		log.Printf("patchlog streams: warning: -grant-file %s may be read by others (mode %v); chmod 600 it", file, fi.Mode().Perm())
	}
	s := strings.TrimSpace(string(b))
	if s == "" {
		log.Fatalf("streams: -grant-file: %s is empty", file)
	}
	return s
}

// streamsReadCmd prints a stream's chunks to stdout, following it until
// it closes (§J.3): from the beginning, or after -since.
func streamsReadCmd(args []string) {
	fs := flag.NewFlagSet("streams read", flag.ExitOnError)
	api := fs.String("api", "http://localhost:8080", "base URL of the patch-log API")
	grantFlag := fs.String("grant", "", "the stream's read grant, as POST /streams answered it")
	grantFile := fs.String("grant-file", "", "file holding -grant")
	author := fs.String("author", "", "X-Author for a -dev server")
	since := fs.String("since", "", "resume after this revision: the last one seen")
	resource := fs.String("resource", "", "with -since, the resource that revision is of, when the stream had continued in another (default the stream's id)")
	fs.Parse(args)
	target, rest := fs.Arg(0), 0
	// Flags may follow NS/ID too.
	if fs.NArg() > 1 {
		fs.Parse(fs.Args()[1:])
		rest = fs.NArg()
	}
	ns, id, ok := strings.Cut(target, "/")
	if !ok || !client.ValidNSName(ns) || !client.ValidResourceName(id) || rest > 0 {
		log.Fatal("usage: patchlog streams read -api URL [-grant TOKEN | -grant-file FILE] [-author NAME] [-since REV [-resource NAME]] NS/ID")
	}
	var copts []client.Option
	if g := streamsGrant(*grantFlag, *grantFile); g != "" {
		copts = append(copts, client.WithBearer(g))
	}
	if *author != "" {
		copts = append(copts, client.WithAuthor(*author))
	}
	c, err := client.New(*api, copts...)
	if err != nil {
		log.Fatal(err)
	}
	var pos streams.Position
	if *since != "" {
		pos = streams.Position{Resource: id, Rev: *since}
		if *resource != "" {
			pos.Resource = *resource
		}
	} else if *resource != "" {
		log.Fatal("streams read: -resource goes with -since")
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
