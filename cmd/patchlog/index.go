package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/follow"
	"github.com/middle-management/patchlog/internal/index"
)

// indexCmd runs the indexing service of Addendum A:
//
//	patchlog index [-api http://localhost:8080] [-db index.db] [-addr :8081] -ns matches,docs
//	               [-bearer GRANT] [-author NAME] [-branches] [-rebuild] [-untyped-listing=false]
func indexCmd(args []string) {
	fs := flag.NewFlagSet("index", flag.ExitOnError)
	api := fs.String("api", "http://localhost:8080", "base URL of the patch-log API")
	db := fs.String("db", "index.db", "SQLite database path of the index")
	addr := fs.String("addr", ":8081", "listen address of the query API")
	nsList := fs.String("ns", "", "comma-separated namespaces to follow (required)")
	bearer := fs.String("bearer", "", "grant for reading the namespaces (Authorization: Bearer)")
	author := fs.String("author", "", "X-Author for a -dev server")
	branches := fs.Bool("branches", false, "also follow branches, building a preview index per branch (§F.8)")
	rebuild := fs.Bool("rebuild", false, "drop the index and replay from the beginning (§A.6)")
	untyped := fs.Bool("untyped-listing", true, "list untyped documents in plain listings (never in text/facet/sort queries)")
	minWait := fs.Duration("min-wait", 2*time.Second, "how long ?min= waits for the index to catch up (§A.5)")
	sse := fs.Bool("sse", false, "follow by server-sent events instead of long-poll")
	fs.Parse(args)

	var nss []string
	for _, n := range strings.Split(*nsList, ",") {
		if n = strings.TrimSpace(n); n != "" {
			nss = append(nss, n)
		}
	}
	if len(nss) == 0 {
		log.Fatal("index: -ns is required")
	}
	var copts []client.Option
	if *bearer != "" {
		copts = append(copts, client.WithBearer(*bearer))
	}
	if *author != "" {
		copts = append(copts, client.WithAuthor(*author))
	}
	c, err := client.New(*api, copts...)
	if err != nil {
		log.Fatal(err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	opt := index.Options{Client: c, DB: *db, Namespaces: nss, Branches: *branches, Rebuild: *rebuild,
		UntypedListing: *untyped, MinWait: *minWait}
	if *sse {
		opt.FollowOptions = append(opt.FollowOptions, followSSE())
	}
	// The core may still be starting: retry reading its origin.
	var ix *index.Index
	for {
		ix, err = index.Open(ctx, opt)
		if err == nil {
			break
		}
		if ctx.Err() != nil {
			log.Fatal(err)
		}
		log.Printf("%v; retrying", err)
		time.Sleep(time.Second)
	}
	defer ix.Close()
	if !ix.FTS() {
		log.Printf("index: FTS5 is not available; text search uses LIKE")
	}

	srv := &http.Server{Addr: *addr, Handler: ix.Handler(), ReadHeaderTimeout: 10 * time.Second}
	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("patchlog index: following %s at %s, serving on %s", strings.Join(nss, ","), *api, ln.Addr())
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatal(err)
		}
	}()
	ix.Run(ctx)
	shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	srv.Shutdown(shutdown)
}

func followSSE() follow.Option { return follow.WithSSE() }
