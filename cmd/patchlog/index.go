package main

import (
	"context"
	"crypto/ecdh"
	"encoding/json"
	"errors"
	"flag"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/derived"
	"github.com/middle-management/patchlog/internal/edge"
	"github.com/middle-management/patchlog/internal/follow"
	"github.com/middle-management/patchlog/internal/index"
	"github.com/middle-management/patchlog/internal/seal"
)

// indexCmd runs the indexing service of Addendum A:
//
//	patchlog index [-api http://localhost:8080] [-db index.db] [-addr :8081] -ns matches,docs
//	               [-bearer GRANT] [-author NAME] [-branches] [-rebuild] [-untyped-listing=false]
//	               [-enc-key B64URL | -enc-key-file PATH] [-purge-url URL]... [-edge-secret FILE [-edge-header NAME]]
//
// Results at /{ns}/at/{ns_id} are immutable and tagged idx:{ns} and
// r:{ns}/{name} per hit; only the current checkpoint's results are kept.
// Read-your-writes: ?min={ns_id} or ?min={ns}:{ns_id}, repeatable. Cache
// purges go to the CDN at -purge-url (repeatable), and are logged if it is
// unset.
//
// Encrypted namespaces (Addendum E): sealed ones are read with keys from
// POST /ns/{ns}/keys with -bearer's grant; -enc-key is the service's X25519
// private key (base64url scalar), which unwraps keys wrapped to the grant's
// enc and reads e2e namespaces whose keyring names its public key (logged
// at start). Results over them are served sealed; see /_status for skipped
// namespaces.
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
	fetchConc := fs.Int("fetch-concurrency", 8, "how many documents the index fetches at once while applying the log, across all namespaces")
	encKey := fs.String("enc-key", "", "the service's X25519 private key (base64url), for sealed and e2e namespaces (Addendum E)")
	encKeyFile := fs.String("enc-key-file", "", "file holding -enc-key")
	var purgeURLs multi
	fs.Var(&purgeURLs, "purge-url", purgeURLUsage)
	edgeSecret := fs.String("edge-secret", "", edgeSecretUsage)
	edgeHeader := fs.String("edge-header", edge.DefaultHeader, edgeHeaderUsage)
	corsFlags := addCORSFlags(fs)
	sdFlags := addShutdownFlags(fs)
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
	recipient := recipientKey("index", *encKey, *encKeyFile)
	copts = append(copts, client.WithKeys(client.NewKeys(recipient)))
	c, err := client.New(*api, copts...)
	if err != nil {
		log.Fatal(err)
	}

	ctx, sigs := shutdownSignals("patchlog index")

	opt := index.Options{Client: c, DB: *db, Namespaces: nss, Branches: *branches, Rebuild: *rebuild,
		UntypedListing: *untyped, MinWait: *minWait, Recipient: recipient, FetchConcurrency: *fetchConc}
	if *sse {
		opt.FollowOptions = append(opt.FollowOptions, followSSE())
	}
	purger := cdnPurger(purgeURLs)
	if purger != nil {
		opt.Purger = purger
	}
	opt.Edge = edgeVerifier(*edgeSecret, *edgeHeader)
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
	defer closePurger(purger) // after ix.Close: its last purges are sent
	defer ix.Close()
	if !ix.FTS() {
		log.Printf("index: FTS5 is not available; text search uses LIKE")
	}

	srv := &http.Server{Addr: *addr, Handler: corsFlags.wrap(ix.Handler()), ReadHeaderTimeout: 10 * time.Second}
	ls := sdFlags.server("patchlog index", srv, nil)
	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("patchlog index: following %s at %s, serving on %s", strings.Join(nss, ","), *api, ln.Addr())
	serveOn(ls, ln)
	// The followers keep the index current while requests drain; they
	// stop after the HTTP server, and the database closes (deferred) last.
	runCtx, stopRun := context.WithCancel(context.Background())
	runDone := make(chan struct{})
	go func() {
		defer close(runDone)
		if err := ix.Run(runCtx); err != nil && !errors.Is(err, context.Canceled) {
			log.Printf("patchlog index: following stopped: %v", err)
		}
	}()
	select {
	case <-ctx.Done():
	case <-runDone:
	}
	forceOnSecond(sigs)
	ls.Shutdown()
	stopRun()
	<-runDone
}

func followSSE() follow.Option { return follow.WithSSE() }

// recipientKey parses the service's X25519 private key from -enc-key or
// -enc-key-file (nil if neither is set) and logs its public JWK, which
// goes into the service grant's enc and e2e keyrings.
func recipientKey(svc, value, file string) *ecdh.PrivateKey {
	var (
		k   *ecdh.PrivateKey
		err error
	)
	switch {
	case value != "" && file != "":
		log.Fatalf("%s: -enc-key and -enc-key-file are exclusive", svc)
	case value != "":
		k, err = derived.ParseRecipientKey(value)
	case file != "":
		k, err = derived.LoadRecipientKey(file)
	default:
		return nil
	}
	if err != nil {
		log.Fatalf("%s: %v", svc, err)
	}
	jwk, _ := json.Marshal(seal.RecipientJWK(k.PublicKey()))
	log.Printf("%s: recipient key %s (enc of the service grant, keyring recipient)", svc, jwk)
	return k
}
