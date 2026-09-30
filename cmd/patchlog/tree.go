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
	"syscall"
	"time"

	"github.com/middle-management/patchlog/internal/catalog"
	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/follow"
	"github.com/middle-management/patchlog/internal/grant"
	"github.com/middle-management/patchlog/internal/tree"
)

// treeCmd runs the tree service of Addendum B, or with -access the catalog
// service of §B.11 that also issues grants:
//
//	patchlog tree -api URL -catalog NS [-db tree.db] [-addr :8082] [-bearer GRANT] [-author NAME]
//	              [-self-placing] [-access -key SEED -kid KID [-ttl 15m] [-admin-group catalog-admins]]
//	              [-enc-key B64URL | -enc-key-file PATH]
//
// The service follows the catalog namespace and every namespace in its
// catalog.trust. -bearer is its own grant, which needs read on all of them.
// Callers of POST /grants and of private listings present an ordinary core
// grant for the catalog namespace as their identity.
//
// Listings live at /{catalog}/at/{at}/… where at is the combined checkpoint
// over the catalog and every followed content namespace (§B.5); they are
// immutable and tagged r:{ns}/{name} and ns:{ns}. Read-your-writes:
// ?min={ns}:{ns_id}, repeatable. Cache purges are logged (no CDN purger is
// wired in here).
//
// Encrypted namespaces (Addendum E) work as for patchlog index: -enc-key is
// the service's X25519 private key; listings of a sealed or e2e catalog are
// served sealed, and /_status reports what is skipped.
func treeCmd(args []string) {
	fs := flag.NewFlagSet("tree", flag.ExitOnError)
	api := fs.String("api", "http://localhost:8080", "base URL of the patch-log API")
	cat := fs.String("catalog", "", "catalog namespace to follow (required)")
	db := fs.String("db", "tree.db", "SQLite database path")
	addr := fs.String("addr", ":8082", "listen address of the tree API")
	bearer := fs.String("bearer", "", "grant for reading the catalog and its trusted namespaces (Authorization: Bearer)")
	author := fs.String("author", "", "X-Author for a -dev server")
	selfPlacing := fs.Bool("self-placing", false, "accept $parents in trusted content documents as implicit placements (§B.9)")
	access := fs.Bool("access", false, "catalog mode: derive access from $access and issue grants (§B.11); needs -key and -kid")
	keySeed := fs.String("key", "", "catalog signing key (b64url Ed25519 seed), for -access")
	kid := fs.String("kid", "", "kid of the catalog key in the catalog and content namespaces, for -access")
	ttl := fs.Duration("ttl", 15*time.Minute, "lifetime of issued grants (capped by the key's maxTtl)")
	adminGroup := fs.String("admin-group", "catalog-admins", "group whose moves skip the no-widening check")
	rebuild := fs.Bool("rebuild", false, "drop the database and replay from the beginning")
	minWait := fs.Duration("min-wait", 2*time.Second, "how long ?min= waits for the service to catch up")
	sse := fs.Bool("sse", false, "follow by server-sent events instead of long-poll")
	encKey := fs.String("enc-key", "", "the service's X25519 private key (base64url), for sealed and e2e namespaces (Addendum E)")
	encKeyFile := fs.String("enc-key-file", "", "file holding -enc-key")
	fs.Parse(args)

	if *cat == "" {
		log.Fatal("tree: -catalog is required")
	}
	var copts []client.Option
	if *bearer != "" {
		copts = append(copts, client.WithBearer(*bearer))
	}
	if *author != "" {
		copts = append(copts, client.WithAuthor(*author))
	}
	recipient := recipientKey("tree", *encKey, *encKeyFile)
	copts = append(copts, client.WithKeys(client.NewKeys(recipient)))
	c, err := client.New(*api, copts...)
	if err != nil {
		log.Fatal(err)
	}
	topt := tree.Options{Client: c, Catalog: *cat, DB: *db, Rebuild: *rebuild, SelfPlacing: *selfPlacing, MinWait: *minWait, Recipient: recipient}
	if *sse {
		topt.FollowOptions = append(topt.FollowOptions, follow.WithSSE())
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var (
		handler http.Handler
		run     func(context.Context) error
		closer  func() error
	)
	// The core may still be starting: retry opening (which reads its origin).
	for {
		if *access {
			if *keySeed == "" || *kid == "" {
				log.Fatal("tree: -access needs -key and -kid")
			}
			priv, perr := grant.ParsePrivateKey(*keySeed)
			if perr != nil {
				log.Fatal(perr)
			}
			var svc *catalog.Service
			svc, err = catalog.Open(ctx, catalog.Options{Tree: topt, Key: priv, Kid: *kid, TTL: *ttl, AdminGroup: *adminGroup})
			if err == nil {
				handler, run, closer = svc.Handler(), svc.Run, svc.Close
			}
		} else {
			var svc *tree.Service
			svc, err = tree.Open(ctx, topt)
			if err == nil {
				handler, run, closer = svc.Handler(), svc.Run, svc.Close
			}
		}
		if err == nil {
			break
		}
		if ctx.Err() != nil {
			log.Fatal(err)
		}
		log.Printf("%v; retrying", err)
		time.Sleep(time.Second)
	}
	defer closer()

	srv := &http.Server{Addr: *addr, Handler: handler, ReadHeaderTimeout: 10 * time.Second}
	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatal(err)
	}
	mode := "tree"
	if *access {
		mode = "catalog"
	}
	log.Printf("patchlog tree: %s service for %s at %s, serving on %s", mode, *cat, *api, ln.Addr())
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatal(err)
		}
	}()
	run(ctx)
	shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	srv.Shutdown(shutdown)
}
