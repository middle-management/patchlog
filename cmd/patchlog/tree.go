package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/middle-management/patchlog/internal/catalog"
	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/edge"
	"github.com/middle-management/patchlog/internal/follow"
	"github.com/middle-management/patchlog/internal/grant"
	"github.com/middle-management/patchlog/internal/release"
	"github.com/middle-management/patchlog/internal/tree"
)

// treeCmd runs the tree service of Addendum B, or with -access the catalog
// service of §B.11 that also issues grants:
//
//	patchlog tree -api URL -catalog NS[,NS]... [-db tree.db] [-addr :8082] [-bearer GRANT] [-author NAME] [-release /r/{ns}/{release}]
//	              [-self-placing] [-access -key SEED -kid KID [-ttl 15m] [-admin-group catalog-admins]
//	              [-merge-key SEED -merge-kid KID -merge-service SUB [-merge-ttl 5m]]]
//	              [-enc-key B64URL | -enc-key-file PATH] [-purge-url URL]... [-edge-secret FILE [-edge-header NAME]]
//
// The service follows the catalog namespace and every namespace in its
// catalog.trust. -bearer is its own grant, which needs read on all of them.
//
// -catalog may name several catalogs (repeated, or comma-separated): each
// gets its own tree service, database and followers, and one origin serves
// them all, each at /{catalog}/… (tree.Multi). Their databases are -db with
// {catalog} replaced by the catalog's name, or, if -db has no {catalog},
// with -{catalog} before its extension (tree.db -> tree-topics.db). -access
// serves exactly one catalog (its /grants are not per catalog).
// Callers of POST /grants and of private listings present an ordinary core
// grant for the catalog namespace as their identity.
//
// Listings live at /{catalog}/at/{at}/… where at is the combined checkpoint
// over the catalog and every followed content namespace (§B.5); they are
// immutable and tagged r:{ns}/{name} and ns:{ns}. Read-your-writes:
// ?min={ns}:{ns_id}, repeatable. Cache purges go to the CDN at -purge-url
// (repeatable), and are logged if it is unset.
//
// Encrypted namespaces (Addendum E) work as for patchlog index: -enc-key is
// the service's X25519 private key; listings of a sealed or e2e catalog are
// served sealed, and /_status reports what is skipped.
func treeCmd(args []string) {
	fs := flag.NewFlagSet("tree", flag.ExitOnError)
	api := fs.String("api", "http://localhost:8080", "base URL of the patch-log API")
	var cats multi
	fs.Var(&cats, "catalog", "catalog namespace to follow (required; repeatable or comma-separated)")
	db := fs.String("db", "tree.db", "SQLite database path; with several catalogs, may contain {catalog}")
	addr := fs.String("addr", ":8082", "listen address of the tree API")
	bearer := fs.String("bearer", "", "grant for reading the catalog and its trusted namespaces (Authorization: Bearer)")
	author := fs.String("author", "", "X-Author for a -dev server")
	selfPlacing := fs.Bool("self-placing", false, "accept $parents in trusted content documents as implicit placements (§B.9)")
	access := fs.Bool("access", false, "catalog mode: derive access from $access and issue grants (§B.11); needs -key and -kid")
	keySeed := fs.String("key", "", "catalog signing key (b64url Ed25519 seed), for -access")
	kid := fs.String("kid", "", "kid of the catalog key in the catalog and content namespaces, for -access")
	ttl := fs.Duration("ttl", 15*time.Minute, "lifetime of issued grants (capped by the key's maxTtl)")
	adminGroup := fs.String("admin-group", "catalog-admins", "group whose moves skip the no-widening check")
	mergeSeed := fs.String("merge-key", "", "merge grant signing key (b64url Ed25519 seed), a key of its own used for nothing else (§F.8); without it POST /merge-grants is refused")
	mergeKid := fs.String("merge-kid", "", "the merge key's kid in the catalog namespace")
	mergeService := fs.String("merge-service", "", "the merge service's sub: merge grants are issued only to it, and name it as their root (§F.8)")
	mergeTTL := fs.Duration("merge-ttl", 5*time.Minute, "lifetime of merge grants (capped by the merge key's maxTtl)")
	rel := fs.String("release", "", "preview a release (§B.5, §F.9): follow the branches the release document /r/{ns}/{release} lists in place of their bases; previews only, no grants (not with -access); read when the service starts")
	rebuild := fs.Bool("rebuild", false, "drop the database and replay from the beginning")
	minWait := fs.Duration("min-wait", 2*time.Second, "how long ?min= waits for the service to catch up")
	sse := fs.Bool("sse", false, "follow by server-sent events instead of long-poll")
	encKey := fs.String("enc-key", "", "the service's X25519 private key (base64url), for sealed and e2e namespaces (Addendum E)")
	encKeyFile := fs.String("enc-key-file", "", "file holding -enc-key")
	var purgeURLs multi
	fs.Var(&purgeURLs, "purge-url", purgeURLUsage)
	edgeSecret := fs.String("edge-secret", "", edgeSecretUsage)
	edgeHeader := fs.String("edge-header", edge.DefaultHeader, edgeHeaderUsage)
	corsFlags := addCORSFlags(fs)
	sdFlags := addShutdownFlags(fs)
	fs.Parse(args)

	catalogs := splitCatalogs(cats)
	if len(catalogs) == 0 {
		log.Fatal("tree: -catalog is required")
	}
	if *access && len(catalogs) > 1 {
		log.Fatal("tree: -access serves one catalog; run one catalog service per catalog")
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
	topt := tree.Options{Client: c, Catalog: catalogs[0], DB: treeDB(*db, catalogs[0], len(catalogs)), Rebuild: *rebuild, SelfPlacing: *selfPlacing, MinWait: *minWait, Recipient: recipient}
	if *sse {
		topt.FollowOptions = append(topt.FollowOptions, follow.WithSSE())
	}
	purger := cdnPurger(purgeURLs)
	if purger != nil {
		topt.Purger = purger
	}
	topt.Edge = edgeVerifier(*edgeSecret, *edgeHeader)

	ctx, sigs := shutdownSignals("patchlog tree")
	if *rel != "" {
		if *access {
			log.Fatal("tree: a release preview serves previews only and issues no grants (§B.5): -release can't be combined with -access")
		}
		for {
			loaded, lerr := release.Load(ctx, c, *rel)
			if lerr == nil {
				topt.Branches = loaded.Doc.Aliases()
				log.Printf("patchlog tree: previewing release %s at %s: %v", loaded.Ref.Live(), loaded.Ref.Rev, topt.Branches)
				break
			}
			if ctx.Err() != nil {
				log.Fatal(lerr)
			}
			log.Printf("tree: reading the release document: %v; retrying", lerr)
			time.Sleep(time.Second)
		}
	}

	var (
		handler http.Handler
		run     func(context.Context) error
		closer  func() error
	)
	if *mergeSeed != "" && (*mergeKid == "" || *mergeService == "" || *mergeKid == *kid) {
		log.Fatal("tree: -merge-key needs -merge-kid (not the catalog's -kid) and -merge-service")
	}
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
			copt := catalog.Options{Tree: topt, Key: priv, Kid: *kid, TTL: *ttl, AdminGroup: *adminGroup,
				MergeKid: *mergeKid, MergeService: *mergeService, MergeTTL: *mergeTTL}
			if *mergeSeed != "" {
				if copt.MergeKey, perr = grant.ParsePrivateKey(*mergeSeed); perr != nil {
					log.Fatal(perr)
				}
			}
			var svc *catalog.Service
			svc, err = catalog.Open(ctx, copt)
			if err == nil {
				handler, run, closer = svc.Handler(), svc.Run, svc.Close
			}
		} else {
			handler, run, closer, err = openTrees(ctx, topt, catalogs, *db)
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
	defer closePurger(purger) // after closer: its last purges are sent
	defer closer()

	srv := &http.Server{Addr: *addr, Handler: corsFlags.wrap(handler), ReadHeaderTimeout: 10 * time.Second}
	ls := sdFlags.server("patchlog tree", srv, nil)
	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatal(err)
	}
	mode := "tree"
	if *access {
		mode = "catalog"
	}
	log.Printf("patchlog tree: %s service for %s at %s, serving on %s", mode, strings.Join(catalogs, ", "), *api, ln.Addr())
	serveOn(ls, ln)
	// The followers keep the listings current while requests drain; they
	// stop after the HTTP server, and the databases close (deferred) last.
	runCtx, stopRun := context.WithCancel(context.Background())
	runDone := make(chan struct{})
	go func() {
		defer close(runDone)
		if err := run(runCtx); err != nil && !errors.Is(err, context.Canceled) {
			log.Printf("patchlog tree: following stopped: %v", err)
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

// splitCatalogs flattens repeated and comma-separated -catalog values,
// dropping duplicates.
func splitCatalogs(vals []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, v := range vals {
		for _, c := range strings.Split(v, ",") {
			if c = strings.TrimSpace(c); c != "" && !seen[c] {
				seen[c] = true
				out = append(out, c)
			}
		}
	}
	return out
}

// treeDB is the database of catalog cat when n catalogs are served.
func treeDB(db, cat string, n int) string {
	if strings.Contains(db, "{catalog}") {
		return strings.ReplaceAll(db, "{catalog}", cat)
	}
	if n <= 1 {
		return db
	}
	ext := filepath.Ext(db)
	return strings.TrimSuffix(db, ext) + "-" + cat + ext
}

// openTrees opens one tree service per catalog (topt is the first's
// options) and serves them on one handler; it closes what it opened if one
// fails.
func openTrees(ctx context.Context, topt tree.Options, catalogs []string, db string) (http.Handler, func(context.Context) error, func() error, error) {
	var svcs []*tree.Service
	closeAll := func() error {
		var first error
		for _, s := range svcs {
			if err := s.Close(); err != nil && first == nil {
				first = err
			}
		}
		return first
	}
	for _, cat := range catalogs {
		o := topt
		o.Catalog, o.DB = cat, treeDB(db, cat, len(catalogs))
		s, err := tree.Open(ctx, o)
		if err != nil {
			closeAll()
			return nil, nil, nil, fmt.Errorf("catalog %s: %w", cat, err)
		}
		svcs = append(svcs, s)
	}
	if len(svcs) == 1 {
		return svcs[0].Handler(), svcs[0].Run, svcs[0].Close, nil
	}
	h, err := tree.Multi(svcs...)
	if err != nil {
		closeAll()
		return nil, nil, nil, err
	}
	run := func(ctx context.Context) error {
		var wg sync.WaitGroup
		errs := make([]error, len(svcs))
		for i, s := range svcs {
			wg.Add(1)
			go func() { defer wg.Done(); errs[i] = s.Run(ctx) }()
		}
		wg.Wait()
		return errors.Join(errs...)
	}
	return h, run, closeAll, nil
}
