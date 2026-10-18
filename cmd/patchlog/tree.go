package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/middle-management/patchlog/internal/catalog"
	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/edge"
	"github.com/middle-management/patchlog/internal/follow"
	"github.com/middle-management/patchlog/internal/grant"
	"github.com/middle-management/patchlog/internal/tree"
)

// treeCmd runs the tree service of Addendum B, or with -access the catalog
// service of §B.11 that also issues grants:
//
//	patchlog tree -api URL -catalog NS[,NS]... [-db tree.db] [-addr :8082] [-bearer GRANT] [-author NAME] [-release /r/{ns}/{release}]
//	              [-self-placing] [-access -key SEED -kid KID [-ttl 15m] [-admin-group catalog-admins]
//	              [-merge-key SEED -merge-kid KID -merge-service SUB [-merge-ttl 5m]]
//	              [-edge-grant-key [KID=]FILE]... [-edge-grant-kid KID] [-origin-edge-grant-kid KID[,KID]]... [-exchange-rate RATE,BURST]]
//	              [-enc-key B64URL | -enc-key-file PATH] [-purge-url URL]... [-edge-secret FILE [-edge-header NAME] [-edge-prefix-header NAME]]
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
// Listings live at /{catalog}/at/{at}/…, or for a reader with a grant at
// /{catalog}/g/{gs}/at/{at}/…, the subject set first (§B.11.5), where at
// is the combined checkpoint over the catalog and every followed content
// namespace (§B.5); they are
// immutable, answered only at the canonical form of their query (§A.5), and
// tagged r:{ns}/{name} and ns:{ns}. Read-your-writes: ?min={ns}:{ns_id},
// repeatable, which always redirects (§A.5). Cache purges go to the CDN at
// -purge-url (repeatable), and are logged if it is unset.
//
// With -access the service also mints edge grants of its own for its
// listings (§B.11.5, §C.5): POST /edge-grants exchanges a caller's grants
// for a cookie bound to its subject set, /{catalog}/g/{gs}, or to
// /{catalog}/g/all for a reader of the catalog and every trusted namespace
// as a whole, and DELETE /edge-grants?prefix=… withdraws them. They are
// signed with the last -edge-grant-key [KID=]FILE, a key of the service's
// own that the origin never holds (without it, a random one per process),
// and accepted under any, so its keys rotate as the origin's do; a plain
// FILE is named -edge-grant-kid (default catalog-{catalog}). No kid of
// the service's may be one of the origin's (-origin-edge-grant-kid,
// repeatable or comma-separated, default origin, which must list every
// kid the origin holds as it rotates): each key vouches only for its own
// prefixes. Each exchange draws one token from the
// exchangeRate bucket of each principal it names (-exchange-rate
// RATE,BURST; 429 when empty). A read under one, without
// Authorization, is the subject set's, and gets edge lifetimes behind a
// verifying edge (-edge-secret) that checked it with the service's kid.
// A catalog named r or ns mints none: its prefixes would overlap the
// core's.
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
	rel := fs.String("release", "", "preview a release (§B.5, §F.9): follow the branches the release document /r/{ns}/{release} lists in place of their bases; previews only, no grants (not with -access), one catalog; the document's log is followed, so a new revision (a rebase's successors) takes effect without a restart")
	rebuild := fs.Bool("rebuild", false, "drop the database and replay from the beginning")
	minWait := fs.Duration("min-wait", 2*time.Second, "how long ?min= waits for the service to catch up")
	sse := fs.Bool("sse", false, "follow by server-sent events instead of long-poll")
	encKey := fs.String("enc-key", "", "the service's X25519 private key (base64url), for sealed and e2e namespaces (Addendum E)")
	encKeyFile := fs.String("enc-key-file", "", "file holding -enc-key")
	var purgeURLs multi
	fs.Var(&purgeURLs, "purge-url", purgeURLUsage)
	edgeSecret := fs.String("edge-secret", "", edgeSecretUsage)
	edgeHeader := fs.String("edge-header", edge.DefaultHeader, edgeHeaderUsage)
	edgePrefixHeader := fs.String("edge-prefix-header", edge.DefaultPrefixHeader, edgePrefixHeaderUsage)
	var edgeGrantKeys multi
	fs.Var(&edgeGrantKeys, "edge-grant-key", "[KID=]FILE: a file holding a key the catalog service signs its own edge-grant cookies with (§B.11.5, §C.5), named KID (a plain FILE takes -edge-grant-kid), for -access: a key of its own that the origin never holds, so neither one of the origin's -edge-grant-key files nor the key derived from -edge-secret (at least 16 bytes); repeatable, to rotate keys as the origin's rotate: cookies under any are accepted, and the last given signs new ones. Without it, a random one per process, so cookies don't survive a restart or reach another instance")
	edgeGrantKid := fs.String("edge-grant-kid", "", "the name (kid) of the service's edge-grant key given as a plain -edge-grant-key FILE, or of the random one, which its cookies carry and a verifying edge looks the key up by (§C.5 \"Format\"), for -access; default catalog-{catalog}. No kid of the service's may be one of the origin's (-origin-edge-grant-kid): each key vouches only for its own prefixes, the service's for /{catalog}/g/{gs}")
	var originKidFlags multi
	fs.Var(&originKidFlags, "origin-edge-grant-kid", "the origin's edge-grant kids, which no kid of the service's may be: every KID of its -edge-grant-key flags, and its -edge-grant-kid (repeatable or comma-separated; default origin). Keep the list in step with the origin's key rotation")
	exchangeRate := fs.String("exchange-rate", "", "exchangeRate (§6.6, §C.5): edge-grant exchanges each principal may make at the service's POST /edge-grants, for -access, as RATE,BURST, e.g. 10,100 (the default); per process")
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
	topt.Edge = edgeVerifier(*edgeSecret, *edgeHeader, *edgePrefixHeader)
	switch {
	case *access:
		if topt.EdgeGrants, err = serviceEdgeGrantCookies(catalogs[0], *edgeGrantKid, originKids(originKidFlags), edgeGrantKeys, topt.Edge, corsFlags); err != nil {
			log.Fatal("tree: ", err)
		}
		switch {
		case topt.EdgeGrants == nil:
			log.Printf("tree: catalog %s mints no edge grants: /%s/g/{gs} would overlap the core's prefixes (§C.5.3)", catalogs[0], catalogs[0])
		case len(edgeGrantKeys) > 0:
			log.Printf("tree: edge grants: minted under kid %s, accepted under %s", topt.EdgeGrants.Kid(), strings.Join(topt.EdgeGrants.Kids(), ", "))
		}
		// A random key is this process's alone (tree.Options).
		topt.EdgeGrantsOwnKey = len(edgeGrantKeys) == 0
		topt.ExchangeRate = tree.DefaultExchangeRate
		if *exchangeRate != "" {
			r, err := parseRate(*exchangeRate)
			if err != nil {
				log.Fatalf("tree: -exchange-rate: %v", err)
			}
			topt.ExchangeRate = tree.Rate{Rate: r.Rate, Burst: r.Burst}
		}
	default:
		if err := edgeFlagsNeedAccess(edgeGrantKeys, originKidFlags, *edgeGrantKid, *exchangeRate); err != nil {
			log.Fatal("tree: ", err)
		}
	}

	ctx, sigs := shutdownSignals("patchlog tree")
	if *rel != "" {
		if *access {
			log.Fatal("tree: a release preview serves previews only and issues no grants (§B.5): -release can't be combined with -access")
		}
		if len(catalogs) > 1 {
			log.Fatal("tree: -release previews one catalog")
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
		} else if *rel != "" {
			// The release document is read now and followed afterwards
			// (§B.5): a new revision switches the preview's branches.
			var pv *tree.Preview
			pv, err = tree.OpenPreview(ctx, topt, *rel)
			if err == nil {
				handler, run, closer = pv.Handler(), pv.Run, pv.Close
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

// serviceEdgeGrantCookies returns the catalog service's own edge-grant
// cookies (§B.11.5, §C.5.3): under the -edge-grant-key flags,
// [KID=]FILE as the origin takes them (readEdgeGrantKeys), a plain FILE
// named kid (catalog-{catalog} if empty), minting with the last and
// accepting all, so the service's keys rotate as the origin's do; without
// one, a random key named kid. No kid may be one of the origin's,
// originKids, and no key the one derived from the edge secret, which the
// origin may hold (FILE edge-secret, for migration): each key vouches
// only for its own prefixes. They are SameSite=None when pages on other
// origins may call with credentials (-cors-credentials-origin), else Lax.
// A catalog named r or ns gets none (nil), since its prefixes would
// overlap the core's, and naming a key or kid for it is an error.
func serviceEdgeGrantCookies(cat, kid string, originKids, keyFlags []string, ev *edge.Verifier, c *corsFlags) (*edge.Cookies, error) {
	if cat == "r" || cat == "ns" {
		if kid != "" || len(keyFlags) > 0 {
			return nil, fmt.Errorf("-edge-grant-key and -edge-grant-kid: catalog %q can't have edge grants, since /%s/g/{gs} would overlap the core's prefixes (§C.5.3)", cat, cat)
		}
		return nil, nil
	}
	if kid == "" {
		kid = "catalog-" + cat
	}
	keys, err := readEdgeGrantKeys(kid, keyFlags, nil, false)
	if err != nil {
		return nil, err
	}
	if len(keys) == 0 {
		keys = []edgeGrantKey{{kid: kid}} // a random key (edge.NewCookies)
	}
	derived := ev.CookieKey()
	for _, k := range keys {
		if slices.Contains(originKids, k.kid) {
			return nil, fmt.Errorf("edge-grant kid %q is the origin's (-origin-edge-grant-kid): the service's key is its own, and vouches only for its own prefixes (§C.5.3)", k.kid)
		}
		if derived != nil && bytes.Equal(k.key, derived) {
			return nil, fmt.Errorf("-edge-grant-key %s: that is the key derived from -edge-secret, which the origin may hold; the service's key is one the origin never holds (§C.5.3)", k.file)
		}
	}
	return cookiesOf(keys, c)
}

// edgeFlagsNeedAccess refuses the edge-grant flags without -access: only
// a catalog service mints edge grants (§B.11.5), so the plain tree service
// would ignore them.
func edgeFlagsNeedAccess(keys, originKids []string, kid, exchangeRate string) error {
	if len(keys) > 0 || len(originKids) > 0 || kid != "" || exchangeRate != "" {
		return errors.New("-edge-grant-key, -edge-grant-kid, -origin-edge-grant-kid and -exchange-rate need -access: only a catalog service mints edge grants (§B.11.5)")
	}
	return nil
}

// originKids flattens repeated and comma-separated -origin-edge-grant-kid
// values, edge.DefaultKid if there are none.
func originKids(vals []string) []string {
	if out := splitCatalogs(vals); len(out) > 0 {
		return out
	}
	return []string{edge.DefaultKid}
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
