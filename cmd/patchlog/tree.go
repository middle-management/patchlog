package main

import (
	"bytes"
	"context"
	"errors"
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

// treeCmd runs the tree service of Addendum B, or with --access the catalog
// service of §B.11 that also issues grants:
//
//	patchlog tree --api URL --catalog NS[,NS]... [--db tree.db] [--addr :8082] [--access --key SEED --kid KID] …
//
// The service follows the catalog namespace and every namespace in its
// catalog.trust. --bearer is its own grant, which needs read on all of them.
//
// --catalog may name several catalogs (repeated, or comma-separated): each
// gets its own tree service, database and followers, and one origin serves
// them all, each at /{catalog}/… (tree.Multi). Their databases are --db with
// {catalog} replaced by the catalog's name, or, if --db has no {catalog},
// with -{catalog} before its extension (tree.db -> tree-topics.db). --access
// serves exactly one catalog (its /grants are not per catalog).
// Callers of POST /grants and of private listings present an ordinary core
// grant for the catalog namespace as their identity.
//
// Listings live at /{catalog}/at/{at}/… while every namespace in them is
// public, for everyone, else at /{catalog}/g/{gs}/at/{at}/…, the subject
// set first (§B.11.5): without --access only g/all, for readers whose grants
// would be issued namespace-wide edge grants on every namespace (403 for
// others, 401 without a grant). at is the combined checkpoint over the
// catalog and every followed content namespace (§B.5); listings are
// immutable, answered only at the canonical form of their query (§A.5), and
// tagged r:{ns}/{name} and ns:{ns}. Read-your-writes: ?min={ns}:{ns_id},
// repeatable, which always redirects (§A.5). Cache purges go to the CDN at
// --purge-url (repeatable), and are logged if it is unset.
//
// With --access the service also mints edge grants of its own for its
// listings (§B.11.5, §C.5): POST /edge-grants exchanges a caller's grants
// for a cookie bound to its subject set, /{catalog}/g/{gs}, or to
// /{catalog}/g/all for a reader whose grants would be issued namespace-wide
// edge grants on each of the catalog and its trusted namespaces that isn't
// public, and DELETE /edge-grants?prefix=… withdraws them. They are
// signed with the last --edge-grant-key [KID=]FILE, a key of the service's
// own that the origin never holds (without it, a random one per process),
// and accepted under any, so its keys rotate as the origin's do; a plain
// FILE is named --edge-grant-kid (default catalog-{catalog}). No kid of
// the service's may be one of the origin's (--origin-edge-grant-kid,
// repeatable or comma-separated, default origin, which must list every
// kid the origin holds as it rotates): each key vouches only for its own
// prefixes. Each exchange draws one token from the
// exchangeRate bucket of each principal it names (--exchange-rate
// RATE,BURST; 429 when empty), shared by the instances on one --db. A read under one, without
// Authorization, is the subject set's, and gets edge lifetimes behind a
// verifying edge (--edge-secret) that checked it with the service's kid.
// A catalog named r or ns mints none: its prefixes would overlap the
// core's.
//
// Encrypted namespaces (Addendum E) work as for patchlog index: --enc-key is
// the service's X25519 private key, --keyring-sender and --trusted-sender
// name the keyring admins it opens and trusts (§E.3.2); listings of a
// sealed or e2e catalog are served sealed, and /_status reports what is
// skipped.
type treeCmd struct {
	API          string        `arg:"--api" default:"http://localhost:8080" placeholder:"URL" help:"base URL of the patch-log API"`
	Catalog      []string      `arg:"--catalog,required,separate" placeholder:"NS[,NS]" help:"catalog namespace to follow (repeatable or comma-separated)"`
	DB           string        `arg:"--db" default:"tree.db" placeholder:"PATH" help:"SQLite database path; with several catalogs, may contain {catalog}"`
	Addr         string        `arg:"--addr" default:":8082" help:"listen address of the tree API"`
	Bearer       string        `arg:"--bearer" placeholder:"GRANT" help:"grant for reading the catalog and its trusted namespaces (Authorization: Bearer)"`
	Author       string        `arg:"--author" placeholder:"NAME" help:"X-Author for a --dev server"`
	SelfPlacing  bool          `arg:"--self-placing" help:"accept $parents in trusted content documents as implicit placements (§B.9)"`
	Access       bool          `arg:"--access" help:"catalog mode: derive access from $access and issue grants (§B.11); needs --key and --kid"`
	Key          string        `arg:"--key" placeholder:"SEED" help:"catalog signing key (b64url Ed25519 seed), for --access"`
	Kid          string        `arg:"--kid" help:"kid of the catalog key in the catalog and content namespaces, for --access"`
	TTL          time.Duration `arg:"--ttl" default:"15m" placeholder:"DURATION" help:"lifetime of issued grants (capped by the key's maxTtl)"`
	AdminGroup   string        `arg:"--admin-group" default:"catalog-admins" placeholder:"GROUP" help:"group whose moves skip the no-widening check"`
	MergeKey     string        `arg:"--merge-key" placeholder:"SEED" help:"merge grant signing key (b64url Ed25519 seed), a key of its own used for nothing else (§F.8); without it POST /merge-grants is refused"`
	MergeKid     string        `arg:"--merge-kid" placeholder:"KID" help:"the merge key's kid in the catalog namespace"`
	MergeService string        `arg:"--merge-service" placeholder:"SUB" help:"the merge service's sub: merge grants are issued only to it, and name it as their root (§F.8)"`
	MergeTTL     time.Duration `arg:"--merge-ttl" default:"5m" placeholder:"DURATION" help:"lifetime of merge grants (capped by the merge key's maxTtl)"`
	Release      string        `arg:"--release" placeholder:"/r/{ns}/{release}" help:"preview a release (§B.5, §F.9): follow the branches the release document lists in place of their bases; previews only, no grants (not with --access), one catalog; the document's log is followed, so a new revision (a rebase's successors) takes effect without a restart"`
	Rebuild      bool          `arg:"--rebuild" help:"drop the database and replay from the beginning"`
	MinWait      time.Duration `arg:"--min-wait" default:"2s" placeholder:"DURATION" help:"how long ?min= waits for the service to catch up"`
	SSE          bool          `arg:"--sse" help:"follow by server-sent events instead of long-poll"`
	encKeyArgs
	keyringArgs
	purgeArgs
	edgeArgs
	EdgeGrantKey       []string `arg:"--edge-grant-key,separate" placeholder:"[KID=]FILE" help:"a file holding a key the catalog service signs its own edge-grant cookies with (§B.11.5, §C.5), named KID (a plain FILE takes --edge-grant-kid), for --access: a key of its own that the origin never holds, so neither one of the origin's --edge-grant-key files nor the key derived from --edge-secret (at least 16 bytes); repeatable, to rotate keys as the origin's rotate: cookies under any are accepted, and the last given signs new ones. Without it, a random one per process, so cookies don't survive a restart or reach another instance"`
	EdgeGrantKid       string   `arg:"--edge-grant-kid" placeholder:"KID" help:"the name (kid) of the service's edge-grant key given as a plain --edge-grant-key FILE, or of the random one, which its cookies carry and a verifying edge looks the key up by (§C.5.3), for --access; default catalog-{catalog}. No kid of the service's may be one of the origin's (--origin-edge-grant-kid): each key vouches only for its own prefixes, the service's for /{catalog}/g/{gs}"`
	OriginEdgeGrantKid []string `arg:"--origin-edge-grant-kid,separate" placeholder:"KID[,KID]" help:"the origin's edge-grant kids, which no kid of the service's may be: every KID of its --edge-grant-key flags, and its --edge-grant-kid (repeatable or comma-separated; default origin). Keep the list in step with the origin's key rotation"`
	ExchangeRate       string   `arg:"--exchange-rate" placeholder:"RATE,BURST" help:"exchangeRate (§6.6, §C.5): edge-grant exchanges each principal may make at the service's POST /edge-grants, for --access, e.g. 10,100 (the default); the buckets are shared by the instances on one --db (§B.11.5)"`
	corsArgs
	shutdownArgs
}

func (a *treeCmd) run(string) {
	catalogs := splitCatalogs(a.Catalog)
	if len(catalogs) == 0 {
		log.Fatal("tree: --catalog is required")
	}
	if a.Access && len(catalogs) > 1 {
		log.Fatal("tree: --access serves one catalog; run one catalog service per catalog")
	}
	var copts []client.Option
	if a.Bearer != "" {
		copts = append(copts, client.WithBearer(a.Bearer))
	}
	if a.Author != "" {
		copts = append(copts, client.WithAuthor(a.Author))
	}
	recipient := recipientKey("tree", a.EncKey, a.EncKeyFile)
	kopts, err := a.keyringArgs.options()
	if err != nil {
		log.Fatalf("tree: %v", err)
	}
	copts = append(copts, kopts...)
	copts = append(copts, client.WithKeys(client.NewKeys(recipient)))
	c, err := client.New(a.API, copts...)
	if err != nil {
		log.Fatal(err)
	}
	topt := tree.Options{Client: c, Catalog: catalogs[0], DB: treeDB(a.DB, catalogs[0], len(catalogs)), Rebuild: a.Rebuild, SelfPlacing: a.SelfPlacing, MinWait: a.MinWait, Recipient: recipient}
	if a.SSE {
		topt.FollowOptions = append(topt.FollowOptions, follow.WithSSE())
	}
	purger := cdnPurger(a.PurgeURL)
	if purger != nil {
		topt.Purger = purger
	}
	topt.Edge = edgeVerifier(a.EdgeSecret, a.EdgeHeader, a.EdgePrefixHeader)
	switch {
	case a.Access:
		if topt.EdgeGrants, err = serviceEdgeGrantCookies(catalogs[0], a.EdgeGrantKid, originKids(a.OriginEdgeGrantKid), a.EdgeGrantKey, topt.Edge, &a.corsArgs); err != nil {
			log.Fatal("tree: ", err)
		}
		switch {
		case topt.EdgeGrants == nil:
			log.Printf("tree: catalog %s mints no edge grants: /%s/g/{gs} would overlap the core's prefixes (§C.5.3)", catalogs[0], catalogs[0])
		case len(a.EdgeGrantKey) > 0:
			log.Printf("tree: edge grants: minted under kid %s, accepted under %s", topt.EdgeGrants.Kid(), strings.Join(topt.EdgeGrants.Kids(), ", "))
		}
		// A random key is this process's alone (tree.Options).
		topt.EdgeGrantsOwnKey = len(a.EdgeGrantKey) == 0
		topt.ExchangeRate = tree.DefaultExchangeRate
		if a.ExchangeRate != "" {
			r, err := parseRate(a.ExchangeRate)
			if err != nil {
				log.Fatalf("tree: --exchange-rate: %v", err)
			}
			topt.ExchangeRate = tree.Rate{Rate: r.Rate, Burst: r.Burst}
		}
	default:
		if err := edgeFlagsNeedAccess(a.EdgeGrantKey, a.OriginEdgeGrantKid, a.EdgeGrantKid, a.ExchangeRate); err != nil {
			log.Fatal("tree: ", err)
		}
	}

	ctx, sigs := shutdownSignals("patchlog tree")
	if a.Release != "" {
		if a.Access {
			log.Fatal("tree: a release preview serves previews only and issues no grants (§B.5): --release can't be combined with --access")
		}
		if len(catalogs) > 1 {
			log.Fatal("tree: --release previews one catalog")
		}
	}

	var (
		handler http.Handler
		run     func(context.Context) error
		closer  func() error
	)
	if a.MergeKey != "" && (a.MergeKid == "" || a.MergeService == "" || a.MergeKid == a.Kid) {
		log.Fatal("tree: --merge-key needs --merge-kid (not the catalog's --kid) and --merge-service")
	}
	// The core may still be starting: retry opening (which reads its origin).
	for {
		if a.Access {
			if a.Key == "" || a.Kid == "" {
				log.Fatal("tree: --access needs --key and --kid")
			}
			priv, perr := grant.ParsePrivateKey(a.Key)
			if perr != nil {
				log.Fatal(perr)
			}
			copt := catalog.Options{Tree: topt, Key: priv, Kid: a.Kid, TTL: a.TTL, AdminGroup: a.AdminGroup,
				MergeKid: a.MergeKid, MergeService: a.MergeService, MergeTTL: a.MergeTTL}
			if a.MergeKey != "" {
				if copt.MergeKey, perr = grant.ParsePrivateKey(a.MergeKey); perr != nil {
					log.Fatal(perr)
				}
			}
			var svc *catalog.Service
			svc, err = catalog.Open(ctx, copt)
			if err == nil {
				handler, run, closer = svc.Handler(), svc.Run, svc.Close
			}
		} else if a.Release != "" {
			// The release document is read now and followed afterwards
			// (§B.5): a new revision switches the preview's branches.
			var pv *tree.Preview
			pv, err = tree.OpenPreview(ctx, topt, a.Release)
			if err == nil {
				handler, run, closer = pv.Handler(), pv.Run, pv.Close
			}
		} else {
			handler, run, closer, err = openTrees(ctx, topt, catalogs, a.DB)
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

	srv := &http.Server{Addr: a.Addr, Handler: a.corsArgs.wrap(handler), ReadHeaderTimeout: 10 * time.Second}
	ls := a.shutdownArgs.server("patchlog tree", srv, nil)
	ln, err := net.Listen("tcp", a.Addr)
	if err != nil {
		log.Fatal(err)
	}
	mode := "tree"
	if a.Access {
		mode = "catalog"
	}
	log.Printf("patchlog tree: %s service for %s at %s, serving on %s", mode, strings.Join(catalogs, ", "), a.API, ln.Addr())
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
// cookies (§B.11.5, §C.5.3): under the --edge-grant-key flags,
// [KID=]FILE as the origin takes them (readEdgeGrantKeys), a plain FILE
// named kid (catalog-{catalog} if empty), minting with the last and
// accepting all, so the service's keys rotate as the origin's do; without
// one, a random key named kid. No kid may be one of the origin's,
// originKids, and no key the one derived from the edge secret, which the
// origin may hold (FILE edge-secret, for migration): each key vouches
// only for its own prefixes. They are SameSite=None when pages on other
// origins may call with credentials (--cors-credentials-origin), else Lax.
// A catalog named r or ns gets none (nil), since its prefixes would
// overlap the core's, and naming a key or kid for it is an error.
func serviceEdgeGrantCookies(cat, kid string, originKids, keyFlags []string, ev *edge.Verifier, c *corsArgs) (*edge.Cookies, error) {
	if cat == "r" || cat == "ns" {
		if kid != "" || len(keyFlags) > 0 {
			return nil, fmt.Errorf("--edge-grant-key and --edge-grant-kid: catalog %q can't have edge grants, since /%s/g/{gs} would overlap the core's prefixes (§C.5.3)", cat, cat)
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
			return nil, fmt.Errorf("edge-grant kid %q is the origin's (--origin-edge-grant-kid): the service's key is its own, and vouches only for its own prefixes (§C.5.3)", k.kid)
		}
		if derived != nil && bytes.Equal(k.key, derived) {
			return nil, fmt.Errorf("--edge-grant-key %s: that is the key derived from --edge-secret, which the origin may hold; the service's key is one the origin never holds (§C.5.3)", k.file)
		}
	}
	return cookiesOf(keys, c)
}

// edgeFlagsNeedAccess refuses the edge-grant flags without --access: only
// a catalog service mints edge grants (§B.11.5), so the plain tree service
// would ignore them.
func edgeFlagsNeedAccess(keys, originKids []string, kid, exchangeRate string) error {
	if len(keys) > 0 || len(originKids) > 0 || kid != "" || exchangeRate != "" {
		return errors.New("--edge-grant-key, --edge-grant-kid, --origin-edge-grant-kid and --exchange-rate need --access: only a catalog service mints edge grants (§B.11.5)")
	}
	return nil
}

// originKids flattens repeated and comma-separated --origin-edge-grant-kid
// values, edge.DefaultKid if there are none.
func originKids(vals []string) []string {
	if out := splitCatalogs(vals); len(out) > 0 {
		return out
	}
	return []string{edge.DefaultKid}
}

// splitCatalogs flattens repeated and comma-separated --catalog values,
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
