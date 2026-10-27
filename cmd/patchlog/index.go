package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/derived"
	"github.com/middle-management/patchlog/internal/edge"
	"github.com/middle-management/patchlog/internal/follow"
	"github.com/middle-management/patchlog/internal/index"
	"github.com/middle-management/patchlog/internal/seal"
	"github.com/middle-management/patchlog/internal/svcedge"
)

// indexCmd runs the indexing service of Addendum A:
//
//	patchlog index [-api http://localhost:8080] [-db index.db] [-addr :8081] -ns matches,docs
//	               [-bearer GRANT] [-author NAME] [-branches] [-rebuild] [-untyped-listing=false]
//	               [-enc-key B64URL | -enc-key-file PATH] [-keyring-sender pub.jwk]... [-trusted-sender pub.jwk]... [-purge-url URL]... [-edge-secret FILE [-edge-header NAME] [-edge-prefix-header NAME]]
//	               [-edge-grant-key [KID=]FILE]... [-edge-grant-kid KID] [-origin-edge-grant-kid KID[,KID]]... [-exchange-rate RATE,BURST]
//
// Results at /{ns}/at/{ns_id}, or /{ns}/g/{gs}/at/{ns_id} for a private
// namespace (§A.4), are immutable and tagged idx:{ns} and r:{ns}/{name} per
// hit; only the current checkpoint's results are kept.
// Read-your-writes: ?min={ns_id} or ?min={ns}:{ns_id}, repeatable, which
// always redirects (§A.5). Results are answered only at the canonical form
// of their query (§A.5); a multi-key sort is one parameter,
// sort=-/kickoff,/title. Cache purges go to the CDN at -purge-url
// (repeatable), and are logged if it is unset.
//
// Encrypted namespaces (Addendum E): sealed ones are read with keys from
// POST /ns/{ns}/keys with -bearer's grant; -enc-key is the service's X25519
// private key (base64url scalar), which unwraps keys wrapped to the grant's
// enc and reads e2e namespaces whose keyring names its public key (logged
// at start). A keyring entry opens only with the public key of the admin
// that wrapped it: -keyring-sender names them, and -trusted-sender those
// the service trusts to distribute the keys it seals views under (§E.3.2).
// Results over them are served sealed; see /_status for skipped
// namespaces.
//
// Edge grants of its own (§A.4, §B.11.5, §C.5): POST /edge-grants
// exchanges a caller's grants for cookies for /{ns}/g/{gs} of each private
// namespace it follows that they name and /_refs/g/{gs} of the caller's
// subject set, under which a verifying edge may cache those results for
// every reader of the subject set, and DELETE /edge-grants?prefix=…
// withdraws them. They are signed with the last -edge-grant-key
// [KID=]FILE, a key of the service's own that the origin never holds
// (rotated as the origin's: cookies under any given are accepted), or
// without one a random key of this process, named -edge-grant-kid
// (default index). No kid of the service's may be one of the origin's
// (-origin-edge-grant-kid). Each exchange draws from the exchangeRate
// bucket of each principal it names (-exchange-rate RATE,BURST, default
// 10,100), shared by the instances on one -db.
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
	keyring := addKeyringFlags(fs)
	var purgeURLs multi
	fs.Var(&purgeURLs, "purge-url", purgeURLUsage)
	edgeSecret := fs.String("edge-secret", "", edgeSecretUsage)
	edgeHeader := fs.String("edge-header", edge.DefaultHeader, edgeHeaderUsage)
	edgePrefixHeader := fs.String("edge-prefix-header", edge.DefaultPrefixHeader, edgePrefixHeaderUsage)
	var edgeGrantKeys multi
	fs.Var(&edgeGrantKeys, "edge-grant-key", "[KID=]FILE: a file holding a key the index signs its own edge-grant cookies with (§A.4, §B.11.5, §C.5), named KID (a plain FILE takes -edge-grant-kid): a key of its own that the origin never holds, so neither one of the origin's -edge-grant-key files nor the key derived from -edge-secret (at least 16 bytes); repeatable, to rotate keys as the origin's rotate: cookies under any are accepted, and the last given signs new ones. Without it, a random one per process, so cookies don't survive a restart or reach another instance")
	edgeGrantKid := fs.String("edge-grant-kid", "index", "the name (kid) of the index's edge-grant key given as a plain -edge-grant-key FILE, or of the random one, which its cookies carry and a verifying edge looks the key up by (§C.5.3). No kid of the index's may be one of the origin's (-origin-edge-grant-kid): each key vouches only for its own prefixes, the index's for /{ns}/g/{gs} and /_refs/g/{gs}")
	var originKidFlags multi
	fs.Var(&originKidFlags, "origin-edge-grant-kid", "the origin's edge-grant kids, which no kid of the index's may be (repeatable or comma-separated; default origin). Keep the list in step with the origin's key rotation")
	exchangeRate := fs.String("exchange-rate", "", "exchangeRate (§6.6, §C.5): edge-grant exchanges each principal may make at the index's POST /edge-grants, as RATE,BURST, e.g. 10,100 (the default); the buckets are shared by the instances on one -db (§B.11.5)")
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
	if *fetchConc < 1 {
		log.Fatal("index: -fetch-concurrency must be at least 1")
	}
	var copts []client.Option
	if *bearer != "" {
		copts = append(copts, client.WithBearer(*bearer))
	}
	if *author != "" {
		copts = append(copts, client.WithAuthor(*author))
	}
	recipient := recipientKey("index", *encKey, *encKeyFile)
	kopts, err := keyring.options()
	if err != nil {
		log.Fatalf("index: %v", err)
	}
	copts = append(copts, kopts...)
	// Keep a connection for each fetch and each namespace's long-poll, so
	// they are reused from one page to the next.
	copts = append(copts, client.WithKeys(client.NewKeys(recipient)), client.WithIdleConns(*fetchConc+len(nss)))
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
	opt.Edge = edgeVerifier(*edgeSecret, *edgeHeader, *edgePrefixHeader)
	if opt.EdgeGrants, err = indexEdgeGrantCookies(*edgeGrantKid, originKids(originKidFlags), edgeGrantKeys, opt.Edge, corsFlags); err != nil {
		log.Fatal("index: ", err)
	}
	if len(edgeGrantKeys) > 0 {
		log.Printf("index: edge grants: minted under kid %s, accepted under %s", opt.EdgeGrants.Kid(), strings.Join(opt.EdgeGrants.Kids(), ", "))
	}
	if *exchangeRate != "" {
		r, err := parseRate(*exchangeRate)
		if err != nil {
			log.Fatalf("index: -exchange-rate: %v", err)
		}
		opt.ExchangeRate = svcedge.Rate{Rate: r.Rate, Burst: r.Burst}
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

// indexEdgeGrantCookies returns the index's own edge-grant cookies (§A.4,
// §B.11.5, §C.5.3): under the -edge-grant-key flags, [KID=]FILE as the
// origin takes them (readEdgeGrantKeys), a plain FILE named kid, minting
// with the last and accepting all; without one, a random key named kid.
// No kid may be one of the origin's, originKids, and no key the one
// derived from the edge secret, which the origin may hold: each key
// vouches only for its own prefixes. They are SameSite=None when pages on
// other origins may call with credentials (-cors-credentials-origin),
// else Lax.
func indexEdgeGrantCookies(kid string, originKids, keyFlags []string, ev *edge.Verifier, c *corsFlags) (*edge.Cookies, error) {
	if kid == "" {
		return nil, errors.New("-edge-grant-kid: empty")
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
			return nil, fmt.Errorf("edge-grant kid %q is the origin's (-origin-edge-grant-kid): the index's key is its own, and vouches only for its own prefixes (§C.5.3)", k.kid)
		}
		if derived != nil && bytes.Equal(k.key, derived) {
			return nil, fmt.Errorf("-edge-grant-key %s: that is the key derived from -edge-secret, which the origin may hold; the index's key is one the origin never holds (§C.5.3)", k.file)
		}
	}
	return cookiesOf(keys, c)
}

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
