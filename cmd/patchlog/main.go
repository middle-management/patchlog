// Command patchlog runs the patch-log server and mints grants.
//
//	patchlog serve [-addr :8080] [-db patchlog.db] [-origin URL] [-dev] [-playground=false] [-tree-url URL] [-operator-key PUB]... [-archive file:///dir] [-archive-root file:///dir]... [-retention-interval 1h] [-remote-bearer ORIGIN=GRANT]... [-remote-url ORIGIN=URL]... [-remote-ignore-purges] [-remote-follow-interval 5m] [-remote-register] [-master-key FILE [-master-key-create]]
//	patchlog keygen
//	patchlog grant mint -key SEED -block '{"kid":…,"sub":…,"ns":[…],"can":[…],"exp":…}'
//	patchlog grant narrow -grant TOKEN -block '{"can":["read"],…}' [-seal]
//	patchlog grant seal -grant TOKEN
//
// Grants are Biscuit v3 tokens (§C.8).
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/middle-management/patchlog/internal/bundle"
	"github.com/middle-management/patchlog/internal/core"
	"github.com/middle-management/patchlog/internal/grant"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/keystore"
	"github.com/middle-management/patchlog/internal/playground"
	"github.com/middle-management/patchlog/internal/server"
)

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(s string) error { *m = append(*m, s); return nil }

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "serve":
		serve(os.Args[2:])
	case "keygen":
		pub, priv := grant.GenerateKey()
		fmt.Printf("public  %s\nprivate %s\n", pub, grant.EncodePrivateKey(priv))
	case "grant":
		grantCmd(os.Args[2:])
	case "index":
		indexCmd(os.Args[2:])
	case "tree":
		treeCmd(os.Args[2:])
	case "merge":
		mergeCmd(os.Args[2:])
	case "rebase":
		rebaseCmd(os.Args[2:])
	case "janitor":
		janitorCmd(os.Args[2:])
	case "export", "import", "bundle":
		bundleCmd(os.Args[1], os.Args[2:])
	case "archive":
		archiveCmd(os.Args[2:])
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage:
  patchlog serve [-addr :8080] [-db patchlog.db] [-origin URL] [-dev] [-playground=false] [-tree-url URL] [-operator-key PUB]... [-archive file:///dir] [-archive-root file:///dir]... [-retention-interval 1h]
                 [-remote-bearer ORIGIN=GRANT]... [-remote-url ORIGIN=URL]... [-remote-ignore-purges] [-remote-follow-interval 5m] [-remote-register]
                 [-master-key FILE [-master-key-create]]
  patchlog keygen
  patchlog grant mint -key SEED -block JSON [-seal]
  patchlog grant narrow -grant TOKEN -block JSON [-seal]
  patchlog grant seal -grant TOKEN      (grants are Biscuit v3 tokens)
  patchlog index -ns NS[,NS…] [-api URL] [-db index.db] [-addr :8081] [-bearer GRANT] [-author NAME] [-branches] [-rebuild] [-untyped-listing=false]
  patchlog tree -api URL -catalog NS [-db tree.db] [-addr :8082] [-access -key SEED -kid KID] [-bearer T] [-author A] [-self-placing]
  patchlog merge status|plan|apply -api URL -branch NS [-base NS] [-bearer T] [-author A] [-freeze] [-squash] [-resolve name=file.json]... [-config patches.json] [-json]
  patchlog rebase -api URL -branch NS -new NAME [-onto NS] [-switch] [-bearer T] [-author A] [-json]
  patchlog janitor -api URL -ns base1,base2 [-dry-run] [-once] [-interval 1m] [-bearer T] [-author A] [-json]
  patchlog export -api URL -ns NS[,NS] [-resource a,b] [-mode history|snapshot] [-o file.jsonl] [-bearer T]
  patchlog import -api URL -ns TARGET -i file.jsonl [-dry-run] (-atomic | -pace 0.5) [-bearer T]
  patchlog bundle verify -i file.jsonl
  patchlog archive restore -db patchlog.db [-from file:///path] [-ns NS] [-resource NAME] [-master-key FILE]`)
	os.Exit(2)
}

func serve(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	addr := fs.String("addr", ":8080", "listen address")
	db := fs.String("db", "patchlog.db", "SQLite database path")
	origin := fs.String("origin", "http://localhost:8080", "canonical origin (§G.1)")
	dev := fs.Bool("dev", false, "disable authentication (development only); X-Author names the author")
	pg := fs.Bool("playground", true, "serve the web playground at /playground/")
	treeURL := fs.String("tree-url", "", "tree service (Addendum B) the playground reads through a read-only proxy at "+server.TreeProxyPrefix+", e.g. http://tree:8082")
	maxItems := fs.Int("max-items-per-batch", 0, "deployment maximum items per batch (default: the namespace default, 1000); allowances may go up to it (§6.6)")
	maxBatch := fs.String("max-batch-size", "", "deployment maximum batch size, e.g. \"64 MiB\" (default: the namespace default, 16 MiB)")
	var opKeys multi
	fs.Var(&opKeys, "operator-key", "base64url Ed25519 public key allowed to create namespaces (repeatable; kid is \"operator\", \"operator-2\", …)")
	archiveDef := fs.String("archive", "", "default pruning archive destination, a file:// directory (§8.6)")
	var archiveRoots multi
	fs.Var(&archiveRoots, "archive-root", "file:// directory under which retention rules may name archive destinations (repeatable; -archive is always allowed)")
	retention := fs.Duration("retention-interval", time.Hour, "how often retention policies are applied (0 disables)")
	var remoteBearers, remoteURLs multi
	fs.Var(&remoteBearers, "remote-bearer", "ORIGIN=GRANT: grant sent to the deployment at ORIGIN for remote branches (read, and export to register) (repeatable, §G.3)")
	fs.Var(&remoteURLs, "remote-url", "ORIGIN=URL: reach the deployment at ORIGIN through URL instead (repeatable)")
	var remoteIDs multi
	fs.Var(&remoteIDs, "remote-identity", "ORIGIN=FILE: X25519 private key (JWK) unwrapping the keys of sealed bases at ORIGIN, named by the -remote-bearer grant's enc (repeatable, §G.5.2)")
	ignorePurges := fs.Bool("remote-ignore-purges", false, "record purges in remote bases' logs as notices instead of applying them (§G.3)")
	remoteFollow := fs.Duration("remote-follow-interval", 5*time.Minute, "how often remote bases' logs are followed (0 disables)")
	remoteRegister := fs.Bool("remote-register", false, "register remote branches with their bases and renew the registrations (§G.3)")
	masterKey := fs.String("master-key", "", "file holding the 32-byte master key of encryption at rest (Addendum E.1); mode 0600")
	masterKeyCreate := fs.Bool("master-key-create", false, "create the -master-key file with a new random key if it doesn't exist")
	rotateEpochs := fs.Duration("rotate-epochs", 0, "rotate every sealed namespace's epoch once it is this old, e.g. 24h (Addendum E.2; 0 disables)")
	rotateOnRevoke := fs.Bool("rotate-on-revoke", false, "rotate a sealed namespace's epoch right after a config write that revokes a grant or removes or changes a key (§E.2.4)")
	fs.Parse(args)
	remote, err := remoteOptions(remoteBearers, remoteURLs, remoteIDs)
	if err != nil {
		log.Fatal(err)
	}
	remote.IgnorePurges, remote.Register, remote.FollowInterval = *ignorePurges, *remoteRegister, *remoteFollow
	if remote.FollowInterval == 0 {
		remote.FollowInterval = -1
	}

	var keys []grant.Key
	for i, k := range opKeys {
		kid := "operator"
		if i > 0 {
			kid = fmt.Sprintf("operator-%d", i+1)
		}
		ks, err := grant.ParseKeys(jsonv.FromGo([]any{map[string]any{"kid": kid, "alg": "ed25519", "pub": k, "can": []any{"*"}}}))
		if err != nil {
			log.Fatalf("operator key: %v", err)
		}
		keys = append(keys, ks...)
	}
	if !*dev && len(keys) == 0 {
		log.Print("warning: no -operator-key given; no namespace can be created")
	}
	max := core.DefaultLimits()
	if *maxItems > 0 {
		max.ItemsPerBatch = *maxItems
	}
	if *maxBatch != "" {
		n, err := core.ParseSize(*maxBatch)
		if err != nil {
			log.Fatalf("-max-batch-size: %v", err)
		}
		max.BatchSize = n
	}
	arch, err := archiver(*archiveDef, archiveRoots)
	if err != nil {
		log.Fatalf("-archive: %v", err)
	}
	if *retention == 0 {
		*retention = -1
	}
	var ks core.KeyStore
	if *masterKey != "" {
		l, err := keystore.LoadFile(*masterKey, *masterKeyCreate)
		if err != nil {
			log.Fatalf("-master-key: %v", err)
		}
		ks = l
	} else if *masterKeyCreate {
		log.Fatal("-master-key-create needs -master-key")
	}
	var treeProxy http.Handler
	if *treeURL != "" {
		if !*pg {
			log.Fatal("-tree-url needs the playground (it proxies under " + server.TreeProxyPrefix + ")")
		}
		if treeProxy, err = server.NewTreeProxy(*treeURL); err != nil {
			log.Fatal(err)
		}
	}
	e, err := core.Open(core.Options{Path: *db, Origin: *origin, AuthDisabled: *dev, OperatorKeys: keys,
		Limits: core.DefaultLimits(), Maximums: max, Archiver: arch, RetentionInterval: *retention, Remote: remote, KeyStore: ks,
		RotateEpochs: *rotateEpochs, RotateOnRevoke: *rotateOnRevoke})
	if err != nil {
		log.Fatal(err)
	}
	defer e.Close()
	srv := &http.Server{Addr: *addr, Handler: handler(server.New(e), *pg, treeProxy), ReadHeaderTimeout: 10 * time.Second}
	log.Printf("patchlog listening on %s (origin %s, dev=%v)", *addr, *origin, *dev)
	if *pg {
		log.Printf("playground: %s%s", localURL(*addr), playground.Prefix)
	}
	if treeProxy != nil {
		log.Printf("tree proxy: %s%s -> %s (GET/HEAD only)", localURL(*addr), server.TreeProxyPrefix, *treeURL)
	}
	log.Fatal(srv.ListenAndServe())
}

// remoteOptions builds the endpoints of remote bases from ORIGIN=VALUE flags.
func remoteOptions(bearers, urls, identities []string) (core.RemoteOptions, error) {
	eps := map[string]core.RemoteEndpoint{}
	for _, pair := range [][]string{bearers, urls, identities} {
		for _, kv := range pair {
			o, v, ok := strings.Cut(kv, "=")
			if !ok || !core.ValidRemoteOrigin(o) || v == "" {
				return core.RemoteOptions{}, fmt.Errorf("remote endpoint %q: want ORIGIN=VALUE with an https origin", kv)
			}
			eps[o] = core.RemoteEndpoint{}
		}
	}
	for _, kv := range bearers {
		o, v, _ := strings.Cut(kv, "=")
		ep := eps[o]
		ep.Bearer = v
		eps[o] = ep
	}
	for _, kv := range urls {
		o, v, _ := strings.Cut(kv, "=")
		ep := eps[o]
		ep.BaseURL = v
		eps[o] = ep
	}
	for _, kv := range identities {
		o, v, _ := strings.Cut(kv, "=")
		id, err := bundle.LoadIdentity(v)
		if err != nil {
			return core.RemoteOptions{}, fmt.Errorf("-remote-identity %s: %w", o, err)
		}
		ep := eps[o]
		ep.Identity = id
		eps[o] = ep
	}
	return core.RemoteOptions{Resolve: func(origin string) (core.RemoteEndpoint, error) {
		return eps[origin], nil
	}}, nil
}

// handler routes /playground/ to the web UI and everything else to the API.
// The playground has its own ServeMux, but the API is not put behind one:
// http.ServeMux cleans paths and answers 301, where §3.6 requires the API's
// own 400 for non-canonical URLs, so only playground paths reach the mux.
// treeProxy, if not nil, serves server.TreeProxyPrefix (-tree-url);
// without it those paths are the playground's 404.
func handler(api http.Handler, withPlayground bool, treeProxy http.Handler) http.Handler {
	if !withPlayground {
		return api
	}
	mux := http.NewServeMux()
	mux.Handle(playground.Prefix, playground.Handler())
	if treeProxy != nil {
		mux.Handle(server.TreeProxyPrefix, treeProxy)
	}
	mux.HandleFunc(strings.TrimSuffix(playground.Prefix, "/"), func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, playground.Prefix, http.StatusFound)
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/playground" || strings.HasPrefix(r.URL.Path, playground.Prefix) {
			mux.ServeHTTP(w, r)
			return
		}
		api.ServeHTTP(w, r)
	})
}

// localURL turns a listen address into a URL a browser on this machine can open.
func localURL(addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "http://" + addr
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "localhost"
	}
	return "http://" + net.JoinHostPort(host, port)
}

func grantCmd(args []string) {
	if len(args) < 1 {
		usage()
	}
	fs := flag.NewFlagSet("grant", flag.ExitOnError)
	key := fs.String("key", "", "signing key seed (base64url)")
	tok := fs.String("grant", "", "grant to narrow or seal (a Biscuit token)")
	block := fs.String("block", "", "block JSON")
	sealIt := fs.Bool("seal", false, "seal the result, so nobody can narrow it further (§C.8)")
	fs.Parse(args[1:])
	var m map[string]any
	if args[0] != "seal" {
		b, err := jsonv.Parse([]byte(*block))
		var ok bool
		m, ok = b.(map[string]any)
		if err != nil || !ok {
			log.Fatalf("-block must be a JSON object: %v", err)
		}
	}
	var g *grant.Grant
	var err error
	switch args[0] {
	case "mint":
		priv, err := grant.ParsePrivateKey(*key)
		if err != nil {
			log.Fatal(err)
		}
		g, err = grant.Mint(m, priv)
		if err != nil {
			log.Fatal(err)
		}
	case "narrow", "seal":
		g, err = grant.Decode(*tok, 0)
		if err != nil {
			log.Fatal(err)
		}
		if args[0] == "narrow" {
			if g, err = g.Narrow(m); err != nil {
				log.Fatal(err)
			}
		} else {
			*sealIt = true
		}
	default:
		usage()
	}
	if *sealIt {
		if g, err = g.Seal(); err != nil {
			log.Fatal(err)
		}
	}
	fmt.Println(g.Encode())
}
