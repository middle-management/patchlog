// Command patchlog runs the patch-log server and mints grants.
//
//	patchlog serve [-addr :8080] [-db patchlog.db] [-origin URL] [-dev] [-playground=false] [-operator-key PUB]...
//	patchlog keygen
//	patchlog grant mint -key SEED -block '{"kid":…,"sub":…,"ns":[…],"can":[…],"exp":…}'
//	patchlog grant narrow -grant TOKEN -block '{"can":["read"],…}'
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

	"github.com/middle-management/patchlog/internal/core"
	"github.com/middle-management/patchlog/internal/grant"
	"github.com/middle-management/patchlog/internal/jsonv"
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
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage:
  patchlog serve [-addr :8080] [-db patchlog.db] [-origin URL] [-dev] [-playground=false] [-operator-key PUB]...
  patchlog keygen
  patchlog grant mint -key SEED -block JSON
  patchlog grant narrow -grant TOKEN -block JSON
  patchlog index -ns NS[,NS…] [-api URL] [-db index.db] [-addr :8081] [-bearer GRANT] [-author NAME] [-branches] [-rebuild] [-untyped-listing=false]`)
	os.Exit(2)
}

func serve(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	addr := fs.String("addr", ":8080", "listen address")
	db := fs.String("db", "patchlog.db", "SQLite database path")
	origin := fs.String("origin", "http://localhost:8080", "canonical origin (§G.1)")
	dev := fs.Bool("dev", false, "disable authentication (development only); X-Author names the author")
	pg := fs.Bool("playground", true, "serve the web playground at /playground/")
	maxItems := fs.Int("max-items-per-batch", 0, "deployment maximum items per batch (default: the namespace default, 1000); allowances may go up to it (§6.6)")
	maxBatch := fs.String("max-batch-size", "", "deployment maximum batch size, e.g. \"64 MiB\" (default: the namespace default, 16 MiB)")
	var opKeys multi
	fs.Var(&opKeys, "operator-key", "base64url Ed25519 public key allowed to create namespaces (repeatable; kid is \"operator\", \"operator-2\", …)")
	fs.Parse(args)

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
	e, err := core.Open(core.Options{Path: *db, Origin: *origin, AuthDisabled: *dev, OperatorKeys: keys,
		Limits: core.DefaultLimits(), Maximums: max})
	if err != nil {
		log.Fatal(err)
	}
	defer e.Close()
	srv := &http.Server{Addr: *addr, Handler: handler(server.New(e), *pg), ReadHeaderTimeout: 10 * time.Second}
	log.Printf("patchlog listening on %s (origin %s, dev=%v)", *addr, *origin, *dev)
	if *pg {
		log.Printf("playground: %s%s", localURL(*addr), playground.Prefix)
	}
	log.Fatal(srv.ListenAndServe())
}

// handler routes /playground/ to the web UI and everything else to the API.
// The playground has its own ServeMux, but the API is not put behind one:
// http.ServeMux cleans paths and answers 301, where §3.6 requires the API's
// own 400 for non-canonical URLs, so only playground paths reach the mux.
func handler(api http.Handler, withPlayground bool) http.Handler {
	if !withPlayground {
		return api
	}
	mux := http.NewServeMux()
	mux.Handle(playground.Prefix, playground.Handler())
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
	tok := fs.String("grant", "", "grant to narrow")
	block := fs.String("block", "", "block JSON")
	fs.Parse(args[1:])
	b, err := jsonv.Parse([]byte(*block))
	m, ok := b.(map[string]any)
	if err != nil || !ok {
		log.Fatalf("-block must be a JSON object: %v", err)
	}
	var g *grant.Grant
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
	case "narrow":
		parent, err := grant.Decode(*tok, 0)
		if err != nil {
			log.Fatal(err)
		}
		g, err = parent.Narrow(m)
		if err != nil {
			log.Fatal(err)
		}
	default:
		usage()
	}
	fmt.Println(g.Encode())
}
