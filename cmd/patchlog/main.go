// Command patchlog runs the patch-log server and mints grants.
//
//	patchlog serve [-addr :8080] [-db patchlog.db] [-origin URL] [-dev] [-operator-key PUB]...
//	patchlog keygen
//	patchlog grant mint -key SEED -block '{"kid":…,"sub":…,"ns":[…],"can":[…],"exp":…}'
//	patchlog grant narrow -grant TOKEN -block '{"can":["read"],…}'
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/middle-management/patchlog/internal/core"
	"github.com/middle-management/patchlog/internal/grant"
	"github.com/middle-management/patchlog/internal/jsonv"
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
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage:
  patchlog serve [-addr :8080] [-db patchlog.db] [-origin URL] [-dev] [-operator-key PUB]...
  patchlog keygen
  patchlog grant mint -key SEED -block JSON
  patchlog grant narrow -grant TOKEN -block JSON`)
	os.Exit(2)
}

func serve(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	addr := fs.String("addr", ":8080", "listen address")
	db := fs.String("db", "patchlog.db", "SQLite database path")
	origin := fs.String("origin", "http://localhost:8080", "canonical origin (§G.1)")
	dev := fs.Bool("dev", false, "disable authentication (development only); X-Author names the author")
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
	e, err := core.Open(core.Options{Path: *db, Origin: *origin, AuthDisabled: *dev, OperatorKeys: keys})
	if err != nil {
		log.Fatal(err)
	}
	defer e.Close()
	srv := &http.Server{Addr: *addr, Handler: server.New(e), ReadHeaderTimeout: 10 * time.Second}
	log.Printf("patchlog listening on %s (origin %s, dev=%v)", *addr, *origin, *dev)
	log.Fatal(srv.ListenAndServe())
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
