package main

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/core"
	"github.com/middle-management/patchlog/internal/dav"
)

// davCmd serves namespaces over WebDAV (a prototype, internal/dav):
//
//	patchlog dav --api URL --ns NS[,NS…] [--catalog NS[,NS…]] [--gateway [--insecure]] [--tls-cert FILE --tls-key FILE] …
//
// Local mode (the default) sends --bearer's grant with every request to the
// core; WebDAV clients log in with HTTP Basic, any user name and the
// password of --password-file, or a random one logged at start. Gateway
// mode sends each request's Basic password upstream as its grant
// (Authorization: Bearer); grants must not cross plain HTTP, so it needs
// TLS on any address but loopback unless --insecure. With --tree-url, the
// trees' folders are listed from the tree service (§H.3, §H.7), as
// serve's --tree-url names it; without, from the catalogs' node documents.
type davCmd struct {
	API              string        `arg:"--api" default:"http://localhost:8080" placeholder:"URL" help:"base URL of the patch-log API"`
	Addr             string        `arg:"--addr" default:"127.0.0.1:8090" help:"listen address of the WebDAV server"`
	NS               []string      `arg:"--ns,separate" placeholder:"NS[,NS]" help:"flat namespace to serve, a directory of its files: raw ones by name, JSON documents as {name}.json (repeatable or comma-separated)"`
	Catalog          []string      `arg:"--catalog,separate" placeholder:"NS[,NS]" help:"catalog namespace to serve as a file tree, one whose namespace document has catalog.files (§H.2; repeatable or comma-separated)"`
	CaseSensitive    bool          `arg:"--case-sensitive" help:"compare the names in a file tree's folder after NFC only, not after case folding too"`
	InlinePDF        bool          `arg:"--inline-pdf" help:"serve PDFs for display in the browser rather than as attachments (Content-Disposition: attachment); either way without the sandbox (§7.8, §H.6)"`
	TreeURL          []string      `arg:"--tree-url,separate" placeholder:"[CATALOG=]URL" help:"tree service (§B.5) following the --catalog trees, e.g. http://tree:8082, which their folders are listed from with each user's grant (§H.3, §H.7); CATALOG=URL maps one catalog to its own (repeatable). Without one, folders are listed from the catalogs' node documents"`
	TreeWait         time.Duration `arg:"--tree-wait" default:"3s" placeholder:"DURATION" help:"how long a user's listing waits for the tree service to reach the user's own writes (?min=) before it reads the node documents"`
	Bearer           string        `arg:"--bearer" placeholder:"GRANT" help:"local mode: the grant every request is sent with (Authorization: Bearer)"`
	BearerFile       string        `arg:"--bearer-file" placeholder:"FILE" help:"local mode: file holding --bearer"`
	Author           string        `arg:"--author" placeholder:"NAME" help:"X-Author for a --dev server (local mode)"`
	PasswordFile     string        `arg:"--password-file" placeholder:"FILE" help:"local mode: file holding the Basic password WebDAV clients log in with (any user name); default a random one, logged at start"`
	Gateway          bool          `arg:"--gateway" help:"gateway mode: each request's Basic password is the grant sent upstream, the user name ignored; over a core with authentication disabled, the Basic user name is the X-Author, and the user (§H.7)"`
	Insecure         bool          `arg:"--insecure" help:"gateway mode: allow plain HTTP on an address other than loopback, so grants cross the network in the clear"`
	TLSCert          string        `arg:"--tls-cert" placeholder:"FILE" help:"serve HTTPS with this certificate (PEM), with --tls-key"`
	TLSKey           string        `arg:"--tls-key" placeholder:"FILE" help:"the private key of --tls-cert (PEM)"`
	FetchConcurrency int           `arg:"--fetch-concurrency" default:"8" placeholder:"N" help:"how many documents are read from the core at once"`
	CacheSize        byteSize      `arg:"--cache-size" default:"64 MiB" placeholder:"SIZE" help:"rendered documents kept in memory by revision id"`
	MaxFileSize      byteSize      `arg:"--max-file-size" default:"16 MiB" placeholder:"SIZE" help:"largest JSON file written (buffered whole) or file kept as a temporary file"`
	MaxRawSize       byteSize      `arg:"--max-raw-size" default:"64 MiB" placeholder:"SIZE" help:"largest raw file written (buffered whole): the deployment's blobSize, 64 MiB by default"`
	shutdownArgs
}

func (a *davCmd) run(string) {
	flat, catalogs := splitCatalogs(a.NS), splitCatalogs(a.Catalog)
	if len(flat)+len(catalogs) == 0 {
		log.Fatal("dav: --ns or --catalog is required")
	}
	if (a.TLSCert == "") != (a.TLSKey == "") {
		log.Fatal("dav: --tls-cert and --tls-key go together")
	}
	tls := a.TLSCert != ""
	var err error
	opt := dav.Options{Namespaces: flat, Catalogs: catalogs, CaseSensitive: a.CaseSensitive, InlinePDF: a.InlinePDF, Gateway: a.Gateway, FetchConcurrency: a.FetchConcurrency,
		CacheBytes: int(a.CacheSize), MaxFileSize: int(a.MaxFileSize), MaxRawSize: int(a.MaxRawSize), TreeWait: a.TreeWait, Logf: log.Printf}
	if opt.TreeService, opt.TreeServices, err = treeServices(a.TreeURL); err != nil {
		log.Fatalf("dav: --tree-url: %v", err)
	}
	copts := []client.Option{client.WithIdleConns(a.FetchConcurrency)}
	if a.Gateway {
		if a.Bearer != "" || a.BearerFile != "" || a.PasswordFile != "" || a.Author != "" {
			log.Fatal("dav: --gateway takes each request's grant; --bearer, --bearer-file, --password-file and --author are for local mode")
		}
		if !tls && !loopback(a.Addr) && !a.Insecure {
			log.Fatalf("dav: --gateway on %s, not a loopback address, needs --tls-cert and --tls-key (grants must not cross plain HTTP), or --insecure", a.Addr)
		}
		if plainRemote(a.API) {
			log.Printf("patchlog dav: warning: --api %s is plain HTTP to another host: every user's grant crosses the network to it in the clear", a.API)
		}
	} else {
		grant := a.Bearer
		if a.BearerFile != "" {
			if grant != "" {
				log.Fatal("dav: --bearer and --bearer-file are exclusive")
			}
			grant = readSecret("--bearer-file", a.BearerFile)
		}
		if grant != "" {
			copts = append(copts, client.WithBearer(grant))
		}
		if a.Author != "" {
			copts = append(copts, client.WithAuthor(a.Author))
		}
		if a.PasswordFile != "" {
			opt.Password = readSecret("--password-file", a.PasswordFile)
		} else {
			opt.Password = randomPassword()
			log.Printf("patchlog dav: WebDAV password (any user name): %s", opt.Password)
		}
		if !tls && !loopback(a.Addr) {
			log.Printf("patchlog dav: warning: serving plain HTTP on %s: the WebDAV password crosses the network in the clear", a.Addr)
		}
	}
	if opt.Client, err = client.New(a.API, copts...); err != nil {
		log.Fatal(err)
	}
	srv, err := dav.New(opt)
	if err != nil {
		log.Fatal(err)
	}
	// A catalog that isn't a file tree (no catalog.files) isn't served.
	cctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	err = srv.Check(cctx)
	cancel()
	if err != nil {
		log.Fatal(err)
	}

	ctx, sigs := shutdownSignals("patchlog dav")
	// A request (a written file, at most --max-raw-size) has ten minutes
	// to arrive, and an idle connection two before it is closed.
	hs := &http.Server{Addr: a.Addr, Handler: srv, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 10 * time.Minute, IdleTimeout: 2 * time.Minute}
	ls := a.shutdownArgs.server("patchlog dav", hs, nil)
	ln, err := net.Listen("tcp", a.Addr)
	if err != nil {
		log.Fatal(err)
	}
	mode, scheme := "local", "http"
	if a.Gateway {
		mode = "gateway"
	}
	if tls {
		scheme = "https"
	}
	log.Printf("patchlog dav: %s mode, serving %s of %s at %s://%s/", mode, strings.Join(append(flat, catalogs...), ","), a.API, scheme, ln.Addr())
	go func() {
		var err error
		if tls {
			err = ls.HTTP.ServeTLS(ln, a.TLSCert, a.TLSKey)
		} else {
			err = ls.HTTP.Serve(ln)
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatal(err)
		}
	}()
	<-ctx.Done()
	forceOnSecond(sigs)
	ls.Shutdown()
}

// treeServices splits --tree-url values into the default tree service, a
// plain URL, and those of catalogs given as CATALOG=URL, as serve's
// --tree-url takes them: what precedes a plain URL's first "=", if any,
// holds its scheme's colon, so it is never a namespace name.
func treeServices(vals []string) (string, map[string]string, error) {
	def, per := "", map[string]string{}
	for _, v := range vals {
		cat, u, ok := strings.Cut(v, "=")
		switch {
		case ok && core.ValidNSName(cat) && per[cat] != "":
			return "", nil, fmt.Errorf("catalog %s is mapped twice", cat)
		case ok && core.ValidNSName(cat):
			per[cat] = u
		case def != "":
			return "", nil, fmt.Errorf("%q: more than one default tree service (map the others as CATALOG=URL)", v)
		default:
			def = v
		}
	}
	return def, per, nil
}

// loopback reports whether a listen address is a loopback one only.
func loopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// plainRemote reports a base URL of plain HTTP to a host other than this
// one.
func plainRemote(api string) bool {
	u, err := url.Parse(api)
	if err != nil || u.Scheme != "http" {
		return false
	}
	if u.Hostname() == "localhost" {
		return false
	}
	ip := net.ParseIP(u.Hostname())
	return ip == nil || !ip.IsLoopback()
}

// loose reports a file others than its owner may read, as ssh does of a
// private key.
func loose(fi os.FileInfo) bool { return fi.Mode().Perm()&0o077 != 0 }

// readSecret reads a grant or password from a file, without surrounding
// white space.
func readSecret(flagName, file string) string {
	b, err := os.ReadFile(file)
	if err != nil {
		log.Fatalf("dav: %s: %v", flagName, err)
	}
	if fi, err := os.Stat(file); err == nil && loose(fi) {
		log.Printf("patchlog dav: warning: %s %s may be read by others (mode %v); chmod 600 it", flagName, file, fi.Mode().Perm())
	}
	s := strings.TrimSpace(string(b))
	if s == "" {
		log.Fatalf("dav: %s: %s is empty", flagName, file)
	}
	return s
}

// randomPassword is 128 random bits in lowercase base32.
func randomPassword() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("dav: random: %v", err))
	}
	return strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b))
}
