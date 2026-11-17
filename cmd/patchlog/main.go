// Command patchlog runs the patch-log server, its services and its client
// tools, and mints grants. Run patchlog --help, or patchlog COMMAND --help,
// for the commands and their flags.
//
// Grants are Biscuit v3 tokens (§C.8).
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"time"

	arg "github.com/alexflint/go-arg"

	"github.com/middle-management/patchlog/internal/bundle"
	"github.com/middle-management/patchlog/internal/cdnpurge"
	"github.com/middle-management/patchlog/internal/core"
	"github.com/middle-management/patchlog/internal/cors"
	"github.com/middle-management/patchlog/internal/edge"
	"github.com/middle-management/patchlog/internal/grant"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/keystore"
	"github.com/middle-management/patchlog/internal/playground"
	"github.com/middle-management/patchlog/internal/server"
)

// version is set at build time: -ldflags "-X main.version=v1.2.3".
var version = "dev"

// runner is a command: run is called with the name of the (innermost)
// subcommand that was given, for structs that serve several.
type runner interface{ run(name string) }

// cli is the patchlog command line: one subcommand.
type cli struct {
	Serve *serveCmd `arg:"subcommand:serve" group:"Server commands" help:"run the patch-log server"`
	Index *indexCmd `arg:"subcommand:index" group:"Server commands" help:"run the search index service (Addendum A)"`
	Tree  *treeCmd  `arg:"subcommand:tree" group:"Server commands" help:"run the tree service, or with --access the catalog service (Addendum B)"`
	Dav   *davCmd   `arg:"subcommand:dav" group:"Server commands" help:"serve namespaces over WebDAV (a prototype)"`

	Get   *getCmd   `arg:"subcommand:get" group:"Client commands" help:"print a resource's document"`
	Put   *putCmd   `arg:"subcommand:put" group:"Client commands" help:"create a resource"`
	Patch *patchCmd `arg:"subcommand:patch" group:"Client commands" help:"append a JSON Patch to a resource"`
	Rm    *rmCmd    `arg:"subcommand:rm" group:"Client commands" help:"delete (tombstone) a resource"`
	Log   *logCmd   `arg:"subcommand:log" group:"Client commands" help:"print a resource's history"`
	Watch *watchCmd `arg:"subcommand:watch" group:"Client commands" help:"follow a namespace's log as it is written"`
	NS    *nsCmd    `arg:"subcommand:ns" group:"Client commands" help:"create, read and configure namespaces (create, get, config, log)"`

	Merge   *mergeCmd   `arg:"subcommand:merge" group:"Branches, releases and bundles" help:"merge a branch, or a release across namespaces (Addendum F)"`
	Rebase  *rebaseCmd  `arg:"subcommand:rebase" group:"Branches, releases and bundles" help:"rebase a branch into a successor branch (§F.5)"`
	Janitor *janitorCmd `arg:"subcommand:janitor" group:"Branches, releases and bundles" help:"purge merged and abandoned branches (§F.6)"`
	Export  *exportCmd  `arg:"subcommand:export" group:"Branches, releases and bundles" help:"export namespaces to a bundle (§G.4)"`
	Import  *importCmd  `arg:"subcommand:import" group:"Branches, releases and bundles" help:"import a bundle into a namespace (§G.4.4)"`
	Bundle  *bundleCmd  `arg:"subcommand:bundle" group:"Branches, releases and bundles" help:"verify a bundle, or make a bundle key"`
	Schema  *schemaCmd  `arg:"subcommand:schema" group:"Branches, releases and bundles" help:"import external JSON Schemas into a namespace"`
	E2E     *e2eCmd     `arg:"subcommand:e2e" group:"Branches, releases and bundles" help:"inspect e2e namespaces (Addendum E)"`

	Keygen     *keygenCmd  `arg:"subcommand:keygen" group:"Keys and operations" help:"print a new Ed25519 key pair for minting grants"`
	Grant      *grantCmd   `arg:"subcommand:grant" group:"Keys and operations" help:"mint, narrow or seal a grant (Biscuit v3, §C.8)"`
	Archive    *archiveCmd `arg:"subcommand:archive" group:"Keys and operations" help:"restore pruned history from its archives (§8.6)"`
	Health     *healthCmd  `arg:"subcommand:health" group:"Keys and operations" help:"check a health endpoint (exit 0 on 200), for container healthchecks"`
	VersionCmd *versionCmd `arg:"subcommand:version" group:"Keys and operations" help:"print the version"`
}

// writeRootHelp writes patchlog's own help: the commands by their group
// tag, which go-arg's help (a flat list) doesn't know.
func writeRootHelp(w io.Writer) {
	fmt.Fprintln(w, "Usage: patchlog <command> [<args>]")
	t := reflect.TypeOf(cli{})
	group := ""
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if g := f.Tag.Get("group"); g != group {
			group = g
			fmt.Fprintf(w, "\n%s:\n", group)
		}
		_, name, _ := strings.Cut(strings.Split(f.Tag.Get("arg"), ",")[0], ":")
		fmt.Fprintf(w, "  %-9s %s\n", name, f.Tag.Get("help"))
	}
	fmt.Fprint(w, `
Run patchlog <command> --help for a command's flags. The client commands and
tools take --api, --bearer and --author, or $PATCHLOG_API, $PATCHLOG_BEARER and
$PATCHLOG_AUTHOR; resources are named NS/NAME, and JSON is given inline, as
@FILE, or - for stdin.
`)
}

// telemetryCommands are the commands that set up OpenTelemetry, if
// configured by OTEL_* (off by default).
var telemetryCommands = []string{"serve", "index", "tree", "dav", "merge", "rebase", "janitor", "export", "import", "bundle", "archive", "schema"}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run parses args, runs the command they name and returns the exit status
// (commands that fail mostly exit on their own).
func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 1 && (args[0] == "-version" || args[0] == "--version") {
		args = []string{"version"}
	}
	if msg := removedCommand(args); msg != "" {
		fmt.Fprintln(stderr, msg)
		return 1
	}
	var c cli
	p, err := newParser(&c, stdout)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	switch err := p.Parse(args); {
	case errors.Is(err, arg.ErrHelp) && len(p.SubcommandNames()) == 0:
		writeRootHelp(stdout)
		return 0
	case errors.Is(err, arg.ErrHelp):
		p.WriteHelpForSubcommand(stdout, p.SubcommandNames()...)
		return 0
	case err != nil:
		p.WriteUsageForSubcommand(stderr, p.SubcommandNames()...)
		fmt.Fprintln(stderr, "error:", flagNamed(err, p.Subcommand()))
		return 2
	}
	names := p.SubcommandNames()
	r, ok := p.Subcommand().(runner)
	if !ok {
		// No command, or a group without its subcommand (patchlog merge).
		if len(names) == 0 {
			writeRootHelp(stderr)
		} else {
			p.WriteHelpForSubcommand(stderr, names...)
		}
		return 2
	}
	if slices.Contains(telemetryCommands, names[0]) {
		// Flushed when the command returns (after a server's graceful
		// shutdown), not on log.Fatal.
		defer startTelemetry(names[0])()
	}
	r.run(names[len(names)-1])
	return 0
}

// flagNamed rewrites go-arg's "PLACEHOLDER is required" to name the flag
// whose placeholder it is in dest.
func flagNamed(err error, dest any) error {
	ph, ok := strings.CutSuffix(err.Error(), " is required")
	if !ok || dest == nil {
		return err
	}
	var name string
	var walk func(t reflect.Type)
	walk = func(t reflect.Type) {
		for i := 0; i < t.NumField() && name == ""; i++ {
			f := t.Field(i)
			if f.Anonymous && f.Type.Kind() == reflect.Struct {
				walk(f.Type)
				continue
			}
			long, opts, _ := strings.Cut(f.Tag.Get("arg"), ",")
			if !slices.Contains(strings.Split(opts, ","), "required") {
				continue
			}
			p, ok := f.Tag.Lookup("placeholder")
			if !ok {
				p = strings.ToUpper(strings.TrimLeft(long, "-"))
			}
			if p == ph && strings.HasPrefix(long, "--") {
				name = long
			}
		}
	}
	walk(reflect.TypeOf(dest).Elem())
	if name == "" {
		return err
	}
	return fmt.Errorf("%s is required", name)
}

func newParser(dest any, out io.Writer) (*arg.Parser, error) {
	return arg.NewParser(arg.Config{Program: "patchlog", Out: out, StrictSubcommands: true}, dest)
}

type versionCmd struct{}

func (versionCmd) run(string) { fmt.Println("patchlog", version) }

type keygenCmd struct{}

func (keygenCmd) run(string) {
	pub, priv := grant.GenerateKey()
	fmt.Printf("public  %s\nprivate %s\n", pub, grant.EncodePrivateKey(priv))
}

// serveCmd is patchlog serve.
type serveCmd struct {
	Addr                string        `arg:"--addr" default:":8080" help:"listen address"`
	DB                  string        `arg:"--db,env:PATCHLOG_DB" default:"patchlog.db" placeholder:"PATH|URL" help:"SQLite database path, or a Postgres URL (postgres://user:pass@host/db, Addendum D.8)"`
	BlobDir             string        `arg:"--blob-dir,env:PATCHLOG_BLOB_DIR" placeholder:"DIR" help:"directory blob bytes are stored in; default <db>.blobs next to a SQLite file. On Postgres every instance must share it (a shared volume); without one, bytes are stored in the database"`
	Origin              string        `arg:"--origin" default:"http://localhost:8080" placeholder:"URL" help:"canonical origin (§G.1)"`
	Dev                 bool          `arg:"--dev" help:"disable authentication (development only); X-Author names the author"`
	Playground          bool          `arg:"--playground" default:"true" help:"serve the web playground at /playground/ (--playground=false to turn it off)"`
	InlinePDF           bool          `arg:"--inline-pdf" help:"serve application/pdf blobs for inline display, without the sandbox that blanks Chromium's viewer, instead of with Content-Disposition: attachment (§7.8)"`
	TreeURL             []string      `arg:"--tree-url,separate" placeholder:"[CATALOG=]URL" help:"tree service (Addendum B) the playground reads through a read-only proxy at /playground/tree/, e.g. http://tree:8082; CATALOG=URL maps one catalog to its own (repeatable)"`
	IndexURL            string        `arg:"--index-url" placeholder:"URL" help:"search index (Addendum A) the playground reads through a read-only proxy at /playground/index/, e.g. http://index:8081; one index serves several namespaces"`
	SchemaFetch         bool          `arg:"--schema-fetch" help:"let the playground's schema import fetch http(s) URLs (off: it takes uploaded files only); private, loopback and link-local addresses are refused unless the host is in --schema-fetch-hosts"`
	SchemaFetchHosts    string        `arg:"--schema-fetch-hosts" placeholder:"H,H" help:"comma-separated hosts --schema-fetch is limited to, e.g. www.schemastore.org,raw.githubusercontent.com (also trusted with private addresses)"`
	MaxItemsPerBatch    int           `arg:"--max-items-per-batch" placeholder:"N" help:"deployment maximum items per batch (default: the namespace default, 1000); allowances may go up to it, so an atomic import of more items needs it raised (§6.6)"`
	MaxBatchSize        *byteSize     `arg:"--max-batch-size" placeholder:"SIZE" help:"deployment maximum batch size, e.g. \"64 MiB\" (default: the namespace default, 16 MiB); allowances may go up to it (§6.6)"`
	DocumentSize        *byteSize     `arg:"--document-size" placeholder:"SIZE" help:"default documentSize of namespaces that don't set one, e.g. \"4 MiB\" (default 1 MiB, where §6.6 says 4 MiB; see docs/CAPACITY.md), at most --max-document-size"`
	MaxDocumentSize     *byteSize     `arg:"--max-document-size" placeholder:"SIZE" help:"deployment maximum documentSize, which namespaces may set in their limits, e.g. \"8 MiB\" (default 4 MiB, §6.6's default)"`
	MaxValidationSteps  int           `arg:"--max-validation-steps" default:"5000000" placeholder:"N" help:"steps validating one document against its schema may take, a step being one schema applied to one value; a write that needs more is refused (422 limit, validationSteps); 0 for no limit"`
	FullValidation      bool          `arg:"--full-validation" help:"validate the whole document on every write; by default a patch to a document this instance has validated against the same schema revision is validated only where it can have changed the verdict"`
	GrantCache          int           `arg:"--grant-cache" placeholder:"N" help:"verified bearer grants kept per instance, the least recently used evicted (default 65536; every request whose grant isn't kept verifies it, docs/CAPACITY.md)"`
	DocCacheSize        *byteSize     `arg:"--doc-cache-size" placeholder:"SIZE" help:"documents kept in memory by revision id, e.g. \"1 GiB\" (default 256 MiB)"`
	ReadCacheSize       *byteSize     `arg:"--read-cache-size" placeholder:"SIZE" help:"revisions the read cache keeps, served without a transaction, e.g. \"256 MiB\" (default 64 MiB)"`
	MaxBlobSize         *byteSize     `arg:"--max-blob-size" placeholder:"SIZE" help:"deployment maximum blob size, e.g. \"1 GiB\" (default: the namespace default, 64 MiB; §7.8)"`
	MaxBlobPending      *byteSize     `arg:"--max-blob-pending" placeholder:"SIZE" help:"deployment maximum bytes of pending blobs per uploader and namespace, e.g. \"16 GiB\" (default: the namespace default, 256 MiB); allowances may go up to it (§6.6)"`
	LogPageSize         int           `arg:"--log-page-size" placeholder:"N" help:"log page size (§6.6, deployment only): a log range answers at most this many entries a page, with X-Log-Next naming the next page's since (§7.1); long-poll answers and /heads pages are as long (default 1000)"`
	LogPageBytes        *byteSize     `arg:"--log-page-bytes" placeholder:"SIZE" help:"bytes of patch sets per resource log page (§6.6 logPageBytes, deployment only), e.g. \"16 MiB\" (the default): a resource log range, long-poll answer or event-stream catch-up page ends before an entry that would take it past, though it always holds one (§7.1, §7.7)"`
	MaxRatePerNS        string        `arg:"--max-rate-per-namespace" placeholder:"RATE,BURST" help:"deployment maximum of ratePerNamespace, e.g. 100000,1000000 (default: the namespace default, 500,1000): namespaces may set their ratePerNamespace up to it, and an allowance's bucket never exceeds it, so an importer's or load harness's allowance needs it raised (§6.6)"`
	MaxRatePerResource  string        `arg:"--max-rate-per-resource" placeholder:"RATE,BURST" help:"deployment maximum of ratePerResource (default: the namespace default, 10,20): namespaces may set their ratePerResource up to it, for small documents that one principal writes often; no allowance lifts the per-resource rate (§6.6)"`
	MaxRatePrincipal    string        `arg:"--max-rate-per-principal" placeholder:"RATE,BURST" help:"deployment maximum of ratePerPrincipal (default: the namespace default, 50,100): namespaces may set their ratePerPrincipal up to it (§6.6)"`
	ExchangeRate        string        `arg:"--exchange-rate" placeholder:"RATE,BURST" help:"edge-grant exchanges per principal (§6.6, §C.5, deployment only), e.g. 10,100 (the default): each POST /edge-grants draws one token from the bucket of each principal whose grants it carries, and none from their write buckets"`
	OperatorKey         []string      `arg:"--operator-key,separate" placeholder:"PUB" help:"base64url Ed25519 public key allowed to create namespaces (repeatable; kid is \"operator\", \"operator-2\", …)"`
	OperatorKeyHistory  []string      `arg:"--operator-key-history,separate" placeholder:"KID=PUB,FROM[,UNTIL]" help:"an operator key and the RFC 3339 period it was in force, published in the JWK Set at jwks_uri (§C.4); list retired keys here too, which are published but no longer accepted; a key authorises only from FROM until UNTIL, even as an --operator-key (repeatable; FROM must be no later than the first entry written under a grant the key signed; an --operator-key not listed is published as in force since the deployment's first entry)"`
	JWKSURI             string        `arg:"--jwks-uri" placeholder:"URL" help:"the jwks_uri GET / publishes (§C.4); default <origin>/.well-known/patchlog-keys, which this server serves"`
	Archive             string        `arg:"--archive" placeholder:"file:///DIR" help:"default pruning archive destination, a file:// directory (§8.6)"`
	ArchiveRoot         []string      `arg:"--archive-root,separate" placeholder:"file:///DIR" help:"file:// directory under which retention rules may name archive destinations (repeatable; --archive is always allowed)"`
	RetentionInterval   time.Duration `arg:"--retention-interval" default:"1h" placeholder:"DURATION" help:"how often retention policies are applied (0 disables)"`
	RemoteBearer        []string      `arg:"--remote-bearer,separate" placeholder:"ORIGIN=GRANT" help:"grant sent to the deployment at ORIGIN for remote branches (read, and export to register) (repeatable, §G.3)"`
	RemoteURL           []string      `arg:"--remote-url,separate" placeholder:"ORIGIN=URL" help:"reach the deployment at ORIGIN through URL instead (repeatable)"`
	RemoteOriginURL     []string      `arg:"--remote-origin-url,separate" placeholder:"ORIGIN=URL" help:"ignored since v0.81; still accepted, with a warning at start, so command lines keep working: it said where the deployment at ORIGIN itself answers, for the start times of a source's epochs from before its e2e raise, which no remote branch reads any more (Addendum E Levels)"`
	RemoteIdentity      []string      `arg:"--remote-identity,separate" placeholder:"ORIGIN=FILE" help:"X25519 private key (JWK) unwrapping the keys of sealed bases at ORIGIN, named by the --remote-bearer grant's enc (repeatable, §G.5.2)"`
	RemoteFollow        time.Duration `arg:"--remote-follow-interval" default:"5m" placeholder:"DURATION" help:"how often remote bases' logs are followed: their purges applied and their raises of level followed (§G.3, §G.5.2); 0 disables following"`
	RemoteFollowTimeout time.Duration `arg:"--remote-follow-timeout" default:"10m" placeholder:"DURATION" help:"how long one remote base's step of a follow may take, after which it is given up until the next and the next base is followed"`
	RemoteRegister      bool          `arg:"--remote-register" help:"register remote branches with their bases and renew the registrations (§G.3)"`
	MasterKey           string        `arg:"--master-key" placeholder:"FILE" help:"file holding the 32-byte master key of encryption at rest (Addendum E.1); mode 0600"`
	MasterKeyCreate     bool          `arg:"--master-key-create" help:"create the --master-key file with a new random key if it doesn't exist"`
	RotateEpochs        time.Duration `arg:"--rotate-epochs" default:"0s" placeholder:"DURATION" help:"rotate every sealed namespace's epoch once it is this old, e.g. 24h (Addendum E.2; 0 disables)"`
	RotateOnRevoke      bool          `arg:"--rotate-on-revoke" help:"rotate a sealed namespace's epoch right after a config write that revokes a grant or removes or changes a key (§E.2.4)"`
	PurgeRaisedE2E      bool          `arg:"--purge-raised-e2e" help:"purge at start, destroying their keys, the namespaces an earlier version raised to e2e by a config write and the remote branches of sources raised so, which this version refuses to start with (Addendum E Levels; to keep a copy, export them with the v0.26.1 tools first)"`
	GroupCommit         int           `arg:"--group-commit" default:"32" placeholder:"N" help:"Postgres: at most this many concurrent resource writes and batches of one namespace committed in one transaction (group commit, D.8); 1 or less commits every write on its own"`
	GroupCommitWait     time.Duration `arg:"--group-commit-wait" default:"200us" placeholder:"DURATION" help:"Postgres: at most how long a group waits for writes of its namespace still being checked (0: no wait)"`
	LocalRateBuckets    bool          `arg:"--local-rate-buckets" help:"Postgres: keep the rate-limit buckets (§6.6) in this instance's memory rather than in the database, saving a round trip per write; only for a deployment of one instance, since instances sharing a database must share their buckets"`
	StoreCompression    string        `arg:"--store-compression" default:"off" placeholder:"off|zstd" help:"zstd: store the patch sets of namespaces without encryption, from 1 KiB, compressed (SQLite only). A format change: earlier versions can't read a database once it holds compressed patch sets, and turning it off again doesn't decompress them"`
	EdgeGrantKey        []string      `arg:"--edge-grant-key,separate" placeholder:"[KID=]FILE" help:"a file holding a key edge-grant cookies of POST /edge-grants are signed with, named KID (a plain FILE takes --edge-grant-kid) (§C.5); a FILE with '=' before any '/' is given as KID=FILE or ./FILE; repeatable, to rotate keys: cookies under any are accepted, and the last given signs new ones. Without it, a random key per process, so cookies don't survive a restart, reach another instance or verify at an edge: an edge verifying cookies needs key files. FILE edge-secret is the key derived from --edge-secret, for migrating to key files only: every holder of the edge secret, services included, can derive it and mint cookies with it"`
	EdgeGrantKid        string        `arg:"--edge-grant-kid" default:"origin" placeholder:"KID" help:"the name (kid) of the edge-grant key given as a plain --edge-grant-key FILE, or of the random one without --edge-grant-key, which the cookies carry and a verifying edge looks the key up by (§C.5.3)"`
	purgeArgs
	edgeArgs
	corsArgs
	shutdownArgs
}

func (a *serveCmd) run(string) {
	ev := edgeVerifier(a.EdgeSecret, a.EdgeHeader, a.EdgePrefixHeader)
	cookies, warn, err := edgeGrantCookies(a.EdgeGrantKid, a.EdgeGrantKey, ev, &a.corsArgs)
	if err != nil {
		log.Fatal(err)
	}
	for _, w := range warn {
		log.Print("warning: " + w)
	}
	if len(a.EdgeGrantKey) > 0 {
		log.Printf("edge grants: minted under kid %s, accepted under %s", cookies.Kid(), strings.Join(cookies.Kids(), ", "))
	}
	remote, warn, err := remoteOptions(a.RemoteBearer, a.RemoteURL, a.RemoteIdentity, a.RemoteOriginURL)
	if err != nil {
		log.Fatal(err)
	}
	for _, w := range warn {
		log.Print("warning: " + w)
	}
	remote.Register, remote.FollowInterval, remote.FollowTimeout = a.RemoteRegister, a.RemoteFollow, a.RemoteFollowTimeout
	if remote.FollowInterval == 0 {
		remote.FollowInterval = -1
	}

	var keys []grant.Key
	for i, k := range a.OperatorKey {
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
	history, err := operatorKeyHistory(a.OperatorKeyHistory)
	if err != nil {
		log.Fatalf("--operator-key-history: %v", err)
	}
	if !a.Dev && len(keys) == 0 {
		log.Print("warning: no --operator-key given; no namespace can be created")
	}
	max := core.DefaultMaximums()
	if a.MaxItemsPerBatch > 0 {
		max.ItemsPerBatch = a.MaxItemsPerBatch
	}
	if a.LogPageSize < 0 {
		log.Fatal("--log-page-size must be positive")
	}
	if a.LogPageSize > 0 {
		max.LogPageSize = a.LogPageSize
	}
	if a.LogPageBytes != nil && *a.LogPageBytes <= 0 {
		log.Fatal("--log-page-bytes must be positive")
	}
	max.LogPageBytes = sizeOr(a.LogPageBytes, max.LogPageBytes)
	if a.ExchangeRate != "" {
		r, err := parseRate(a.ExchangeRate)
		if err != nil {
			log.Fatalf("--exchange-rate: %v", err)
		}
		max.ExchangeRate = r
	}
	max.BatchSize = sizeOr(a.MaxBatchSize, max.BatchSize)
	max.BlobSize = sizeOr(a.MaxBlobSize, max.BlobSize)
	max.BlobPending = sizeOr(a.MaxBlobPending, max.BlobPending)
	max.DocumentSize = sizeOr(a.MaxDocumentSize, max.DocumentSize)
	if a.GrantCache < 0 {
		log.Fatal("--grant-cache must be positive")
	}
	limits := core.DefaultLimits()
	if a.DocumentSize != nil {
		if n := int(*a.DocumentSize); n > max.DocumentSize {
			log.Fatalf("--document-size %d exceeds --max-document-size %d", n, max.DocumentSize)
		}
		limits.DocumentSize = int(*a.DocumentSize)
	} else {
		limits.DocumentSize = min(limits.DocumentSize, max.DocumentSize)
	}
	for _, f := range []struct{ flag, key, v string }{
		{"--max-rate-per-namespace", "ratePerNamespace", a.MaxRatePerNS},
		{"--max-rate-per-resource", "ratePerResource", a.MaxRatePerResource},
		{"--max-rate-per-principal", "ratePerPrincipal", a.MaxRatePrincipal},
	} {
		if err := rateMaximumOf(f.key, f.v, &limits, &max); err != nil {
			log.Fatalf("%s: %v", f.flag, err)
		}
	}
	arch, err := archiver(a.Archive, a.ArchiveRoot)
	if err != nil {
		log.Fatalf("--archive: %v", err)
	}
	retention := a.RetentionInterval
	if retention == 0 {
		retention = -1
	}
	var ks core.KeyStore
	if a.MasterKey != "" {
		l, err := keystore.LoadFile(a.MasterKey, a.MasterKeyCreate)
		if err != nil {
			log.Fatalf("--master-key: %v", err)
		}
		ks = l
	} else if a.MasterKeyCreate {
		log.Fatal("--master-key-create needs --master-key")
	}
	var treeProxy http.Handler
	if len(a.TreeURL) > 0 {
		if !a.Playground {
			log.Fatal("--tree-url needs the playground (it proxies under " + server.TreeProxyPrefix + ")")
		}
		if treeProxy, err = server.NewTreeProxy(a.TreeURL...); err != nil {
			log.Fatal(err)
		}
	}
	var indexProxy http.Handler
	if a.IndexURL != "" {
		if !a.Playground {
			log.Fatal("--index-url needs the playground (it proxies under " + server.IndexProxyPrefix + ")")
		}
		if indexProxy, err = server.NewIndexProxy(a.IndexURL); err != nil {
			log.Fatal(err)
		}
	}
	opt := core.Options{Path: a.DB, BlobDir: a.BlobDir, Origin: a.Origin, AuthDisabled: a.Dev, OperatorKeys: keys, OperatorKeyHistory: history, JWKSURI: a.JWKSURI,
		Limits: limits, Maximums: max, GrantCacheEntries: a.GrantCache, DocCacheBytes: sizeOr(a.DocCacheSize, 0), ReadCacheBytes: sizeOr(a.ReadCacheSize, 0), Archiver: arch, RetentionInterval: retention, Remote: remote, KeyStore: ks,
		RotateEpochs: a.RotateEpochs, RotateOnRevoke: a.RotateOnRevoke, PurgeRaisedE2E: a.PurgeRaisedE2E, GroupCommit: a.GroupCommit, GroupCommitWait: a.GroupCommitWait, LocalRateBuckets: a.LocalRateBuckets, StoreCompression: a.StoreCompression}
	if opt.GroupCommit < 1 {
		opt.GroupCommit = 1 // off
	}
	opt.FullValidation = a.FullValidation
	if opt.MaxValidationSteps = a.MaxValidationSteps; a.MaxValidationSteps <= 0 {
		opt.MaxValidationSteps = -1 // no limit
	}
	if opt.GroupCommitWait <= 0 {
		opt.GroupCommitWait = -1 // none
	}
	purger := cdnPurger(a.PurgeURL)
	if purger != nil {
		opt.Purger = purger
	}
	e, err := core.Open(opt)
	if err != nil {
		log.Fatal(err)
	}
	sopts := []server.Option{server.WithEdge(ev), server.WithEdgeGrants(cookies)}
	if a.InlinePDF {
		sopts = append(sopts, server.WithInlinePDF())
	}
	srv := &http.Server{Addr: a.Addr, Handler: a.corsArgs.wrap(handler(server.New(e, sopts...), a.Playground, treeProxy, indexProxy, playground.Options{SchemaFetch: a.SchemaFetch, SchemaFetchHosts: splitList(a.SchemaFetchHosts)})), ReadHeaderTimeout: 10 * time.Second}
	ls := a.shutdownArgs.server("patchlog", srv, e.Ping)
	sigCtx, sigs := shutdownSignals("patchlog")
	ln, err := net.Listen("tcp", a.Addr)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("patchlog %s listening on %s (origin %s, dev=%v)", version, a.Addr, a.Origin, a.Dev)
	if a.Playground {
		log.Printf("playground: %s%s", localURL(a.Addr), playground.Prefix)
	}
	if treeProxy != nil {
		log.Printf("tree proxy: %s%s -> %s (GET/HEAD only)", localURL(a.Addr), server.TreeProxyPrefix, strings.Join(a.TreeURL, ","))
	}
	if indexProxy != nil {
		log.Printf("index proxy: %s%s -> %s (GET/HEAD only)", localURL(a.Addr), server.IndexProxyPrefix, a.IndexURL)
	}
	serveOn(ls, ln)
	<-sigCtx.Done()
	forceOnSecond(sigs)
	// Handlers have returned (or been cancelled) before the engine stops
	// its background jobs and closes the database; queued purges are
	// flushed last.
	ls.Shutdown()
	if err := e.Close(); err != nil {
		log.Printf("patchlog: closing the engine: %v", err)
	}
	closePurger(purger)
	log.Print("patchlog: stopped")
}

// wrap adds CORS to h as the flags configure it, exiting on bad values.
func (c *corsArgs) wrap(h http.Handler) http.Handler {
	origins, err := cors.Parse(c.CORSOrigin)
	if err != nil {
		log.Fatalf("--cors-origin: %v", err)
	}
	if c.CORSCredentials && slices.Contains(origins, "*") {
		log.Fatal("--cors-credentials needs explicit --cors-origin values, not *")
	}
	credOrigins, err := c.credentialOrigins()
	if err != nil {
		log.Fatal(err)
	}
	if len(origins) > 0 {
		log.Printf("CORS: allowing %s", strings.Join(origins, ", "))
	}
	if len(credOrigins) > 0 {
		log.Printf("CORS: allowing credentials from %s", strings.Join(credOrigins, ", "))
	}
	return cors.Wrap(h, cors.Config{Origins: origins, CredentialOrigins: credOrigins, Credentials: c.CORSCredentials, MaxAge: c.CORSMaxAge})
}

// credentialOrigins are the --cors-credentials-origin values, checked.
func (c *corsArgs) credentialOrigins() ([]string, error) {
	out, err := cors.Parse(c.CORSCredentialsOrigin)
	if err != nil {
		return nil, fmt.Errorf("--cors-credentials-origin: %v", err)
	}
	if slices.Contains(out, "*") {
		return nil, fmt.Errorf("--cors-credentials-origin takes named origins, not *")
	}
	return out, nil
}

// parseRate parses a token bucket given as RATE,BURST (§6.6): tokens a
// second, positive, and the bucket's size, at least 1.
func parseRate(s string) (core.Rate, error) {
	rs, bs, ok := strings.Cut(s, ",")
	r, err1 := strconv.ParseFloat(strings.TrimSpace(rs), 64)
	b, err2 := strconv.ParseFloat(strings.TrimSpace(bs), 64)
	if !ok || err1 != nil || err2 != nil || !(r > 0) || !(b >= 1) || math.IsInf(r, 0) || math.IsInf(b, 0) {
		return core.Rate{}, fmt.Errorf("%q: want RATE,BURST, a positive rate a second and a burst of at least 1", s)
	}
	return core.Rate{Rate: r, Burst: b}, nil
}

// rateMaximum applies --max-rate-per-namespace, RATE,BURST ("" leaves the
// default), as the deployment's maximum of ratePerNamespace (§6.6): what a
// namespace may set its own to, and what an allowance's bucket may be at
// most. The default limit is held to it.
func rateMaximum(s string, limits, max *core.Limits) error {
	return rateMaximumOf("ratePerNamespace", s, limits, max)
}

// rateMaximumOf applies a -max-rate-per-… flag, RATE,BURST ("" leaves the
// default), as the deployment's maximum of the rate limit named key
// (ratePerNamespace, ratePerResource or ratePerPrincipal, §6.6): what a
// namespace may set its own to. The default limit is held to it.
func rateMaximumOf(key, s string, limits, max *core.Limits) error {
	if s == "" {
		return nil
	}
	r, err := parseRate(s)
	if err != nil {
		return err
	}
	field := func(l *core.Limits) *core.Rate {
		switch key {
		case "ratePerResource":
			return &l.RatePerResource
		case "ratePerPrincipal":
			return &l.RatePerPrincipal
		}
		return &l.RatePerNamespace
	}
	*field(max) = r
	cur := field(limits)
	*cur = core.Rate{Rate: min(cur.Rate, r.Rate), Burst: min(cur.Burst, r.Burst)}
	return nil
}

// edgeSecretKey, as the FILE of the origin's --edge-grant-key, is the key
// derived from --edge-secret (edge.KeyFromSecret), for migrating a
// deployment that minted under it to key files without making clients
// exchange again (§C.5.3). Every holder of the edge secret can
// derive it, the services that take --edge-secret for their own edge
// lifetimes included, and mint core cookies with it, so the origin holds
// it only when named so. A file of that name is given as ./edge-secret.
const edgeSecretKey = "edge-secret"

// edgeGrantKey is one --edge-grant-key flag's key and the kid naming it.
type edgeGrantKey struct {
	kid, file string
	key       []byte
}

// derived reports the key derived from the edge secret (FILE
// edgeSecretKey).
func (k edgeGrantKey) derived() bool { return k.file == edgeSecretKey }

// readEdgeGrantKeys reads the keys of --edge-grant-key flags, [KID=]FILE, a
// plain FILE named kid, in the order given. A flag is KID=FILE only when
// no '/' comes before its first '=', so a path holding '=' is a plain
// FILE. A key is its file's bytes, surrounding whitespace trimmed, at
// least 16; FILE edgeSecretKey is the key derived from ev's secret, which
// only the origin may hold (origin false refuses it).
func readEdgeGrantKeys(kid string, keyFlags []string, ev *edge.Verifier, origin bool) ([]edgeGrantKey, error) {
	var out []edgeGrantKey
	for _, f := range keyFlags {
		k, file, ok := strings.Cut(f, "=")
		if !ok || strings.ContainsAny(k, "/"+string(filepath.Separator)) {
			k, file = kid, f
		}
		if k == "" || file == "" {
			return nil, fmt.Errorf("--edge-grant-key %q: want KID=FILE or FILE", f)
		}
		gk := edgeGrantKey{kid: k, file: file}
		switch {
		case gk.derived() && !origin:
			return nil, fmt.Errorf("--edge-grant-key %s: the key derived from --edge-secret is never a service's: the origin may hold it (a file of that name is ./%s)", f, edgeSecretKey)
		case gk.derived():
			if gk.key = ev.CookieKey(); gk.key == nil {
				return nil, fmt.Errorf("--edge-grant-key %s: the key derived from --edge-secret needs --edge-secret (a file of that name is ./%s)", f, edgeSecretKey)
			}
		default:
			b, err := os.ReadFile(file)
			if err != nil {
				return nil, fmt.Errorf("--edge-grant-key: %v", err)
			}
			gk.key = []byte(strings.TrimSpace(string(b)))
			if len(gk.key) < 16 {
				return nil, fmt.Errorf("--edge-grant-key %s: the key must be at least 16 bytes", file)
			}
		}
		out = append(out, gk)
	}
	return out, nil
}

// cookiesOf returns the edge-grant cookies of keys, oldest first: minting
// with the last and accepting all, so keys rotate (edge.Cookies.AddKey).
// They are SameSite=None when pages on other origins may call with
// credentials (--cors-credentials-origin), else Lax.
func cookiesOf(keys []edgeGrantKey, c *corsArgs) (*edge.Cookies, error) {
	var ck *edge.Cookies
	for _, k := range keys {
		if ck == nil {
			ck = edge.NewCookies(k.kid, k.key)
		} else if err := ck.AddKey(k.kid, k.key); err != nil {
			return nil, fmt.Errorf("--edge-grant-key %s: %v", k.file, err)
		}
	}
	if co, err := c.credentialOrigins(); err == nil && (len(co) > 0 || c.CORSCredentials) {
		ck.SameSite = http.SameSiteNoneMode
	}
	return ck, nil
}

// edgeGrantCookies returns the edge-grant cookies of POST /edge-grants
// (§C.5): under the --edge-grant-key flags (readEdgeGrantKeys), minting
// with the last and accepting all, so keys rotate (§C.5.3);
// without one, under a random key of this process, named kid, which no
// edge can verify. It never falls back on the key derived from the edge
// secret, which every service holding the secret could derive too:
// FILE edgeSecretKey opts in to it, for migration only. warn says what
// the operator should know of the choice: a verifying edge without key
// files, or the derived key held.
func edgeGrantCookies(kid string, keyFlags []string, ev *edge.Verifier, c *corsArgs) (ck *edge.Cookies, warn []string, err error) {
	if kid == "" {
		return nil, nil, errors.New("--edge-grant-kid: empty")
	}
	keys, err := readEdgeGrantKeys(kid, keyFlags, ev, true)
	if err != nil {
		return nil, nil, err
	}
	if len(keys) == 0 {
		keys = []edgeGrantKey{{kid: kid}} // a random key (edge.NewCookies)
		if ev != nil {
			warn = append(warn, "edge grants: --edge-secret without --edge-grant-key: cookies are signed with a random key of this process, so they verify only at this instance, not after a restart, and no edge can verify them; "+
				"with several origin instances, cookies one mints are refused by the others, so give every instance the same --edge-grant-key key files. "+
				"An edge verifying cookies needs those key files too, and must drop the key derived from the edge secret: it is no longer used by default, since every service holding the secret could derive it")
		}
	}
	for _, k := range keys {
		if k.derived() {
			warn = append(warn, fmt.Sprintf("edge grants: --edge-grant-key %s=%s holds the key derived from --edge-secret: every holder of the edge secret, the catalog service and the search index included, can derive it and mint cookies for any namespace with it. Use it only to migrate to key files, and drop it once its cookies have expired (§C.5)", k.kid, edgeSecretKey))
		}
	}
	ck, err = cookiesOf(keys, c)
	return ck, warn, err
}

// edgeVerifier returns the verifying edge of --edge-secret, or nil.
func edgeVerifier(file, header, prefixHeader string) *edge.Verifier {
	if file == "" {
		return nil
	}
	v, err := edge.Load(file, header, prefixHeader)
	if err != nil {
		log.Fatalf("--edge-secret: %v", err)
	}
	log.Printf("verifying edge: edge lifetimes for private reads with %s and %s", v.Header(), v.PrefixHeader())
	return v
}

// cdnPurger returns the HTTP purger for --purge-url flags, or nil (the
// services' default purger then logs).
func cdnPurger(urls []string) *cdnpurge.Purger {
	if len(urls) == 0 {
		return nil
	}
	p, err := cdnpurge.New(cdnpurge.Options{URLs: urls})
	if err != nil {
		log.Fatalf("--purge-url: %v", err)
	}
	log.Printf("cdn purges go to %s", strings.Join(urls, ", "))
	return p
}

// closePurger flushes queued purges on shutdown, for at most 5 seconds.
func closePurger(p *cdnpurge.Purger) {
	if p == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := p.Close(ctx); err != nil {
		log.Printf("cdn purge: flush on shutdown: %v", err)
	}
}

// operatorKeyHistory parses --operator-key-history flags,
// KID=PUB,FROM[,UNTIL] with PUB a base64url Ed25519 public key and the
// times in RFC 3339 (§C.4).
func operatorKeyHistory(flags []string) ([]core.OperatorKeyPeriod, error) {
	var out []core.OperatorKeyPeriod
	for _, f := range flags {
		kid, rest, ok := strings.Cut(f, "=")
		parts := strings.Split(rest, ",")
		if !ok || kid == "" || len(parts) < 2 || len(parts) > 3 {
			return nil, fmt.Errorf("%q: want KID=PUB,FROM[,UNTIL]", f)
		}
		ks, err := grant.ParseKeys(jsonv.FromGo([]any{map[string]any{"kid": kid, "alg": "ed25519", "pub": parts[0], "can": []any{"*"}}}))
		if err != nil {
			return nil, fmt.Errorf("%q: %v", f, err)
		}
		p := core.OperatorKeyPeriod{Kid: kid, Pub: ks[0].Pub}
		if p.From, err = time.Parse(time.RFC3339, parts[1]); err != nil {
			return nil, fmt.Errorf("%q: from: %v", f, err)
		}
		if len(parts) == 3 {
			if p.Until, err = time.Parse(time.RFC3339, parts[2]); err != nil {
				return nil, fmt.Errorf("%q: until: %v", f, err)
			}
		}
		out = append(out, p)
	}
	return out, nil
}

// remoteOriginURLIgnored is the warning of a start with --remote-origin-url.
const remoteOriginURLIgnored = "--remote-origin-url is ignored since v0.81: it said where an origin itself answers, for the start times of a source's epochs from before its e2e raise, which no remote branch reads any more (Addendum E Levels); remove it"

// remoteOptions builds the endpoints of remote bases from ORIGIN=VALUE
// flags. originURLs (--remote-origin-url) are checked as the others but
// ignored, with a warning: nothing reads them since v0.81.
func remoteOptions(bearers, urls, identities, originURLs []string) (core.RemoteOptions, []string, error) {
	eps := map[string]core.RemoteEndpoint{}
	for _, pair := range [][]string{bearers, urls, identities, originURLs} {
		for _, kv := range pair {
			o, v, ok := strings.Cut(kv, "=")
			if !ok || !core.ValidRemoteOrigin(o) || v == "" {
				return core.RemoteOptions{}, nil, fmt.Errorf("remote endpoint %q: want ORIGIN=VALUE with an https origin", kv)
			}
			eps[o] = core.RemoteEndpoint{}
		}
	}
	var warn []string
	if len(originURLs) > 0 {
		warn = append(warn, remoteOriginURLIgnored)
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
			return core.RemoteOptions{}, nil, fmt.Errorf("--remote-identity %s: %w", o, err)
		}
		ep := eps[o]
		ep.Identity = id
		eps[o] = ep
	}
	return core.RemoteOptions{Resolve: func(origin string) (core.RemoteEndpoint, error) {
		return eps[origin], nil
	}}, warn, nil
}

// handler routes /playground/ to the web UI and everything else to the API.
// The playground has its own ServeMux, but the API is not put behind one:
// http.ServeMux cleans paths and answers 301, where §3.6 requires the API's
// own 400 for non-canonical URLs, so only playground paths reach the mux.
// treeProxy, if not nil, serves server.TreeProxyPrefix (--tree-url);
// without it those paths are the playground's 404. indexProxy likewise
// serves server.IndexProxyPrefix (--index-url).
func handler(api http.Handler, withPlayground bool, treeProxy, indexProxy http.Handler, pgOpt ...playground.Options) http.Handler {
	if !withPlayground {
		return api
	}
	mux := http.NewServeMux()
	var po playground.Options
	if len(pgOpt) > 0 {
		po = pgOpt[0]
	}
	mux.Handle(playground.Prefix, playground.HandlerWith(api, po))
	if treeProxy != nil {
		mux.Handle(server.TreeProxyPrefix, treeProxy)
	}
	if indexProxy != nil {
		mux.Handle(server.IndexProxyPrefix, indexProxy)
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

// grantCmd is patchlog grant mint|narrow|seal.
type grantCmd struct {
	Mint   *grantMintCmd   `arg:"subcommand:mint" help:"mint a grant signed with a key"`
	Narrow *grantNarrowCmd `arg:"subcommand:narrow" help:"narrow a grant with another block"`
	Seal   *grantSealCmd   `arg:"subcommand:seal" help:"seal a grant, so nobody can narrow it further"`
}

type grantMintCmd struct {
	Key   string `arg:"--key,required" placeholder:"SEED" help:"signing key seed (base64url)"`
	Block string `arg:"--block,required" placeholder:"JSON" help:"block JSON, e.g. {\"kid\":…,\"sub\":…,\"ns\":[…],\"can\":[…],\"exp\":…}"`
	Seal  bool   `arg:"--seal" help:"seal the result, so nobody can narrow it further (§C.8)"`
}

type grantNarrowCmd struct {
	Grant string `arg:"--grant,required" placeholder:"TOKEN" help:"grant to narrow (a Biscuit token)"`
	Block string `arg:"--block,required" placeholder:"JSON" help:"block JSON, e.g. {\"can\":[\"read\"],…}"`
	Seal  bool   `arg:"--seal" help:"seal the result, so nobody can narrow it further (§C.8)"`
}

type grantSealCmd struct {
	Grant string `arg:"--grant,required" placeholder:"TOKEN" help:"grant to seal (a Biscuit token)"`
}

func (a *grantMintCmd) run(string) {
	priv, err := grant.ParsePrivateKey(a.Key)
	if err != nil {
		log.Fatal(err)
	}
	g, err := grant.Mint(blockArg(a.Block), priv)
	if err != nil {
		log.Fatal(err)
	}
	printGrant(g, a.Seal)
}

func (a *grantNarrowCmd) run(string) {
	g, err := grant.Decode(a.Grant, 0)
	if err != nil {
		log.Fatal(err)
	}
	if g, err = g.Narrow(blockArg(a.Block)); err != nil {
		log.Fatal(err)
	}
	printGrant(g, a.Seal)
}

func (a *grantSealCmd) run(string) {
	g, err := grant.Decode(a.Grant, 0)
	if err != nil {
		log.Fatal(err)
	}
	printGrant(g, true)
}

// blockArg parses --block, a JSON object.
func blockArg(s string) map[string]any {
	b, err := jsonv.Parse([]byte(s))
	m, ok := b.(map[string]any)
	if err != nil || !ok {
		log.Fatalf("--block must be a JSON object: %v", err)
	}
	return m
}

// printGrant prints g, sealed first if seal.
func printGrant(g *grant.Grant, seal bool) {
	if seal {
		var err error
		if g, err = g.Seal(); err != nil {
			log.Fatal(err)
		}
	}
	fmt.Println(g.Encode())
}

// exportCmd, importCmd and the bundle commands are the Addendum G.4
// tools, whose flags and logic are in internal/bundle.
type (
	exportCmd       struct{ bundle.ExportCmd }
	importCmd       struct{ bundle.ImportCmd }
	bundleVerifyCmd struct{ bundle.VerifyCmd }
	bundleKeygenCmd struct{ bundle.KeygenCmd }
)

type bundleCmd struct {
	Verify *bundleVerifyCmd `arg:"subcommand:verify" help:"verify a bundle's chains and signatures"`
	Keygen *bundleKeygenCmd `arg:"subcommand:keygen" help:"write a bundle key (prints the public key, for --recipient and a grant's enc)"`
}

func (a *exportCmd) run(string)       { runBundle(a.Run) }
func (a *importCmd) run(string)       { runBundle(a.Run) }
func (a *bundleVerifyCmd) run(string) { runBundle(a.Run) }
func (a *bundleKeygenCmd) run(string) { runBundle(a.Run) }

// runBundle runs a bundle command, interruptible by SIGINT, and exits 1
// if it fails.
func runBundle(run func(context.Context, io.Writer, io.Writer) error) {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	err := run(ctx, os.Stdout, os.Stderr)
	stop()
	if err != nil {
		toolFatal(err)
	}
}
