package main

// Flag groups several commands share, embedded in their argument structs
// (go-arg flattens embedded structs), and the value types of flags that
// take a size.

import (
	"fmt"
	"strings"
	"time"

	"github.com/middle-management/patchlog/internal/core"
)

// byteSize is a size flag such as "64 MiB" (core.ParseSize). As a pointer
// field, nil means the flag wasn't given.
type byteSize int

func (s *byteSize) UnmarshalText(b []byte) error {
	n, err := core.ParseSize(string(b))
	if err != nil {
		return err
	}
	*s = byteSize(n)
	return nil
}

func (s byteSize) String() string { return fmt.Sprint(int(s)) }

// sizeOr is *s, or def when the flag wasn't given.
func sizeOr(s *byteSize, def int) int {
	if s == nil {
		return def
	}
	return int(*s)
}

// splitList splits comma-separated values, repeated flags or not, dropping
// empty entries.
func splitList(vals ...string) []string {
	var out []string
	for _, v := range vals {
		for _, s := range strings.Split(v, ",") {
			if s = strings.TrimSpace(s); s != "" {
				out = append(out, s)
			}
		}
	}
	return out
}

// shutdownArgs are the --shutdown-* flags of serve, index, tree and dav.
type shutdownArgs struct {
	ShutdownTimeout time.Duration `arg:"--shutdown-timeout" default:"30s" placeholder:"DURATION" help:"on SIGTERM/SIGINT, how long in-flight requests are waited for before they are cancelled (long-polls and event streams end at once)"`
	ShutdownDelay   time.Duration `arg:"--shutdown-delay" default:"0s" placeholder:"DURATION" help:"on SIGTERM/SIGINT, how long to keep serving with /_health answering 503 before stopping, so load balancers take the instance out of rotation first"`
}

// corsArgs are the --cors-* flags every server takes.
type corsArgs struct {
	CORSOrigin            []string      `arg:"--cors-origin,separate,env:PATCHLOG_CORS_ORIGINS" placeholder:"ORIGIN" help:"origin browser pages may call from, e.g. https://app.example, or * for any (repeatable or comma-separated; unset: no CORS)"`
	CORSCredentialsOrigin []string      `arg:"--cors-credentials-origin,separate" placeholder:"ORIGIN" help:"origin whose pages may call with credentials (cookies), such as edge-grant cookies (§C.5): named in Access-Control-Allow-Origin with Access-Control-Allow-Credentials: true, even when --cors-origin is * (repeatable or comma-separated; never *)"`
	CORSCredentials       bool          `arg:"--cors-credentials" help:"send Access-Control-Allow-Credentials, for pages that send cookies (needs explicit --cors-origin values; grants travel in Authorization and don't need it)"`
	CORSMaxAge            time.Duration `arg:"--cors-max-age" default:"10m" placeholder:"DURATION" help:"how long browsers may cache a CORS preflight"`
}

// purgeArgs is --purge-url, of serve, index and tree.
type purgeArgs struct {
	PurgeURL []string `arg:"--purge-url,separate" placeholder:"URL" help:"CDN URL that cache-tag purges are sent to, as PURGE with X-Purge-Tags (repeatable; e.g. http://cdn:8080/ for deploy/varnish). Unset: purges are only logged"`
}

// edgeArgs are the verifying-edge flags of serve, index and tree (§9).
type edgeArgs struct {
	EdgeSecret       string `arg:"--edge-secret" placeholder:"FILE" help:"file holding the secret a grant-verifying edge sends in --edge-header, with the prefix of the edge grant it checked in --edge-prefix-header (§9), each as one header line without a comma (so the secret has none): private reads it verified, with no Authorization, get edge lifetimes; every other private response is CDN-Cache-Control: no-store, and is served all the same. Unset: no verifying edge, and private responses are CDN-Cache-Control: no-store"`
	EdgeHeader       string `arg:"--edge-header" default:"X-Edge-Verified" placeholder:"NAME" help:"request header carrying --edge-secret"`
	EdgePrefixHeader string `arg:"--edge-prefix-header" default:"X-Edge-Prefix" placeholder:"NAME" help:"request header carrying the prefix of the edge grant the edge verified (§9)"`
}

// encKeyArgs name the X25519 private key of the index and tree services.
type encKeyArgs struct {
	EncKey     string `arg:"--enc-key" placeholder:"B64URL" help:"the service's X25519 private key (base64url), for sealed and e2e namespaces (Addendum E)"`
	EncKeyFile string `arg:"--enc-key-file" placeholder:"PATH" help:"file holding --enc-key"`
}

// keyringArgs name the admin keys whose e2e keyring entries a tool or
// service opens, and those it trusts to distribute keys it seals under
// (§E.3.2); and the encryption levels it expects of namespaces (§7.1).
type keyringArgs struct {
	KeyringSender []string `arg:"--keyring-sender,separate" placeholder:"PUB.JWK" help:"file with a keyring admin's X25519 public key (a JWK {kty, crv, x}, or base64url x): e2e keyring entries it wrapped are opened (§E.3.2), and, unless --trusted-sender is given, sealed under; repeatable"`
	TrustedSender []string `arg:"--trusted-sender,separate" placeholder:"PUB.JWK" help:"as --keyring-sender, and trusted to distribute keys: once any is given, this tool seals (writes, prunes, re-encrypted merges, derived views) only under keys whose keyring entry is from one of these or from its own identity, while reads still open keys from every --keyring-sender (§E.3.2); never under a key without a sender; repeatable"`
	ExpectLevel   []string `arg:"--expect-level,separate" placeholder:"NS=LEVEL" help:"the encryption level namespace ns is known to have (at-rest, sealed or e2e). The tool holds it from its first request, so a server or cache that claims a lower one is refused, and with sealed or e2e a document served in the clear is too; a branch of ns is held at least at that level, so the tool reads a namespace's document once before trusting a first document in the clear from it (§7.1, Levels); without it a level is only held once learnt, in this process; repeatable"`
}

// toolArgs are the connection flags of the client tools (merge, rebase,
// janitor, e2e).
type toolArgs struct {
	API         string `arg:"--api,env:PATCHLOG_API" default:"http://localhost:8080" placeholder:"URL" help:"deployment base URL"`
	Bearer      string `arg:"--bearer,env:PATCHLOG_BEARER" placeholder:"GRANT" help:"grant sent as Authorization: Bearer"`
	BearerFile  string `arg:"--bearer-file,env:PATCHLOG_BEARER_FILE" placeholder:"FILE" help:"file holding --bearer, so the grant is not in the process arguments or the shell history (exclusive with --bearer; a --bearer-file beats $PATCHLOG_BEARER, a --bearer beats $PATCHLOG_BEARER_FILE)"`
	Author      string `arg:"--author,env:PATCHLOG_AUTHOR" placeholder:"NAME" help:"X-Author (development servers only)"`
	JSON        bool   `arg:"--json" help:"print JSON"`
	SignKey     string `arg:"--sign-key,env:PATCHLOG_SIGN_KEY" placeholder:"KID:SEED" help:"kid:seed (the seed 32 bytes in base64url): sign every step this tool writes with this key (§C.3.1). The kid must be listed in the signers of the grant (--bearer) the writes are sent under. Original signatures are never carried over"`
	SignKeyFile string `arg:"--sign-key-file,env:PATCHLOG_SIGN_KEY_FILE" placeholder:"FILE" help:"file holding --sign-key (exclusive with it, as --bearer-file is with --bearer)"`
	Dev         bool   `arg:"--dev" help:"ignored, kept for scripts: whether the deployment runs with authentication disabled is read from GET / (§1, §7)"`
	keyringArgs
}

// identityArgs is --identity, of merge and rebase.
type identityArgs struct {
	Identity []string `arg:"--identity,separate" placeholder:"KEY.JWK" help:"file with an X25519 private key (a private JWK {kty, crv, x, d}, or base64url d) for e2e namespaces (Addendum E.3): the key the keyrings (and --bearer's enc) name, to read the branch and re-encrypt for the target (§F.8); repeatable when they name different keys"`
}
