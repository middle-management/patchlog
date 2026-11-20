package main

// patchlog grant inspect | check | show: reading grants (§C). inspect
// decodes a token offline; check verifies it against a namespace's keys and
// revocations as of the namespace's head, locally, as the index service
// does (internal/grantcheck); show prints the grant recorded in a
// namespace.

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/grant"
	"github.com/middle-management/patchlog/internal/grantcheck"
)

var b64url = base64.RawURLEncoding

// tokenArg is TOKEN, or - for the token on stdin (trimmed).
func tokenArg(s string, stdin io.Reader) (string, error) {
	if s == "-" {
		b, err := io.ReadAll(stdin)
		if err != nil {
			return "", err
		}
		s = string(b)
	}
	s = strings.TrimSpace(s)
	if s == "" {
		return "", errors.New("the grant is empty")
	}
	return s, nil
}

// relTime says when t is, relative to now: "expired 2h ago" or "in 3h".
func relTime(t, now time.Time) string {
	d := t.Sub(now)
	if d <= 0 {
		return "expired " + shortDur(-d) + " ago"
	}
	return "in " + shortDur(d)
}

func shortDur(d time.Duration) string {
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d/time.Second))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d/time.Minute))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh", int(d/time.Hour))
	}
	return fmt.Sprintf("%dd", int(d/(24*time.Hour)))
}

// grantInspectCmd is patchlog grant inspect TOKEN|-.
type grantInspectCmd struct {
	JSON  bool   `arg:"--json" help:"print JSON"`
	Token string `arg:"positional,required" placeholder:"TOKEN|-" help:"the grant (a Biscuit token), or - to read it from stdin"`
}

func (a *grantInspectCmd) run(string) {
	if err := a.exec(os.Stdin, os.Stdout, time.Now()); err != nil {
		toolFatal(err)
	}
}

// blockView is one block of an inspected grant, as printed.
func blockView(b grant.Block, now time.Time) map[string]any {
	m := map[string]any{}
	if b.Kid != "" {
		m["kid"] = b.Kid
	}
	if b.Sub != "" {
		m["sub"] = b.Sub
	}
	if b.Via != "" {
		m["via"] = b.Via
	}
	if b.HasNS {
		m["ns"] = nonNil(b.NS)
	}
	if b.HasCan {
		m["can"] = nonNil(b.Can)
	}
	if b.HasRoles {
		m["roles"] = nonNil(b.Roles)
	}
	if len(b.Groups) > 0 {
		m["groups"] = b.Groups
	}
	if len(b.Attrs) > 0 {
		m["attrs"] = b.Attrs
	}
	if b.Nbf != nil {
		m["nbf"] = b.Nbf.UTC().Format(time.RFC3339)
	}
	if b.Exp != nil {
		m["exp"] = b.Exp.UTC().Format(time.RFC3339)
		m["expired"] = !b.Exp.After(now)
		m["expires"] = relTime(*b.Exp, now)
	}
	if len(b.Rules) > 0 {
		m["rules"] = b.Rules
	}
	if len(b.Signers) > 0 {
		var ss []any
		for _, s := range b.Signers {
			ss = append(ss, map[string]any{"kid": s.Kid, "alg": s.Alg, "pub": b64url.EncodeToString(s.Pub)})
		}
		m["signers"] = ss
	}
	if b.Enc != nil {
		m["enc"] = b64url.EncodeToString(b.Enc.Bytes())
	}
	return m
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func (a *grantInspectCmd) exec(stdin io.Reader, out io.Writer, now time.Time) error {
	tok, err := tokenArg(a.Token, stdin)
	if err != nil {
		return err
	}
	g, err := grant.Decode(tok, 0)
	if err != nil {
		return fmt.Errorf("not a grant: %w", err)
	}
	blocks := make([]any, len(g.Blocks))
	for i, b := range g.Blocks {
		blocks[i] = blockView(b, now)
	}
	if a.JSON {
		return writeJSON(out, map[string]any{"id": g.ID().String(), "sealed": g.Sealed(), "verified": false, "blocks": blocks})
	}
	fmt.Fprintf(out, "grant %s: %d block(s), sealed: %s\n", g.ID(), len(g.Blocks), yesNo(g.Sealed()))
	fmt.Fprintln(out, "(read offline: signatures are not verified; patchlog grant check NS verifies against a namespace)")
	for i := range g.Blocks {
		role := "narrowing"
		if i == 0 {
			role = "root"
		}
		fmt.Fprintf(out, "\nblock %d (%s)\n", i, role)
		writeBlock(out, blocks[i].(map[string]any))
	}
	return nil
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

// blockOrder is the order a block's fields are printed in.
var blockOrder = []string{"kid", "sub", "via", "ns", "can", "roles", "groups", "attrs", "nbf", "exp", "rules", "signers", "enc"}

func writeBlock(out io.Writer, m map[string]any) {
	for _, k := range blockOrder {
		v, ok := m[k]
		if !ok {
			continue
		}
		switch k {
		case "exp":
			fmt.Fprintf(out, "  %-8s %v (%v)\n", k, v, m["expires"])
		case "signers":
			var parts []string
			for _, s := range v.([]any) {
				sm := s.(map[string]any)
				parts = append(parts, fmt.Sprintf("%v (%v)", sm["kid"], sm["alg"]))
			}
			fmt.Fprintf(out, "  %-8s %s\n", k, strings.Join(parts, ", "))
		case "ns", "can", "roles", "groups":
			if s := v.([]string); len(s) == 0 {
				fmt.Fprintf(out, "  %-8s (none)\n", k)
			} else {
				fmt.Fprintf(out, "  %-8s %s\n", k, strings.Join(s, ", "))
			}
		case "rules":
			fmt.Fprintf(out, "  %-8s %d rule(s)\n", k, len(v.([]any)))
		case "enc":
			fmt.Fprintf(out, "  %-8s X25519 %v\n", k, v)
		default:
			fmt.Fprintf(out, "  %-8s %v\n", k, v)
		}
	}
}

// grantCheckCmd is patchlog grant check NS TOKEN|-.
type grantCheckCmd struct {
	toolArgs
	NS    string `arg:"positional,required" placeholder:"NS"`
	Token string `arg:"positional,required" placeholder:"TOKEN|-" help:"the grant (a Biscuit token), or - to read it from stdin"`
}

func (a *grantCheckCmd) run(string) { runClient(a) }

// refusedError is a grant the namespace refuses.
type refusedError struct {
	status int
	msg    string
}

func (e *refusedError) Error() string { return "refused: " + e.msg }

func (a *grantCheckCmd) exec(ctx context.Context, out, errw io.Writer) error {
	tok, err := tokenArg(a.Token, os.Stdin)
	if err != nil {
		return err
	}
	return a.check(ctx, tok, out)
}

// check verifies tok for a.NS. The namespace's documents are read with
// --bearer's grant, or, without one, with tok itself.
func (a *grantCheckCmd) check(ctx context.Context, tok string, out io.Writer) error {
	tf := a.toolArgs
	if tf.Bearer == "" {
		tf.Bearer = tok
	}
	ch := grantcheck.New(tf.client(), grantcheck.WithTTL(time.Hour)) // one snapshot: Verify and Config below read the same head
	v, err := ch.Verify(ctx, a.NS, tok)
	var ae *grant.AuthError
	if errors.As(err, &ae) {
		if a.JSON {
			if err := writeJSON(out, map[string]any{"allowed": false, "ns": a.NS, "status": ae.Status, "reason": ae.Msg}); err != nil {
				return err
			}
		}
		return &refusedError{ae.Status, ae.Msg}
	}
	if err != nil {
		return err
	}
	cfg, err := ch.Config(ctx, a.NS)
	if err != nil {
		return err
	}
	var can []string
	for verb, ok := range v.Can {
		if ok {
			can = append(can, verb)
		}
	}
	sort.Strings(can)
	reads := ""
	if v.Can["read"] {
		reads = "per resource"
		if ch.ReadsUnrestricted(v) {
			reads = "every resource"
		}
	}
	var exp *time.Time
	for _, b := range v.Grant.Blocks {
		if b.Exp != nil && (exp == nil || b.Exp.Before(*exp)) {
			exp = b.Exp
		}
	}
	if a.JSON {
		m := map[string]any{"allowed": true, "ns": a.NS, "head": cfg.Head, "sub": v.Principal.ID, "grant": v.Principal.Grant,
			"can": nonNil(can), "key": v.Key.Kid, "operator": v.Operator}
		if v.EffectiveRoles != nil {
			m["roles"] = v.EffectiveRoles
		}
		if len(v.Principal.Via) > 0 {
			m["via"] = v.Principal.Via
		}
		if reads != "" {
			m["reads"] = reads
		}
		if exp != nil {
			m["exp"] = exp.UTC().Format(time.RFC3339)
		}
		return writeJSON(out, m)
	}
	fmt.Fprintf(out, "allowed in %s (as of head %s)\n", a.NS, cfg.Head)
	fmt.Fprintf(out, "  sub      %s\n", v.Principal.ID)
	if v.Key != nil {
		fmt.Fprintf(out, "  key      %s\n", v.Key.Kid)
	}
	fmt.Fprintf(out, "  can      %s\n", strings.Join(can, ", "))
	if reads != "" {
		fmt.Fprintf(out, "  reads    %s\n", reads)
	}
	if v.EffectiveRoles != nil {
		fmt.Fprintf(out, "  roles    %s\n", strings.Join(v.EffectiveRoles, ", "))
	}
	if len(v.Principal.Via) > 0 {
		fmt.Fprintf(out, "  via      %s\n", strings.Join(v.Principal.Via, ", "))
	}
	if exp != nil {
		fmt.Fprintf(out, "  exp      %s (%s)\n", exp.UTC().Format(time.RFC3339), relTime(*exp, time.Now()))
	}
	return nil
}

// grantShowCmd is patchlog grant show NS GID.
type grantShowCmd struct {
	toolArgs
	NS  string `arg:"positional,required" placeholder:"NS"`
	GID string `arg:"positional,required" placeholder:"GID" help:"the grant's id, as in a gesture or an entry's grant (§C.3.1)"`
}

func (a *grantShowCmd) run(string) { runClient(a) }

func (a *grantShowCmd) exec(ctx context.Context, out, errw io.Writer) error {
	g, err := a.client().Grant(ctx, a.NS, a.GID)
	if err != nil {
		if client.IsNotFound(err) {
			return fmt.Errorf("%s has no grant %s", a.NS, a.GID)
		}
		return err
	}
	if a.JSON {
		return writeJSON(out, map[string]any{"id": g.ID, "root": g.Root, "stored": g.Stored})
	}
	fmt.Fprintf(out, "grant %s (recorded in %s, %d stored block(s))\n", g.ID, a.NS, len(g.Stored))
	return writeJSON(out, g.Root)
}
