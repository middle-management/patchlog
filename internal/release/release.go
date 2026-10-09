// Package release reads and writes release documents (§F.9): ordinary
// resources that list the branches of a release spanning several
// namespaces.
//
//	// /r/releases/release-7
//	{ "name": "release-7",
//	  "at": "1c…",                                   // optional: combined checkpoint the branches started from (§B.5)
//	  "branches": { "matches":    { "ns": "matches-r7",    "at": "1k…" },
//	                "cat-season": { "ns": "cat-season-r7", "at": "1m…" },
//	                "schemas":    { "ns": "schemas-r7",    "at": "1d…" } },
//	  "on": "/r/releases/release-6/rev/1x…",          // optional: the release this one builds on
//	  "owners": ["user:anna"] }
//
// The core never reads a release document. Tools that act on one (the
// merge service, previews, grant issuers, the janitor) check for
// themselves, under their own authority, what they are about to do: a
// release document only says which branches go together.
//
// Keys of branches are the namespaces paths name (the bases, or for a
// release built on another one, the namespaces of the earlier release's
// keys). Validation is structural: names are namespace names, ids are ids,
// no branch is listed twice and no branch is its own key. Unknown fields
// are kept (Extra), so a tool rewriting the document (a rebase) doesn't
// drop what others put there.
package release

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/seal"
)

// Branch is one listed branch: the branch namespace and the base revision
// it started at.
type Branch struct {
	NS string `json:"ns"`
	At string `json:"at,omitempty"`
}

// Doc is a release document.
type Doc struct {
	Name string `json:"name"`
	// At is the combined checkpoint the branches started from (§B.5),
	// optional, and dropped after a rebase. Each branch's own at is
	// authoritative (§F.9 Starting); tools never use this one in its place.
	At string `json:"at,omitempty"`
	// Branches maps the namespace paths name to its branch.
	Branches map[string]Branch `json:"branches"`
	// On is the release this one builds on: a pinned link
	// /r/{ns}/{name}/rev/{id}, or a live one.
	On     string   `json:"on,omitempty"`
	Owners []string `json:"owners,omitempty"`
	// Extra holds the fields this package doesn't know, kept as they are.
	Extra map[string]any `json:"-"`
}

var (
	nameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)
	linkRe = regexp.MustCompile(`^/r/([a-z0-9][a-z0-9_-]{0,63})/([a-z0-9][a-z0-9._-]{0,127})(/rev/(1[a-z2-7]{32}))?$`)
)

// known are the fields Doc models.
var known = map[string]bool{"name": true, "at": true, "branches": true, "on": true, "owners": true}

// Parse reads a release document from its JSON value (as client.Doc.Value
// holds it) and validates it.
func Parse(v any) (*Doc, error) {
	m, ok := v.(map[string]any)
	if !ok {
		return nil, errors.New("release: the document is not an object")
	}
	d := &Doc{Branches: map[string]Branch{}, Extra: map[string]any{}}
	var errs []string
	str := func(k string) string {
		x, present := m[k]
		if !present {
			return ""
		}
		s, ok := x.(string)
		if !ok {
			errs = append(errs, k+" must be a string")
		}
		return s
	}
	d.Name, d.At, d.On = str("name"), str("at"), str("on")
	if bs, present := m["branches"]; present {
		bm, ok := bs.(map[string]any)
		if !ok {
			errs = append(errs, "branches must be an object")
		}
		for k, x := range bm {
			o, ok := x.(map[string]any)
			if !ok {
				errs = append(errs, "branches."+k+" must be an object")
				continue
			}
			b := Branch{}
			b.NS, _ = o["ns"].(string)
			b.At, _ = o["at"].(string)
			if _, ok := o["ns"].(string); !ok {
				errs = append(errs, "branches."+k+".ns must be a string")
			}
			if at, present := o["at"]; present {
				if _, ok := at.(string); !ok {
					errs = append(errs, "branches."+k+".at must be a string")
				}
			}
			d.Branches[k] = b
		}
	}
	if os, present := m["owners"]; present {
		arr, ok := os.([]any)
		if !ok {
			errs = append(errs, "owners must be an array of strings")
		}
		for _, x := range arr {
			s, ok := x.(string)
			if !ok {
				errs = append(errs, "owners must be an array of strings")
				break
			}
			d.Owners = append(d.Owners, s)
		}
	}
	for k, x := range m {
		if !known[k] {
			d.Extra[k] = x
		}
	}
	if len(errs) > 0 {
		sort.Strings(errs)
		return nil, fmt.Errorf("release: %s", strings.Join(errs, "; "))
	}
	if err := d.Validate(); err != nil {
		return nil, err
	}
	return d, nil
}

// Validate checks the document's structure.
func (d *Doc) Validate() error {
	var errs []string
	if !nameRe.MatchString(d.Name) {
		errs = append(errs, fmt.Sprintf("name %q is not a valid name", d.Name))
	}
	if d.At != "" && !validID(d.At) {
		errs = append(errs, "at is not an id")
	}
	if len(d.Branches) == 0 {
		errs = append(errs, "branches must list at least one branch")
	}
	seen := map[string]string{}
	for _, k := range d.Keys() {
		b := d.Branches[k]
		switch {
		case !client.ValidNSName(k):
			errs = append(errs, fmt.Sprintf("branches key %q is not a namespace name", k))
		case !client.ValidNSName(b.NS):
			errs = append(errs, fmt.Sprintf("branches.%s.ns %q is not a namespace name", k, b.NS))
		case b.NS == k:
			errs = append(errs, fmt.Sprintf("branches.%s.ns names the namespace itself, not a branch of it", k))
		case seen[b.NS] != "":
			errs = append(errs, fmt.Sprintf("branch %s is listed for both %s and %s", b.NS, seen[b.NS], k))
		}
		seen[b.NS] = k
		if b.At != "" && !validID(b.At) {
			errs = append(errs, fmt.Sprintf("branches.%s.at is not an id", k))
		}
	}
	if d.On != "" && !linkRe.MatchString(d.On) {
		errs = append(errs, "on must be a link /r/{ns}/{name}[/rev/{id}]")
	}
	for _, o := range d.Owners {
		if o == "" {
			errs = append(errs, "owners must not contain empty strings")
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("release: %s", strings.Join(errs, "; "))
	}
	return nil
}

func validID(s string) bool {
	_, err := ids.Parse(s)
	return err == nil
}

// Keys returns the branch keys (the namespaces paths name), sorted.
func (d *Doc) Keys() []string {
	out := make([]string, 0, len(d.Branches))
	for k := range d.Branches {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// BranchNames returns the listed branch namespaces, sorted by key.
func (d *Doc) BranchNames() []string {
	var out []string
	for _, k := range d.Keys() {
		out = append(out, d.Branches[k].NS)
	}
	return out
}

// KeyOf returns the key a branch namespace is listed under, or "".
func (d *Doc) KeyOf(branch string) string {
	for k, b := range d.Branches {
		if b.NS == branch {
			return k
		}
	}
	return ""
}

// Aliases maps each key to its branch: what a release preview follows in
// place of the key (§B.5).
func (d *Doc) Aliases() map[string]string {
	out := map[string]string{}
	for k, b := range d.Branches {
		out[k] = b.NS
	}
	return out
}

// Value renders the document as a JSON value, with Extra kept.
func (d *Doc) Value() map[string]any {
	m := map[string]any{}
	for k, v := range d.Extra {
		m[k] = v
	}
	m["name"] = d.Name
	if d.At != "" {
		m["at"] = d.At
	}
	bs := map[string]any{}
	for k, b := range d.Branches {
		o := map[string]any{"ns": b.NS}
		if b.At != "" {
			o["at"] = b.At
		}
		bs[k] = o
	}
	m["branches"] = bs
	if d.On != "" {
		m["on"] = d.On
	}
	if len(d.Owners) > 0 {
		os := make([]any, len(d.Owners))
		for i, o := range d.Owners {
			os[i] = o
		}
		m["owners"] = os
	}
	return m
}

// MarshalJSON renders Value.
func (d *Doc) MarshalJSON() ([]byte, error) { return json.Marshal(d.Value()) }

// Ref is where a release document lives: /r/{NS}/{Name}, optionally a
// revision.
type Ref struct {
	NS, Name string
	Rev      string // "" = the head
}

// ParseRef parses /r/{ns}/{name} or /r/{ns}/{name}/rev/{id}; a full URL
// is accepted too, and only its path is used.
func ParseRef(s string) (Ref, error) {
	if i := strings.Index(s, "://"); i >= 0 {
		rest := s[i+3:]
		j := strings.IndexByte(rest, '/')
		if j < 0 {
			return Ref{}, fmt.Errorf("release: %q has no path", s)
		}
		s = rest[j:]
	}
	m := linkRe.FindStringSubmatch(s)
	if m == nil {
		return Ref{}, fmt.Errorf("release: %q is not /r/{ns}/{name}[/rev/{id}]", s)
	}
	return Ref{NS: m[1], Name: m[2], Rev: m[4]}, nil
}

// String is the link: live, or pinned with Rev.
func (r Ref) String() string {
	s := "/r/" + r.NS + "/" + r.Name
	if r.Rev != "" {
		s += "/rev/" + r.Rev
	}
	return s
}

// Live is the live link /r/{ns}/{name}.
func (r Ref) Live() string { return "/r/" + r.NS + "/" + r.Name }

// Loaded is a release document read through the client, with the
// revision it was read at.
type Loaded struct {
	Ref Ref // Rev is the revision read
	Doc *Doc
	// Head is the resource's head when it was read (Ref.Rev may be an
	// older revision if one was asked for).
	Head string
}

// Load reads a release document: the head of a live link, or exactly the
// revision of a pinned one.
func Load(ctx context.Context, c *client.Client, link string) (*Loaded, error) {
	ref, err := ParseRef(link)
	if err != nil {
		return nil, err
	}
	h, err := c.Head(ctx, ref.NS, ref.Name)
	if err != nil {
		return nil, fmt.Errorf("release: %s: %w", ref.Live(), err)
	}
	if h.State != client.Live && ref.Rev == "" {
		return nil, fmt.Errorf("release: %s is %s", ref.Live(), h.State)
	}
	rev := ref.Rev
	if rev == "" {
		rev = h.ID
	}
	d, err := c.Doc(ctx, ref.NS, ref.Name, rev)
	if err != nil {
		return nil, fmt.Errorf("release: %s/rev/%s: %w", ref.Live(), rev, err)
	}
	doc, err := Parse(d.Value)
	if err != nil {
		return nil, fmt.Errorf("%w (in %s/rev/%s)", err, ref.Live(), rev)
	}
	ref.Rev = rev
	return &Loaded{Ref: ref, Doc: doc, Head: h.ID}, nil
}

// Write stores doc as a new revision of the release document at ref,
// replacing its whole content in one patch set with If-Match: parent (or
// creating it if parent is ""). The patch set adds a fresh $nonce where
// one is needed (needsNonce). It returns the new revision.
func Write(ctx context.Context, c *client.Client, ref Ref, parent string, doc *Doc) (string, error) {
	if err := doc.Validate(); err != nil {
		return "", err
	}
	val := jsonv.FromGo(doc.Value())
	patches := []any{map[string]any{"op": "replace", "path": "", "value": val}}
	if parent == "" {
		patches = client.GenesisPatches(val)
	}
	if needsNonce(ctx, c, ref.NS, doc) {
		patches = append(patches, map[string]any{"op": "add", "path": seal.NoncePath, "value": seal.NewNonce()})
	}
	var res *client.WriteResult
	var err error
	if parent == "" {
		res, err = c.Create(ctx, ref.NS, ref.Name, patches)
	} else {
		res, err = c.Append(ctx, ref.NS, ref.Name, parent, patches)
	}
	if err != nil {
		return "", fmt.Errorf("release: writing %s: %w", ref.Live(), err)
	}
	return res.ID, nil
}

// needsNonce reports whether a write of doc to ns adds a fresh $nonce
// (§C.7): doc was read with one (kept in Extra), which the fresh one
// replaces, since the old is never written back as is, or ns requires
// nonces, or c can't read its namespace document (client.NeedsNonce).
func needsNonce(ctx context.Context, c *client.Client, ns string, doc *Doc) bool {
	if _, had := doc.Extra["$nonce"]; had {
		return true
	}
	return c.NeedsNonce(ctx, ns)
}
