package bundle_test

import (
	"bytes"
	"crypto/ecdh"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/bundle"
	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/grant"
	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/sig"
)

// Spec v0.82, bundles (§G.4.1): a grant line whose grant isn't the id of
// its root, or whose stored block's grant_block isn't canonical(root),
// rejects the whole bundle (BT-2, scenario 47); so does a member §G.4.1
// doesn't define (BT-1, scenario 48).

// v82Authored is a bundle with authors of matches/derby: a grant line,
// then one revision that names it, signed by the grant's signer. It
// returns the grant and a second one, of another subject, to swap in.
func v82Authored(t *testing.T) (b []byte, g, other *grant.Grant, key bundle.KeyEntry) {
	t.Helper()
	nsKey := clienttest.NewKey("ns-key")
	bot := signerKey(t, "bot-1", 1)
	g = mint(t, nsKey.Priv, nsKey.Kid, "alice", bot)
	other = mint(t, nsKey.Priv, nsKey.Kid, "mallory", bot)
	key = keyEntryOf(nsKey)
	sign := func(parent *ids.ID, body []byte) string {
		return bot.Sign(sig.Digest(srcOrigin, "matches", "derby", parent, body))
	}
	b = writeHistory(t, "matches", "derby", func(w *bundle.Writer) ids.ID {
		noErr(t, w.Line(grantLine(t, "matches", g, key)))
		l, id := history(t, "matches", "derby", nil, client.GenesisPatches(map[string]any{"n": 1}), sign, g.ID().String())
		noErr(t, w.Line(l))
		return id
	})
	return b, g, other, key
}

// v82EditLine rewrites line n (1 = the header) of bundle b, canonical
// again, so that only what edit changed can reject it.
func v82EditLine(t *testing.T, b []byte, n int, edit func(m map[string]any)) []byte {
	t.Helper()
	ls := lines(b)
	out := make([][]byte, len(ls))
	copy(out, ls)
	m := jsonv.MustParse(ls[n-1]).(map[string]any)
	edit(m)
	out[n-1] = jsonv.Canonical(m)
	return join(out)
}

// v82Rejected checks that err rejects the bundle at line, for want.
func v82Rejected(t *testing.T, what string, err error, line int, want string) {
	t.Helper()
	var be *bundle.Error
	if err == nil || !errors.Is(err, bundle.ErrInvalid) || !errors.As(err, &be) {
		t.Fatalf("%s: %v, want an invalid-bundle error", what, err)
	}
	if be.Line != line || !strings.Contains(be.Msg, want) {
		t.Fatalf("%s: line %d, %q; want line %d and %q", what, be.Line, be.Msg, line, want)
	}
}

// v82Disagreeing are bundles whose grant line (line 2) disagrees with its
// root, each with the reason a reader gives. Their signatures are as
// valid as the edit leaves them: the rule needs none (§G.4.1).
func v82Disagreeing(t *testing.T) map[string]struct {
	b    []byte
	want string
} {
	t.Helper()
	good, g, other, _ := v82Authored(t)
	if _, err := bundle.Verify(bytes.NewReader(good)); err != nil {
		t.Fatalf("the control bundle: %v", err)
	}
	otherStored := storedBlocks(t, other)[0]
	return map[string]struct {
		b    []byte
		want string
	}{
		// grant names another grant's id, a well-formed one.
		"another id": {v82EditLine(t, good, 2, func(m map[string]any) { m["grant"] = other.ID().String() }), "not the id of its root"},
		// root changed after the fact: the id no longer follows from it.
		"root edited": {v82EditLine(t, good, 2, func(m map[string]any) { m["root"].(map[string]any)["sub"] = "mallory" }), "not the id of its root"},
		// The id follows from root, but the stored block is another
		// grant's: its grant_block isn't canonical(root).
		"another stored block": {v82EditLine(t, good, 2, func(m map[string]any) { m["stored"] = otherStored }), "grant_block is not canonical(root)"},
		// The same without key: nothing of the rule depends on it.
		"another stored block, no key": {v82EditLine(t, good, 2, func(m map[string]any) {
			m["stored"] = otherStored
			delete(m, "key")
		}), "grant_block is not canonical(root)"},
		// The form before v0.73, an array: its first element is the
		// authority block, and is checked.
		"another stored block, array form": {v82EditLine(t, good, 2, func(m map[string]any) {
			m["stored"] = []any{otherStored, storedBlocks(t, g)[0]}
		}), "grant_block is not canonical(root)"},
		// A stored block that doesn't decode has no grant_block.
		"stored undecodable": {v82EditLine(t, good, 2, func(m map[string]any) { m["stored"] = "AAAA" }), "no grant_block"},
	}
}

// BT-2 (§G.4.1, §C.3.1 Reading grants; FED-3): the Reader rejects the
// bundle at the grant line, with the rule that failed, through Verify and
// VerifyWith, plain and sealed; the Writer refuses to write such a line.
// The array form of stored still reads where its first element agrees.
func TestV082GrantLineDisagreesWithRoot(t *testing.T) {
	t.Parallel()
	id := identity(t)
	for name, c := range v82Disagreeing(t) {
		_, err := bundle.Verify(bytes.NewReader(c.b))
		v82Rejected(t, name+": Verify", err, 2, c.want)
		reported := 0
		_, err = bundle.VerifyWith(ctx, bytes.NewReader(c.b), bundle.VerifyOptions{OnSignature: func(bundle.SigResult) { reported++ }})
		v82Rejected(t, name+": VerifyWith", err, 2, c.want)
		if reported != 0 {
			t.Fatalf("%s: %d signatures reported of a bundle rejected at its grant line", name, reported)
		}
		// Sealed (§G.5.1.1): the decrypted bundle is checked as §G.4.1.
		var sealed bytes.Buffer
		sw := must(bundle.NewSealedWriter(&sealed, []*ecdh.PublicKey{id.PublicKey()}))
		must(sw.Write(c.b))
		noErr(t, sw.Close())
		r, _, err := bundle.Unseal(bytes.NewReader(sealed.Bytes()), id)
		if err == nil {
			_, err = bundle.Verify(r)
		}
		v82Rejected(t, name+": sealed", err, 2, c.want)
	}

	// The Writer shares the checker: it writes no such line.
	_, g, other, key := v82Authored(t)
	hdr := bundle.Header{Origin: srcOrigin, Created: "2026-10-04T12:00:00Z", Authors: true,
		At:   map[string]string{"matches": ids.Hash(nil, []byte("at")).String()},
		Docs: map[string]bundle.DocInfo{"matches/derby": {History: bundle.Full, Head: ids.Hash(nil, []byte("x")).String()}}}
	wrongID := grantLine(t, "matches", g, key)
	wrongID.GrantLine.ID = other.ID().String()
	wrongStored := grantLine(t, "matches", g, key)
	wrongStored.GrantLine.Stored = storedBlocks(t, other)[0]
	noKey := grantLine(t, "matches", g, bundle.KeyEntry{})
	noKey.GrantLine.Stored = storedBlocks(t, other)[0]
	for name, c := range map[string]struct {
		l    bundle.Line
		want string
	}{
		"wrong id":             {wrongID, "not the id of its root"},
		"wrong stored":         {wrongStored, "grant_block is not canonical(root)"},
		"wrong stored, no key": {noKey, "grant_block is not canonical(root)"},
	} {
		var out bytes.Buffer
		w := must(bundle.NewWriter(&out, hdr))
		v82Rejected(t, "Writer, "+name, w.Line(c.l), 2, c.want)
	}

	// Control: the array form whose first element is the authority block
	// reads, as before (stored.md: kept read-only).
	good, _, _, _ := v82Authored(t)
	arr := v82EditLine(t, good, 2, func(m map[string]any) { m["stored"] = []any{m["stored"]} })
	if _, err := bundle.Verify(bytes.NewReader(arr)); err != nil {
		t.Fatalf("stored as an array of the authority block: %v", err)
	}
}

// v82NothingWritten checks that a refused import left no namespace ns.
func v82NothingWritten(t *testing.T, d *deployment, what, ns string) {
	t.Helper()
	if _, err := d.c.NSHead(ctx, ns); !client.IsNotFound(err) {
		t.Fatalf("%s: the refused import created %s: %v", what, ns, err)
	}
}

// Scenario 47 (§G.4.1; BT-2): an import of a bundle with a disagreeing
// grant line is rejected whole at step 1, before anything is written,
// whatever the mode.
func TestV082ImportRejectsDisagreeingGrantLine(t *testing.T) {
	t.Parallel()
	dst := newDeployment(t, cmsOrigin)
	for name, c := range v82Disagreeing(t) {
		for _, mode := range []bundle.ImportMode{bundle.Atomic, bundle.Backfill} {
			_, err := bundle.Import(ctx, dst.c, bundle.BytesOpener(c.b), bundle.ImportOptions{Mode: mode, CreateNamespaces: true})
			v82Rejected(t, name+": import ("+string(mode)+")", err, 2, c.want)
			v82NothingWritten(t, dst, name, "matches")
		}
	}
	// Control: the bundle the edits started from imports.
	good, _, _, _ := v82Authored(t)
	importB(t, dst, good, bundle.ImportOptions{CreateNamespaces: true})
	if doc := dst.doc("matches", "derby"); doc["n"] != 1.0 {
		t.Fatalf("the control import: %v", doc)
	}
}

// Scenario 48 (§G.4.1, FED-3; BT-1): a bundle whose header, a history
// line or a grant line carries a member §G.4.1 doesn't define, or whose
// grant line's key does, is rejected whole at import step 1: nothing is
// written.
func TestV082ImportRejectsUndefinedMember(t *testing.T) {
	t.Parallel()
	good, _, _, _ := v82Authored(t)
	dst := newDeployment(t, cmsOrigin)
	for name, c := range map[string]struct {
		line int
		edit func(m map[string]any)
		want string
	}{
		"header":       {1, func(m map[string]any) { m["x-note"] = "hello" }, "x-note"},
		"grant line":   {2, func(m map[string]any) { m["x-note"] = "hello" }, "x-note"},
		"grant key":    {2, func(m map[string]any) { m["key"].(map[string]any)["x-note"] = "hello" }, "x-note"},
		"history line": {3, func(m map[string]any) { m["x-note"] = "hello" }, "x-note"},
	} {
		b := v82EditLine(t, good, c.line, c.edit)
		_, err := bundle.Verify(bytes.NewReader(b))
		v82Rejected(t, name+": Verify", err, c.line, c.want)
		_, err = bundle.Import(ctx, dst.c, bundle.BytesOpener(b), bundle.ImportOptions{Mode: bundle.Atomic, CreateNamespaces: true})
		v82Rejected(t, name+": import", err, c.line, c.want)
		v82NothingWritten(t, dst, name, "matches")
	}
}

// BT-2, the exporter: a source whose grant record's root isn't its stored
// block's grant_block gets no grant line (the Writer would refuse it and
// abort the export): the grant is left off the lines that would name it,
// as one that can't be fetched is (§G.4.1), with a note, and the bundle
// reads.
func TestV082ExportLeavesDisagreeingGrantOff(t *testing.T) {
	t.Parallel()
	nsKey := clienttest.NewKey("ns-key")
	bot := signerKey(t, "bot-a", 1)
	ga := mint(t, nsKey.Priv, nsKey.Kid, "alice", bot)
	gb := mint(t, nsKey.Priv, nsKey.Kid, "bob", bot)
	byAuthor := map[string]*grant.Grant{"alice": ga, "bob": gb}
	served := map[string]*grant.Grant{ga.ID().String(): ga, gb.ID().String(): gb}
	// bob's record is served with another root than its stored block has.
	grantsRE := regexp.MustCompile(`^/ns/[a-z0-9_-]+/grants/(1[a-z2-7]+)$`)
	inner := grantsHandler(served, func(a string) *grant.Grant { return byAuthor[a] }, nil)
	wrap := func(next http.Handler) http.Handler {
		h := inner(next)
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if m := grantsRE.FindStringSubmatch(r.URL.Path); m != nil && m[1] == gb.ID().String() {
				root := jsonv.MustParse(jsonv.Canonical(gb.Blocks[0].Raw)).(map[string]any)
				root["sub"] = "mallory"
				body, _ := json.Marshal(map[string]any{"id": gb.ID().String(), "root": root, "stored": splitStored(gb.Stored())})
				w.Header().Set("Content-Type", "application/json")
				w.Write(body)
				return
			}
			h.ServeHTTP(w, r)
		})
	}
	srv := clienttest.New(t, clienttest.Options{Wrap: wrap})
	as := func(author string) *client.Client { return srv.Client(t, client.WithAuthor(author)) }
	_, err := as("alice").CreateNamespace(ctx, "matches", map[string]any{"read": "public",
		"keys": []any{nsKey.Entry("create", "append", "delete", "read")}})
	noErr(t, err)
	r1 := must(as("alice").Create(ctx, "matches", "derby", client.GenesisPatches(map[string]any{"n": 1}))).ID
	r2 := must(as("bob").Append(ctx, "matches", "derby", r1, ops(op("replace", "/n", 2)))).ID

	var buf bytes.Buffer
	plan, sum, err := bundle.Export(ctx, as("alice"), &buf, bundle.ExportOptions{Select: []string{"matches/derby"}, Authors: true})
	noErr(t, err)
	if sum.Lines != 3 { // alice's grant line and the two revisions
		t.Fatalf("lines %d, want 3: %s", sum.Lines, buf.String())
	}
	var grantLines []string
	named := map[string]any{}
	for _, l := range lines(buf.Bytes())[1:] {
		m := jsonv.MustParse(l).(map[string]any)
		if _, isLine := m["stored"]; isLine {
			grantLines = append(grantLines, m["grant"].(string))
			continue
		}
		named[m["id"].(string)] = m["grant"]
	}
	if len(grantLines) != 1 || grantLines[0] != ga.ID().String() {
		t.Fatalf("grant lines %v, want alice's alone", grantLines)
	}
	if named[r1] != ga.ID().String() || named[r2] != nil {
		t.Fatalf("grants named: %v, want alice's on %s and none on %s", named, r1, r2)
	}
	notes := strings.Join(plan.Notes, "\n")
	if !strings.Contains(notes, gb.ID().String()) || !strings.Contains(notes, "disagrees with itself") {
		t.Fatalf("notes: %v", plan.Notes)
	}
	if _, err := bundle.Verify(bytes.NewReader(buf.Bytes())); err != nil {
		t.Fatalf("the exported bundle: %v", err)
	}
}
