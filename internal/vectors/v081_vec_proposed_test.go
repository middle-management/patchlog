package vectors_test

// The candidate vectors of docs/VECTORS-PROPOSED.md (P.1–P.7, for §I.15's
// list), each computed here through the reference's production code and
// compared with the candidate. testdata/proposed.json holds the candidates
// as the document gives them (extracted, never computed); a value the
// reference computes otherwise is a failure here, reported to the writer,
// never a candidate overwritten with ours.

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/middle-management/patchlog/internal/bundle"
	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/files"
	"github.com/middle-management/patchlog/internal/grant"
	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/merge"
	"github.com/middle-management/patchlog/internal/schema"
	"github.com/middle-management/patchlog/internal/seal"
	"github.com/middle-management/patchlog/internal/vectors/golden"
)

// proposedFile is testdata/proposed.json.
type proposedFile struct {
	P1 struct {
		ReleaseDoc, ReleaseGenesis, Plan1, Digest1, Plan2, Digest2 string
		Digest2KeepingFreshNonces, FreshNonce1, FreshNonce2        string
	} `json:"P.1"`
	P2 struct {
		Renderings []struct {
			Doc, Rendering, SHA256 string
			Bytes                  int
		}
		Numbers [][2]string
	} `json:"P.2"`
	P3 struct {
		RecipientSeed, Sealed, SHA256, BundleDigest, SealedDigest string
		Headers                                                   []string
		Bytes                                                     int
		Rejected                                                  []struct{ Change, Bytes, SHA256, Rule string }
	} `json:"P.3"`
	P4 []struct {
		Instance, Bytes, Hostname, Why string
		IDNHostname                    string `json:"idn-hostname"`
	} `json:"P.4"`
	P5 struct {
		Kid         string
		Plaintexts  map[string]string
		Rows        []struct{ Payload, Key, PL, Plaintext, Tag, PaddedTag string }
		First, Last string
		LogRange    int    `json:"logRangeBytes"`
		LogRangeSum string `json:"logRangeSHA256"`
	} `json:"P.5"`
	P6 struct {
		Bundle, Digest, WithoutGrantLineSHA256, AuthorsFalseSHA256 string
		PlainWithVia, PlainDigest, PlainWithViaSHA256              string
		Bytes, PlainBytes                                          int
	} `json:"P.6"`
	P7 []struct{ Name, Rule, Library, Token string } `json:"P.7"`
}

func loadProposed(t *testing.T) proposedFile {
	t.Helper()
	var f proposedFile
	if !golden.Load(t, "proposed", &f) {
		t.Fatal("testdata/proposed.json is missing")
	}
	return f
}

func sha256Hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// P.1 (TOOLS §F.9): plan digests. The release path is the release
// document's revision, its genesis id computed as the client computes a
// write's (§3.3). Plan 1 goes through merge.PlanObject, as a release's
// digest is built, and merge.PlanDigest. Plan 2's batches carry config,
// which no release batch of the reference does (PlanObject builds none,
// questions Q30): its items go through PlanObject, the second batch's
// precondition on the first batch's result included, and the config
// members are added by hand. The fresh-nonce stripping (merge's
// digestSteps) is unexported and not reachable from here; the candidate's
// account of which ops it strips is checked through PlanDigest instead:
// keeping them gives the digest the candidate calls wrong.
func TestV081ProposedPlanDigests(t *testing.T) {
	t.Parallel()
	p := loadProposed(t).P1
	ops := func(s string) []any { return jsonv.MustParse([]byte(s)).([]any) }
	gen, err := client.ExpectedRevision("", []byte(`[{"op":"add","path":"","value":`+p.ReleaseDoc+`}]`))
	if err != nil || gen != p.ReleaseGenesis {
		t.Fatalf("release genesis %s %v, want %s", gen, err, p.ReleaseGenesis)
	}
	release := "/r/releases/release-7/rev/" + gen

	st := &merge.ReleaseStep{Step: 3, Key: "matches", Resources: []string{"derby"}}
	plan, err := merge.PlanObject(release, []*merge.ReleaseBranch{{Key: "matches", NS: "matches-r7", Target: "matches", At: nsID2}},
		[]*merge.ReleaseStep{st}, map[*merge.ReleaseStep][]any{st: {
			map[string]any{"resource": "derby", "ifMatch": idG, "steps": []any{ops(patches2)}},
		}})
	if err != nil {
		t.Fatal(err)
	}
	if got := string(jsonv.Canonical(plan)); got != p.Plan1 {
		t.Errorf("Plan 1 is\n%s\nwant\n%s", got, p.Plan1)
	}
	if d := merge.PlanDigest(plan); d != p.Digest1 {
		t.Errorf("Plan 1 digest %s, want %s", d, p.Digest1)
	}

	plan2 := func(fresh bool) map[string]any {
		derby0 := []any{ops(patches2), "delete"}
		final := map[string]any{"title": "Final"}
		var derby1 any = []any{}
		if fresh {
			derby0[0] = append([]any{map[string]any{"op": "add", "path": "/$nonce", "value": p.FreshNonce1}}, ops(patches2)...)
			final["$nonce"] = p.FreshNonce2
			derby1 = []any{map[string]any{"op": "replace", "path": "/$nonce", "value": p.FreshNonce2}}
		}
		b := &merge.ReleaseBranch{Key: "cat", NS: "cat-season-r7", Target: "cat-season", At: "1vmctae4vewju6nvxi374rkrkmyzpdrif"}
		s2 := &merge.ReleaseStep{Step: 2, Key: "cat", Resources: []string{"derby", "final"}}
		s4 := &merge.ReleaseStep{Step: 4, Key: "cat", Resources: []string{"derby", "semi"}}
		plan, err := merge.PlanObject(release, []*merge.ReleaseBranch{b}, []*merge.ReleaseStep{s2, s4}, map[*merge.ReleaseStep][]any{
			s2: {
				map[string]any{"resource": "derby", "ifMatch": idG, "steps": derby0},
				map[string]any{"resource": "final", "ifNoneMatch": "*", "steps": []any{[]any{map[string]any{"op": "add", "path": "", "value": final}}}},
			},
			s4: {
				map[string]any{"resource": "derby", "after": map[string]any{"step": 2.0, "key": "cat", "item": "derby"}, "steps": []any{derby1}},
				map[string]any{"resource": "semi", "ifMatch": idC, "steps": []any{[]any{map[string]any{"op": "add", "path": "/$nonce", "value": "not-a-fresh-nonce"}}}},
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		batches := plan["batches"].([]any)
		batches[0].(map[string]any)["config"] = map[string]any{"ifMatch": idG, "patches": ops(`[{"op":"add","path":"/x-release","value":"release-7"}]`)}
		batches[1].(map[string]any)["config"] = map[string]any{"ifMatch": map[string]any{"batch": 0.0}, "patches": ops(`[{"op":"remove","path":"/x-release"}]`)}
		return plan
	}
	if got := string(jsonv.Canonical(plan2(false))); got != p.Plan2 {
		t.Errorf("Plan 2 is\n%s\nwant\n%s", got, p.Plan2)
	}
	if d := merge.PlanDigest(plan2(false)); d != p.Digest2 {
		t.Errorf("Plan 2 digest %s, want %s", d, p.Digest2)
	}
	if d := merge.PlanDigest(plan2(true)); d != p.Digest2KeepingFreshNonces {
		t.Errorf("Plan 2 keeping its fresh nonces: digest %s, the candidate's wrong one %s", d, p.Digest2KeepingFreshNonces)
	}
}

// P.2 (TOOLS §H.1): file renderings, through jsonv.ParseInput (a write's
// parser) and files.Rendering; the exponents through jsonv.FormatNumber.
func TestV081ProposedRenderings(t *testing.T) {
	t.Parallel()
	p := loadProposed(t).P2
	if len(p.Renderings) != 7 {
		t.Fatalf("%d renderings in proposed.json, want 7", len(p.Renderings))
	}
	for _, r := range p.Renderings {
		doc, err := jsonv.ParseInput([]byte(r.Doc))
		if err != nil {
			t.Errorf("%s: %v", r.Doc, err)
			continue
		}
		got := files.Rendering(doc)
		if string(got) != r.Rendering || len(got) != r.Bytes || sha256Hex(got) != r.SHA256 {
			t.Errorf("%s renders as %d bytes (sha-256 %s):\n%s\nwant %d bytes (%s):\n%s", r.Doc, len(got), sha256Hex(got), got, r.Bytes, r.SHA256, r.Rendering)
		}
	}
	for _, n := range p.Numbers {
		f, err := strconv.ParseFloat(n[0], 64)
		if err != nil {
			t.Fatal(err)
		}
		if got := jsonv.FormatNumber(f); got != n[1] {
			t.Errorf("FormatNumber(%s) = %s, want %s", n[0], got, n[1])
		}
	}
}

// P.4 (§6.2 step 5): hostname and idn-hostname under the format
// assertions of the reference's schema dialect (schema.V073, which a
// write's validation compiles with).
func TestV081ProposedHostnames(t *testing.T) {
	t.Parallel()
	rows := loadProposed(t).P4
	if len(rows) != 5 {
		t.Fatalf("%d rows in proposed.json, want 5", len(rows))
	}
	compile := func(format string) *jsonschema.Schema {
		c := jsonschema.NewCompiler()
		schema.V073.Configure(c)
		if err := c.AddResource("x.json", map[string]any{"format": format}); err != nil {
			t.Fatal(err)
		}
		s, err := c.Compile("x.json")
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	host, idn := compile("hostname"), compile("idn-hostname")
	verdict := func(s *jsonschema.Schema, v any) string {
		if s.Validate(v) != nil {
			return "422"
		}
		return "accept"
	}
	for _, r := range rows {
		b, err := hex.DecodeString(r.Bytes)
		if err != nil || !bytes.Equal(b, []byte(r.Instance)) {
			t.Fatalf("%s: bytes %s don't match", r.Instance, r.Bytes)
		}
		v, err := jsonv.ParseInput(b)
		if err != nil {
			t.Fatal(err)
		}
		if got := verdict(host, v); got != r.Hostname {
			t.Errorf("hostname %s: %s, want %s (%s)", r.Instance, got, r.Hostname, r.Why)
		}
		if got := verdict(idn, v); got != r.IDNHostname {
			t.Errorf("idn-hostname %s: %s, want %s (%s)", r.Instance, got, r.IDNHostname, r.Why)
		}
	}
}

// P.3 (§G.5.1.1): a sealed bundle of I.9's two lines to the recipient
// 20 21 … 3f, opened by seal.OpenBundle; its plaintext's digest and the
// sealed file's, through ids.Of (I.9's header lacks created, at and docs,
// so the bundle Reader, which needs them, isn't asked; TestI9BundleDigest).
// Its lines are reproduced under the envelope's K_b with the IV c0 … cb
// by sealLine (seal.SealWithIV needs a kid, which bundle lines have none
// of); every rejection row is rebuilt from it, its file hash compared, and
// refused by OpenBundle read to its end.
func TestV081ProposedSealedBundle(t *testing.T) {
	t.Parallel()
	p := loadProposed(t).P3
	sealed := []byte(p.Sealed)
	if len(sealed) != p.Bytes || sha256Hex(sealed) != p.SHA256 {
		t.Fatalf("the sealed bundle in proposed.json: %d bytes, sha-256 %s", len(sealed), sha256Hex(sealed))
	}
	seed, _ := hex.DecodeString(p.RecipientSeed)
	if !bytes.Equal(seed, seq(0x20)) {
		t.Fatal("recipient seed")
	}
	recipient := x25519(t, seed)
	open := func(b []byte) (string, error) {
		r, err := seal.OpenBundle(bytes.NewReader(b), recipient)
		if err != nil {
			return "", err
		}
		pt, err := io.ReadAll(r)
		return string(pt), err
	}
	plain, err := open(sealed)
	if err != nil || plain != i9 {
		t.Fatalf("opens to %q, %v; want I.9's bundle", plain, err)
	}
	if d := ids.Of([]byte(plain)).String(); d != p.BundleDigest {
		t.Errorf("source.bundle %s, want %s", d, p.BundleDigest)
	}
	if d := ids.Of(sealed).String(); d != p.SealedDigest {
		t.Errorf("the sealed bytes' digest %s, want %s", d, p.SealedDigest)
	}

	lines := strings.SplitAfter(string(sealed), "\n")
	lines = lines[:len(lines)-1] // after the last 0x0A
	if len(lines) != 3 {
		t.Fatalf("%d lines", len(lines))
	}
	env, _, err := seal.ParseBundleEnvelope([]byte(strings.TrimSuffix(lines[0], "\n")))
	if err != nil {
		t.Fatal(err)
	}
	kb := contentKey(t, recipient, env)
	pts := strings.SplitAfter(strings.TrimSuffix(i9, "\n"), "\n")
	for i := range pts {
		pts[i] = strings.TrimSuffix(pts[i], "\n")
	}
	for i, h := range p.Headers {
		if got := sealLineRaw(t, kb, h, []byte(pts[i])) + "\n"; got != lines[i+1] {
			t.Errorf("line %d under %s is\n%s\nwant\n%s", i, h, got, lines[i+1])
		}
	}

	hdr := func(n int, last bool, extra map[string]any) map[string]any {
		pl := map[string]any{"bundle": env.ID, "line": float64(n)}
		if last {
			pl["last"] = true
		}
		for k, v := range extra {
			pl[k] = v
		}
		return map[string]any{"alg": "dir", "enc": "A256GCM", "pl": pl}
	}
	file := func(l1, l2 string) []byte { return []byte(lines[0] + l1 + l2) }
	line := func(h map[string]any, i int) string { return sealLine(t, kb, h, []byte(pts[i])) + "\n" }
	head := `{"alg":"dir","enc":"A256GCM","pl":{"bundle":"` + env.ID + `","last":true,"line":1}}`
	cases := []struct {
		rule string // a fragment of the row's rule, which keeps the rows in step
		b    []byte
	}{
		{"isn't canonical", file(lines[1], sealLineRaw(t, kb, `{"alg":"dir","enc":"A256GCM","pl":{"bundle":"`+env.ID+`","line":1,"last":true}}`, []byte(pts[1]))+"\n")},
		{"isn't canonical", file(lines[1], sealLineRaw(t, kb, strings.Replace(head, `"pl":`, `"pl": `, 1), []byte(pts[1]))+"\n")},
		{"other members", file(lines[1], line(hdr(1, true, map[string]any{"ns": "matches"}), 1))},
		{"differs from id", file(lines[1], line(hdr(1, true, map[string]any{"bundle": "AAAAAAAAAAAAAAAAAAAAAA"}), 1))},
		{"in order", file(lines[1], line(hdr(2, true, nil), 1))},
		{"no line says last", file(lines[1], line(hdr(1, false, nil), 1))},
		{"follows the one that says last", file(line(hdr(0, true, nil), 0), lines[2])},
		{"0x0D", []byte(strings.TrimSuffix(lines[0], "\n") + "\r\n" + lines[1] + lines[2])},
		{"0x0D", []byte(lines[0] + lines[1] + strings.TrimSuffix(lines[2], "\n") + "\r\n")},
		{"lacks its 0x0A", []byte(lines[0] + lines[1] + strings.TrimSuffix(lines[2], "\n"))},
		{"blank line", file(lines[1], lines[2]+"\n")},
		{"fails to decrypt", file(lines[1], strings.TrimSuffix(lines[2], "Q\n")+"B\n")},
	}
	if len(cases) != len(p.Rejected) {
		t.Fatalf("%d rejection rows in proposed.json, %d built", len(p.Rejected), len(cases))
	}
	for i, c := range cases {
		row := p.Rejected[i]
		if !strings.Contains(row.Rule, c.rule) {
			t.Fatalf("row %d (%s) is no %q row", i, row.Rule, c.rule)
		}
		if got := sha256Hex(c.b); got != row.SHA256 {
			t.Errorf("%s: the file is sha-256 %s, want %s", row.Change, got, row.SHA256)
		}
		if pt, err := open(c.b); err == nil {
			t.Errorf("%s: opened to %q, want refused (%s)", row.Change, pt, row.Rule)
		}
	}
}

// P.6 (§G.4.1): full-history lines with via in a bundle with "authors":
// true, written by bundle.Writer with I.4's grant line (I.14's authority
// block as stored, the root key as key), and read back by the bundle
// Reader, which recomputes the ids and the grant id and verifies stored's
// signature under key.pub; and the rejected and accepted variants.
func TestV081ProposedBundleVia(t *testing.T) {
	t.Parallel()
	p := loadProposed(t).P6
	created := map[string]string{idG: "2026-10-04T12:00:00.000Z", idC: "2026-10-04T12:05:00.000Z"}
	write := func(authors bool) (string, string) {
		var buf bytes.Buffer
		h := bundle.Header{Origin: "https://staging.example", Created: "2026-10-04T14:00:00Z", Authors: authors,
			At: map[string]string{"matches": nsID2}, Docs: map[string]bundle.DocInfo{"matches/derby": {History: bundle.Full, Head: idC}},
			Access: map[string]string{"matches": bundle.AccessPrivate}}
		w, err := bundle.NewWriter(&buf, h)
		if err != nil {
			t.Fatal(err)
		}
		if authors {
			stored := i14Authority(t)
			if err := w.Line(bundle.Line{NS: "matches", GrantLine: &bundle.GrantLine{ID: i4GrantID, Root: jsonv.MustParse([]byte(i4Root)).(map[string]any),
				Stored: stored, Key: bundle.KeyEntry{Kid: "ops-2026", Alg: "Ed25519", Pub: "A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg"}}}); err != nil {
				t.Fatal(err)
			}
		}
		for _, l := range []bundle.Line{
			{NS: "matches", Resource: "derby", ID: idG, Kind: "rev", Parent: "", Patches: jsonv.MustParse([]byte(patches1))},
			{NS: "matches", Resource: "derby", ID: idC, Kind: "rev", Parent: idG, Patches: jsonv.MustParse([]byte(patches2)), Via: []string{"svc:translator"}},
		} {
			if authors {
				l.Author, l.Created, l.Grant = "user:bob", created[l.ID], i4GrantID
			} else {
				l.Via = nil
			}
			if err := w.Line(l); err != nil {
				t.Fatal(err)
			}
		}
		d, err := w.Close()
		if err != nil {
			t.Fatal(err)
		}
		return buf.String(), d
	}
	b, d := write(true)
	if b != p.Bundle || len(b) != p.Bytes || d != p.Digest {
		t.Errorf("the Writer wrote %d bytes, digest %s:\n%s\nwant %d bytes, %s:\n%s", len(b), d, b, p.Bytes, p.Digest, p.Bundle)
	}
	if got, err := readBundle(p.Bundle); err != nil || got != p.Digest {
		t.Errorf("the Reader: %s %v, want %s", got, err, p.Digest)
	}
	ls := strings.SplitAfter(p.Bundle, "\n")
	for _, c := range []struct {
		what, b, sum string
	}{
		{"without the grant line", ls[0] + ls[2] + ls[3], p.WithoutGrantLineSHA256},
		{"authors false", strings.Replace(p.Bundle, `"authors":true`, `"authors":false`, 1), p.AuthorsFalseSHA256},
		{"without authorship, c keeping via", p.PlainWithVia, p.PlainWithViaSHA256},
	} {
		if got := sha256Hex([]byte(c.b)); got != c.sum {
			t.Errorf("%s: sha-256 %s, want %s", c.what, got, c.sum)
		}
		if got, err := readBundle(c.b); err == nil {
			t.Errorf("%s: read with digest %s, want rejected", c.what, got)
		}
	}
	plain := strings.Replace(p.PlainWithVia, `,"via":["svc:translator"]`, "", 1)
	pb, pd := write(false)
	if pb != plain || len(pb) != p.PlainBytes || pd != p.PlainDigest {
		t.Errorf("without authorship the Writer wrote %d bytes, digest %s:\n%s\nwant %d bytes, %s", len(pb), pd, pb, p.PlainBytes, p.PlainDigest)
	}
	if got, err := readBundle(plain); err != nil || got != p.PlainDigest {
		t.Errorf("without authorship the Reader: %s %v, want %s", got, err, p.PlainDigest)
	}
}

// i14Authority is the authority block of I.14's token in base64url without
// padding, the stored form of §C.3.1, as the grant package encodes it.
func i14Authority(t *testing.T) string {
	t.Helper()
	tok := strings.Join(strings.Fields(i14Token), "")
	g, err := grant.Decode(tok, 0)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(g.Stored())
}

// i14Token is I.14's token (SPEC §I.14), as printed.
const i14Token = `
EpcCCqoBCgtncmFudF9ibG9jawqMAXsiY2FuIjpbInJlYWQiLCJhcHBlbmQiXSwiZXhwIjoiMjAyNi0xMC0wNVQwMDowMDowMFoiLCJncm91
cHMiOlsibWF0Y2gtZGVzayJdLCJraWQiOiJvcHMtMjAyNiIsIm5zIjpbIm1hdGNoZXMiXSwicnVsZXMiOltdLCJzdWIiOiJ1c2VyOmJvYiJ9
GAMiCgoICIAIEgMYgQgSJAgAEiAlQ7kv8QlVEUdq3INp223ckzZloRl43aFATuEGbKlVnRpAWgaUHLoFLrXYHs2MaIetUEXWGK0SK3h0v5xB
RUsBNE2qQ14tB8LGmoIYtimpZPta1sYSQLSXob_gozBFMAKwBCgBGp8BCjMKI3siY2FuIjpbInJlYWQiXSwidmlhIjoic3ZjOnJlYWRlciJ9
GAMiCgoICIAIEgMYgggSJAgAEiAXRVO0Vt3fxpCOyrHBAf5qsh4rqgYXeVt9Q6Y0gpk_1RpA8F--Z-0pJdeRlyhAqVvLMmB_GniPzob9JmjQ
7YO0D3Q2C3CKHXITLKHBjp3DfkQNccX2F8XKmGJl-6o7fmuICSgBIiIKIGBhYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ent8fX5_
`

// P.7 (§C.8): Biscuit tokens each breaking one acceptance rule, refused
// 401 by the reference's decoder (grant.DecodeLimited under a
// deployment's default bounds) or, where they decode, by grant.Verify in a
// namespace whose keys are ops-2026 (I.14's root key) and ops-2027 (seed
// 20 21 … 3f), at a time within I.4's window. I.14's token is the control,
// accepted there, so a token that fails for an unrelated reason (a line
// joined wrongly) doesn't pass for a refusal. stage pins where each is
// refused.
func TestV081ProposedBiscuitRefusals(t *testing.T) {
	t.Parallel()
	toks := loadProposed(t).P7
	stage := map[string]string{
		"Authority block with a second fact":                  "decode",
		"Authority block with a rule":                         "decode",
		"Authority block with a check":                        "decode",
		"Authority block with a block scope":                  "decode",
		"Authority block with a public key":                   "decode",
		"Authority block with context":                        "decode",
		"Authority block with an unused symbol":               "decode",
		"Authority block adding the narrowing block's string": "decode",
		"Narrowing block appended as a third-party block":     "decode",
		"Authority block signed over Biscuit's version 0":     "decode",
		"Narrowing block signed over the version 0 payload":   "decode",
		"Root block string not canonical":                     "decode",
		"Root block string not I-JSON":                        "decode",
		"Narrowing block string not canonical":                "decode",
		"Narrowing block signed with P-256":                   "decode",
		"Authority signature with `S + L` in place of `S`":    "verify",
		"Wrong `kid`": "verify",
	}
	keys, err := grant.ParseKeys(jsonv.MustParse([]byte(`[{"kid":"ops-2026","alg":"Ed25519","pub":"A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg","can":["*"]},` +
		`{"kid":"ops-2027","alg":"Ed25519","pub":"Kay64UG8yvCyLhqU000LxzYeUm0L_hLIl5S8kyKWbdc","can":["*"]}]`)))
	if err != nil {
		t.Fatal(err)
	}
	env := grant.Env{Now: time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC), NS: "matches", Keys: keys}
	lim := grant.Limits{Size: 8192, Rules: 256}
	judge := func(tok string) (string, error) {
		g, err := grant.DecodeLimited(tok, lim)
		if err != nil {
			return "decode", err
		}
		if _, err := grant.Verify(g, env); err != nil {
			return "verify", err
		}
		return "", nil
	}
	if st, err := judge(strings.Join(strings.Fields(i14Token), "")); err != nil {
		t.Fatalf("I.14's token, the control: refused at %s: %v", st, err)
	}
	if len(toks) != len(stage) {
		t.Fatalf("%d tokens in proposed.json, %d pinned", len(toks), len(stage))
	}
	for _, tk := range toks {
		want := ""
		for prefix, st := range stage {
			if strings.HasPrefix(tk.Name, prefix) {
				want = st
			}
		}
		if want == "" {
			t.Errorf("%s: no stage pinned", tk.Name)
			continue
		}
		st, err := judge(tk.Token)
		var ae *grant.AuthError
		switch {
		case err == nil:
			t.Errorf("%s: accepted, want 401 (%s)", tk.Name, tk.Rule)
		case !errors.As(err, &ae) || ae.Status != 401:
			t.Errorf("%s: %v, want 401 (%s)", tk.Name, err, tk.Rule)
		case st != want:
			t.Errorf("%s: refused at %s (%v), pinned at %s", tk.Name, st, err, want)
		}
	}
}
