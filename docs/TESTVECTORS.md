# Patch Log — Test vectors

The test vectors are part of the spec: **[SPEC.md, Addendum I](SPEC.md#addendum-i--test-vectors-normative)**
(normative since v0.56). This file no longer carries a copy of them.

The reference reproduces every value of I.1–I.10, I.7's `K_n` and I.13's grant tag, and refuses
every input Addendum I marks as rejected, in
[`internal/vectors/addendum_i_test.go`](../internal/vectors/addendum_i_test.go). Each value is
computed by the production function the reference uses for it, never by a formula recomputed in
the test: the I-JSON parser and canonicaliser (I.1), the id formulas and the client's and
verifier's recomputation of them (I.2, I.3), grant minting and decoding and author signatures
(I.4), edge-grant cookies (I.5), padding (I.6), per-resource and namespace keys (I.7:
`seal.ResourceKey`, and `seal.NamespaceKey`, `K_n` =
`b2d9864bdf7f562d58e3638e08ec2e97e553c74995edbcef110ee9adfed62b4c` since v0.81), subject sets and
the tree service's combined checkpoint (I.8), the bundle Writer and Reader (I.9), file renderings
(I.10) and the grant sealed under `K_n` (I.13: `seal.SealWithIV` under `NamespaceKey` with
`seal.GrantPL`, tag `sAMGTdYa8kLrAP_ZfHvxCA`, v0.81; `TestI13GrantUnderKn`). I.1's `400`s and the
ids a write answers are also checked against an in-process deployment. `internal/ids` and
`internal/files` pin their own vectors in their package tests. §I.15–§I.21, which joined the
addendum in v0.82, and §I.22–§I.24, which joined it in v0.85, have their own files and sections below.

Since v0.81 services seal views under view keys, `HKDF-SHA256(K_n or K_r, "patchlog-view", view)`
(SERVICES §E.2.6, `seal.ViewKey`); `internal/derived` checks that its views open under them and
under no other key. A view-key vector is §I.23, and one for a response sealed whole is candidate C.4 below.

```
go test ./internal/vectors/ ./internal/ids/ ./internal/files/
```

This file used to be the v0.55 draft of that addendum, printed by `docs/vectorgen`. Both are
retired. The draft listed two inputs as rejected that the spec accepts: the integer literal 10²¹,
whose canonical form is `1e+21` (§3.1), and the "trailing-bit" id
`1l2gi2hhm3vt72ls2oufqpkqpsh6uvmlm`, a valid id since 160 bits fill 32 base32 characters exactly and
leave no padding bits (§3.2). `vectorgen` recomputed the grant id, the signing input, the cookie MAC
and `K_r` with code of its own instead of calling the reference's.

## Proposed additions (the reference's own)

Vectors for what "Still to come" (§I.26; §I.25 before v0.86, §I.22 before v0.85, §I.11 and §I.15 before v0.82) has listed, and those the
spec writer asked for, are computed through
production code too and kept in [`internal/vectors/testdata`](../internal/vectors/testdata) as
JSON, each naming the production function that produced it: RE2 `\u` (`re2.json`), key wraps in
HPKE base and auth mode (`keywrap.json`), `/keys` entries (`wrappedkeys.json`), sealed payloads and
blobs (`sealed.json`), sealed bundles (`sealedbundle.json`), the plan digest (`plandigest.json`),
Biscuit tokens and revocation ids (`biscuit.json`), file renderings (`renderings.json`),
noncharacters (`noncharacters.json`), `/principal`'s `key` (`principal.json`), a history line with
`via` (`bundlevia.json`), the archive key (`archivekey.json`, informative) and sealed resource
events (`resourceevents.json`). Rejection cases name the rule they break; cases the spec leaves
open are marked `informative`. They are a proposal for the writer until Addendum I takes them.
The tests check the stored files byte for byte and the verdicts on their own;

```
go test ./internal/vectors/ ./internal/grant/ ./internal/merge/ ./internal/core/ -run Vector -update
```

regenerates them (randomness is fixed with the reference's test hooks, sealed bundles under a fixed
seed).

## §I.15–§I.21 (v0.82; §I.17 as of v0.85)

v0.81's candidates P.1–P.7, which the reference confirmed in v0.27.0, are Addendum I's §I.15–§I.21
since v0.82. Their values are kept as SPEC.md prints them in
[`testdata/addendum_i.json`](../internal/vectors/testdata/addendum_i.json) (extracted from the
text, never computed, and never rewritten by `-update`) and checked through production code in
[`internal/vectors/addendum_i15_test.go`](../internal/vectors/addendum_i15_test.go):

```
go test ./internal/vectors/ ./internal/grant/ -run 'TestI1[5-9]|TestI2[01]|V081Symbol'
```

| | Test | What the reference computes it with |
|---|---|---|
| §I.15 Plan digests (§F.9) | `TestI15PlanDigests` | the release revision's genesis id through `client.ExpectedRevision`; `plan₁` through `merge.PlanObject` and `merge.PlanDigest`; `plan₂`'s items and its `{ batch, item }` precondition through `PlanObject`, its `config` members added by hand (no release batch of the reference carries config), and both digests through `PlanDigest`, which also gives the digest the spec calls wrong when the fresh-nonce ops are kept. The fresh-nonce stripping itself (merge's `digestSteps`) is unexported and checked by merge's own tests |
| §I.16 More file renderings (§H.1) | `TestI16Renderings` | `jsonv.ParseInput`, `files.Rendering`, by length and sha-256; the six exponents through `jsonv.FormatNumber`; the last rendering's 96 bytes as §I.16 prints them (v0.85) |
| §I.17 Sealed bundles (§G.5.1.1), recomputed in v0.85 | `TestI17SealedBundle` | I.12's envelope and the three lines opened by `seal.OpenBundle` with recipient `20 21 … 3f`: the plaintext is I.20's accepted bundle (`"authors": false`), which the bundle Reader reads with I.20's digest `1wmmkh2s…`; `ids.Of` over the 1580 sealed bytes (`1mrkazwa…`); the envelope opened to `K_b` `dbe5882e…`; the lines rebuilt under it with the IV `c0 … cb` (AES-GCM in the test: bundle lines have no `kid`, which `seal.SealWithIV` needs), unpadded and, through `seal.Pad`, padded to 272, 256 and 256 bytes (the three tags, the 1789-byte file, which opens to the same bundle; `seal.BundleWriter` with `Pad` writes lines of the same lengths); each of the twelve rejection rows rebuilt, its file hash compared and refused by `OpenBundle` |
| §I.18 Hostnames (§6.2 step 5) | `TestI18Hostnames` | the format assertions of the reference's dialect (`schema.V073`), four rows, five instances |
| §I.19 Sealed log entries, namespace documents and ranges (§E.2.2) | `TestI19SealedPayloads`, `TestI19SealedServed` | every row's plaintext sealed under `seal.ResourceKey` or `seal.NamespaceKey` with the pl of `seal.ResourcePL`, `NamespaceDocPL` or `RangePL`, through `seal.SealWithIV`, padded through `seal.Pad`: all twelve tags, `entry_g`'s JWE and the 1247-byte range; and the forms a sealed deployment serves (below) |
| §I.20 Full-history lines with `via` (§G.4.1) | `TestI20BundleVia` | `bundle.Writer` with I.4's grant line (I.14's authority block as `stored`) and the bundle Reader, which recomputes the line ids and, since v0.82, holds the grant line to its `root`; the signature under `key.pub` through `grant.ParseStoredBlock` and `SignedBy`, as a verifier checks it: the 1543-byte bundle (`1hywrrzi…`), the 631-byte one (`1wmmkh2s…`) and the three rejections |
| §I.21 Biscuit tokens refused (§C.8) | `TestI21BiscuitRefusals` | `grant.DecodeLimited`, then `grant.Verify` in a namespace with keys `ops-2026` and `ops-2027`; I.14's token is the accepted control: `401` for all seventeen tokens (fifteen at decoding, `S + L` and the wrong `kid` at verification) |

§I.19's plaintexts are illustrative: no conforming deployment writes them as given. Their grant is
I.4's, whose `ns` is `["matches"]`, not `demo`, and whose `can` (read, append) creates no resource
(`403`, checked); a sealed namespace's patch sets carry a fresh `$nonce`, which §I.19's don't; and
`nsentry₁`'s target is I.2's `g`, not the revision of the namespace document. A sealed
deployment's `demo` at epoch 3, with §I.19's `nsdoc` as its document, is checked for the forms
instead (`TestI19SealedServed`): its namespace document is §I.19's byte for byte, and its log
entries, ranges and empty page open under the one key they must (`K_r` or `K_n`), are canonical,
and have §I.19's members, with `parent` `""` at genesis, `prev` `""` first, `via` on `c` and a range
the array of its entries.

`internal/grant`'s `TestV081SymbolUnusedPerBlock` pins the per-block rule §I.21's eighth token
breaks: a symbol an earlier block adds that only a later block uses is refused at the block that
adds it.

**§I.17 in v0.85.** The spec recomputed §I.17 from its text alone and asks the reference to
confirm it. It does: every value reproduces through the production code above (the 1580-byte
file and its sha-256, both digests, `K_b`, the three lines, the padded tags, length and sha-256,
and the twelve rejection files, each refused). Until v0.85 it sealed I.9's two lines, which
§G.4.1 rejects once decrypted (907 bytes, `30bf22f8…`). In v0.85 the last row
("line 2's last character `Q` made `B`") left a tag that isn't canonical base64url, which the
reference refuses as a malformed JWE before it decrypts anything. v0.86 makes it `A`
(`f69e76d7…`), which keeps the tag canonical and changes it: the test checks that the row is
refused by decryption, as its rule says.

## §I.22–§I.24 (v0.85)

v0.82's candidates C.1, the per-entry half of C.2, and C.3, which the reference confirmed in
v0.28.0, are Addendum I's §I.22–§I.24 since v0.85, their values unchanged. They are kept as
SPEC.md prints them in `testdata/addendum_i.json` and checked in
[`internal/vectors/addendum_i22_test.go`](../internal/vectors/addendum_i22_test.go):

```
go test ./internal/vectors/ -run 'TestI2[234]'
```

| | Test | What the reference computes it with |
|---|---|---|
| §I.22 Sealed events (§E.2.2) | `TestI22SealedEvents`, `TestI22SealedEventsServed` | the two resource rows under `seal.ResourceKey` with the pl of `seal.ResourceEventPL`, the namespace event under `seal.NamespaceKey` with the pl of `seal.NamespaceEventPL`, through `seal.SealWithIV` and `seal.Pad`: all six tags and the namespace event's JWE; the client (`NSEvents`, `ResourceEvents`) reading the three as a stream serves them, and refusing the namespace event under the range pl §I.22 names (v0.81's form, tag `yXiFzJA3…`, rebuilt); and the forms a sealed deployment serves |
| §I.23 View keys and per-entry sealing (§E.2.6) | `TestI23ViewKey` | the view from I.8's `gs` (`grantcheck.SubjectSetID`; an input only), `ns_id₂` and `derived.CanonicalQuery` without `min`; `seal.ViewKey` over `K_r`; the hit's JWE through `seal.SealWithIV` with the pl of `derived.View`, padded through `seal.Pad`; `derived.SealItem` (own IV) for the same header and plaintext; `derived.OpenItem` opening the JWE and rejecting the four altered views |
| §I.24 Bundles refused (§G.4.1) | `TestI24BundlesRefused` | each bundle built from §I.20's and matched to its sha-256, then read by the bundle Reader: row 1's id is `grant.Decode` of §I.21's `ops-2027` token, `ID()`, the id §I.21 now states; row 2's `stored` is the authority block cut out of §I.21's token whose root block string has `sub` first; each rejected whole, rows 1 and 2 at the grant line (line 2), row 3 at the header. The Writer refuses rows 1 and 2 too |

## Candidate vectors (VECTORS-PROPOSED.md, v0.85)

[VECTORS-PROPOSED.md](VECTORS-PROPOSED.md) holds candidates for "Still to come" (§I.26's list since v0.86; the document itself still says §I.25), computed
independently from the v0.85 text. They are kept as the document gives them in
[`testdata/candidates.json`](../internal/vectors/testdata/candidates.json) (extracted, never
computed) and checked through production code in
[`internal/vectors/v085_candidates_test.go`](../internal/vectors/v085_candidates_test.go) (the
computed values) and
[`internal/vectors/v085_pending_test.go`](../internal/vectors/v085_pending_test.go) (what a
deployment answers with them):

```
go test ./internal/vectors/ -run 'V085C'
```

| | What the reference computes it with | Verdict |
|---|---|---|
| C.4 Whole-response sealing at an index `gs` (§E.2.6, §A.4) | the `key:` string of `ops-2026` with I.14's `pub` through `catvis.KeySubject`, the function the origin and the index bind a `gs` to a key with; the `gs` over the one marker `reads:demo:key:…` through `grantcheck.SubjectSetID`; the view with `derived.CanonicalQuery`; `seal.ViewKey` over `K_n`; both JWEs through `seal.SealWithIV` with the pl of `derived.View`, the padded one over `seal.Pad` (204 bytes to 256); `derived.SealView` (own IV) for the same header and plaintext, and `derived.OpenView` opening both candidates at that view and not at §I.23's | confirmed: the `key:` string, the marker, the `gs`, the view, the view key and both JWEs in full. `canonical([kid, pub])` is read with `pub` the key entry's base64url string, as "Underdetermined" supposes: that is the reference's reading too. An index answering a namespace-wide reader at this `gs` is checked in `TestV085C4IndexServesWhole` |
| C.5 Grant lines whose `key` doesn't match (§G.4.1) | each bundle built from §I.20's by changing the grant line's `key.kid`, or its `key.pub` to the key of seed `20 21 … 3f` (`ed25519.NewKeyFromSeed`), and matched to the candidate's sha-256 (`TestV085C5GrantLineKey`); then read by the bundle Reader (`TestV085C5GrantLineKeyRejected`) | confirmed: both sha-256 values; each bundle is rejected whole at the grant line (line 2) by the check §G.4.1 gained in v0.85 |

§I.22's plaintexts, like §I.19's, are illustrative; the served forms are checked against the same
sealed deployment (`TestI22SealedEventsServed`): after a prune at `c` and a purge, the namespace
event for the last entry opens under `K_n` with pl `{ event, ns }` and under no range's pl, its
plaintext that entry, and the reference's client reads the stream as that entry; the `prune` and
`purge` events open under `K_r` with pl `{ kind, name, ns }`, their plaintext the namespace entry
without `id` and `prev`.
