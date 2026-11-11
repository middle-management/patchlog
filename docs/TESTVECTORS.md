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
addendum in v0.82, have their own file and section below.

Since v0.81 services seal views under view keys, `HKDF-SHA256(K_n or K_r, "patchlog-view", view)`
(SERVICES §E.2.6, `seal.ViewKey`); `internal/derived` checks that its views open under them and
under no other key. A view-key vector is candidate C.2 below, which the reference confirms.

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

Vectors for what "Still to come" (§I.22, before v0.82 §I.11 and §I.15) has listed, and those the
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

## §I.15–§I.21 (v0.82)

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
| §I.16 More file renderings (§H.1) | `TestI16Renderings` | `jsonv.ParseInput`, `files.Rendering`, by length and sha-256; the six exponents through `jsonv.FormatNumber` and in the last rendering's bytes |
| §I.17 Sealed bundles (§G.5.1.1) | `TestI17SealedBundle` | I.12's envelope and the two lines opened by `seal.OpenBundle` with recipient `20 21 … 3f`; `ids.Of` over the plaintext (I.9's digest; I.9's lines, which the bundle Reader refuses for want of `created`, `at` and `docs`) and over the 907 sealed bytes (`1gc7sf6e…`); the lines rebuilt under the envelope's `K_b` with the IV `c0 … cb` (AES-GCM in the test: bundle lines have no `kid`, which `seal.SealWithIV` needs); each of the twelve rejection rows rebuilt, its file hash compared and refused by `OpenBundle` |
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

## Candidate vectors (VECTORS-PROPOSED.md, v0.82)

[VECTORS-PROPOSED.md](VECTORS-PROPOSED.md) holds candidates for §I.22's list, computed
independently from the v0.82 text. They are kept as the document gives them in
[`testdata/candidates.json`](../internal/vectors/testdata/candidates.json) (extracted, never
computed) and checked through production code in
[`internal/vectors/v082_vectors_test.go`](../internal/vectors/v082_vectors_test.go):

```
go test ./internal/vectors/ -run 'V082C'
```

| | What the reference computes it with | Verdict |
|---|---|---|
| C.1 Resource `purge` and `prune` events, namespace events (§E.2.2) | the two resource rows under `seal.ResourceKey` with the pl of `seal.ResourceEventPL`, the namespace event under `seal.NamespaceKey` with the pl of `seal.NamespaceEventPL`, through `seal.SealWithIV` and `seal.Pad`; the client (`NSEvents`, `ResourceEvents`) reading the three as a stream serves them, and refusing v0.81's range form of the namespace event (its tag `yXiFzJA3…`, rebuilt); and the forms a sealed deployment serves (`TestV082C1EventsServed`) | confirmed: all six tags and the namespace event's JWE. The closing sentence is not: read as written, it says the resource events' `{"kind":…,"name":…,"ns":…}` is no longer accepted, against its own table and §E.2.2, which keep it. The reference accepts that form for resource events and refuses only the range form of a namespace event |
| C.2 A view key and JWEs under it (§E.2.6) | the view from I.8's `gs` (`grantcheck.SubjectSetID`), `ns_id₂` and `derived.CanonicalQuery` without `min`; `seal.ViewKey` over `K_n` and `K_r`; both JWEs through `seal.SealWithIV` with the pl of `derived.View`, padded through `seal.Pad`; `derived.SealView` and `SealItem` (own IVs) for the same headers and plaintexts; `derived.OpenView` and `OpenItem` opening the candidate's JWEs and rejecting the four altered views | confirmed: the canonical query, the view, both view keys, both JWEs and both padded tags; the four altered `pl.view` forms are rejected |
| C.3 Bundle rejections (§G.4.1) | each bundle built from §I.20's and matched to the candidate's sha-256, then read by the bundle Reader: row 1's id is `grant.Decode` of §I.21's `ops-2027` token, `ID()`; row 2's `stored` is the authority block cut out of §I.21's token whose root block string has `sub` first (the grant package refuses to decode it) | confirmed: the three sha-256 values, each bundle rejected whole, rows 1 and 2 at the grant line (line 2) for the rule named, row 3 at the header. The Writer refuses rows 1 and 2 too |

C.1's plaintexts, like §I.19's, are illustrative; the served forms are checked against the same
sealed deployment (`TestV082C1EventsServed`): after a prune at `c` and a purge, the namespace
event for the last entry opens under `K_n` with pl `{ event, ns }` and under no range's pl, its
plaintext that entry, and the reference's client reads the stream as that entry; the `prune` and
`purge` events open under `K_r` with pl `{ kind, name, ns }`, their plaintext the namespace entry
without `id` and `prev`.
