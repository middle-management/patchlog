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
`internal/files` pin their own vectors in their package tests.

Since v0.81 services seal views under view keys, `HKDF-SHA256(K_n or K_r, "patchlog-view", view)`
(SERVICES §E.2.6, `seal.ViewKey`); `internal/derived` checks that its views open under them and
under no other key. §I.15 lists a view-key vector, which neither Addendum I nor the candidates
below give yet.

```
go test ./internal/vectors/ ./internal/ids/ ./internal/files/
```

This file used to be the v0.55 draft of that addendum, printed by `docs/vectorgen`. Both are
retired. The draft listed two inputs as rejected that the spec accepts: the integer literal 10²¹,
whose canonical form is `1e+21` (§3.1), and the "trailing-bit" id
`1l2gi2hhm3vt72ls2oufqpkqpsh6uvmlm`, a valid id since 160 bits fill 32 base32 characters exactly and
leave no padding bits (§3.2). `vectorgen` recomputed the grant id, the signing input, the cookie MAC
and `K_r` with code of its own instead of calling the reference's.

## Proposed additions (I.11 and the writer's list)

The vectors I.11 lists as still to come, and those the spec writer asked for, are computed through
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

## Candidate vectors (VECTORS-PROPOSED.md, v0.81)

[VECTORS-PROPOSED.md](VECTORS-PROPOSED.md) holds candidates for §I.15's list, computed
independently from the v0.81 text. They are kept as the document gives them in
[`testdata/proposed.json`](../internal/vectors/testdata/proposed.json) (extracted, never computed)
and checked through production code in
[`internal/vectors/v081_vec_proposed_test.go`](../internal/vectors/v081_vec_proposed_test.go):

```
go test ./internal/vectors/ ./internal/grant/ -run 'V081Proposed|V081Symbol'
```

| | What the reference computes it with | Verdict |
|---|---|---|
| P.1 Plan digests (§F.9) | the release revision's genesis id through `client.ExpectedRevision`; Plan 1 through `merge.PlanObject` and `merge.PlanDigest`; Plan 2's items and its `{ batch, item }` precondition through `PlanObject`, its `config` members added by hand (no release batch of the reference carries config), and both digests through `PlanDigest`, which also gives the candidate's wrong digest when the fresh-nonce ops are kept | confirms `1pjgzny3…` and `1gb5opsh…`; the fresh-nonce stripping itself (merge's `digestSteps`) is unexported and checked by merge's own tests |
| P.2 File renderings (§H.1) | `jsonv.ParseInput`, `files.Rendering`; the exponents through `jsonv.FormatNumber` | confirms all seven renderings and six numbers |
| P.3 Sealed bundles (§G.5.1.1) | `seal.OpenBundle` with recipient `20 21 … 3f`, `ids.Of` over the plaintext (`1b3a64kk…`; I.9's lines, which the bundle Reader refuses for want of `created`, `at` and `docs`) and the sealed file (`1gc7sf6e…`); the lines rebuilt under the envelope's `K_b` with the IV `c0 … cb` (AES-GCM in the test: bundle lines have no `kid`, which `seal.SealWithIV` needs); each rejection row rebuilt, its file hash compared and refused by `OpenBundle` | confirms the 907-byte file and all twelve rejections |
| P.4 `hostname`, `idn-hostname` (§6.2 step 5) | the format assertions of the reference's dialect (`schema.V073`) | confirms all five rows |
| P.5 Sealed log entries, events, namespace documents and ranges (§E.2.2) | every row's plaintext sealed under `seal.ResourceKey` or `seal.NamespaceKey` with the pl of `seal.ResourcePL`, `ResourceEventPL`, `NamespaceDocPL` or `RangePL`, through `seal.SealWithIV`, padded through `seal.Pad`; and the forms a sealed deployment serves (below) | confirms all eighteen tags, both full JWEs and the 1247-byte range |
| P.6 Full-history lines with `via` (§G.4.1) | `bundle.Writer` with I.4's grant line (I.14's authority block as `stored`) and the bundle Reader, which recomputes the line ids; the grant line's claims (grant id over `root`, `stored`'s string `canonical(root)`, its signature under `key.pub`) through `grant.ParseStoredBlock`, `ID` and `SignedBy`, as a verifier checks them (the Reader doesn't, and §G.4.1 doesn't ask it to) | confirms the 1543-byte bundle (`1hywrrzi…`), the 631-byte one (`1wmmkh2s…`) and the three rejections |
| P.7 Biscuit tokens failing §C.8 | `grant.DecodeLimited`, then `grant.Verify` in a namespace with keys `ops-2026` and `ops-2027`; I.14's token is the accepted control | confirms `401` for all seventeen tokens (the version 0 payloads at decode, `S + L` and the wrong `kid` at verification) |

P.5's plaintexts are the candidate's own: no conforming deployment writes them as given. Their
grant is I.4's, whose `ns` is `["matches"]`, not `demo`, and whose `can` (read, append) creates no
resource (`403`, checked); a sealed namespace's patch sets carry a fresh `$nonce`, which P.5's
don't; and `nsentry₁`'s target is I.2's `g`, not the revision of the namespace document. A sealed
deployment's `demo` at epoch 3, with P.5's `nsdoc` as its document, is checked for the forms
instead (`TestV081ProposedSealedServed`): its namespace document is P.5's byte for byte, and its
log entries, ranges, empty page, namespace event and purge and prune events open under the one
key they must (`K_r` or `K_n`), are canonical, and have P.5's members, with `parent` `""` at genesis,
`prev` `""` first, `via` on `c`, a range the array of its entries and an event its one entry.

`internal/grant`'s `TestV081SymbolUnusedPerBlock` pins the per-block rule P.7's eighth token
breaks: a symbol an earlier block adds that only a later block uses is refused at the block that
adds it.
