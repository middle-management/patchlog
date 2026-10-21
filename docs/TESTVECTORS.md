# Patch Log — Test vectors (draft addendum)

Status: draft, for spec v0.55. Proposed as the addendum §13 calls for ("Test vectors"),
covering the definitions §1 (Conformance) requires to agree byte-exactly between
implementations: ids (§3), blob ids (§3.7), bundle digests (§G.4.1), plan digests (§F.9)
and padding buckets (§E.2.2), plus the byte-exact derived values of §B.5, §B.11.5, §C.3,
§C.5.3 and §E.2.1.

Every vector below was computed with the reference implementation (Go, v0.22.0) by
`docs/vectorgen`. Where a vector is already pinned by a reference test, the test is named.
All byte strings are hex; all JSON is shown in its canonical form (§3.1).

## 1. Canonical JSON (§3.1, RFC 8785)

Canonicalisation is RFC 8785 (JCS) over UTF-8. The number rules of §3.1 are the ones most
easily misimplemented; an implementation MUST accept or reject these inputs as shown:

| Input (as received) | Verdict | Canonical form |
|---|---|---|
| `{"a":1,"b":2.0}` | accept | `{"a":1,"b":2}` |
| `{"a":1e2}` | accept | `{"a":100}` |
| `{"a":9007199254740991}` (2⁵³−1) | accept | `{"a":9007199254740991}` |
| `{"a":9007199254740992}` (2⁵³) | **reject `400`** | — |
| `{"a":1e21}` | accept | `{"a":1e+21}` |
| `{"a":1000000000000000000000}` (10²¹, integer literal) | **reject `400`** | — |
| `{"a":1e300}` | accept | `{"a":1e+300}` |
| `{"a":-9007199254740992}` | **reject `400`** | — |
| `{"a":0.1}` | accept | `{"a":0.1}` |
| `{"a":1,"a":2}` (duplicate key) | **reject `400`** | — |

Sorting is by UTF-16 code units, as JCS requires: `{"b":1,"a":2,"ä":3}` canonicalises as
`{"a":2,"b":3,"ä":3}` (JCS example), and keys with characters above U+FFFF sort by their
surrogate pair.

## 2. Ids (§3.2–§3.5)

Let

```
patches₁ = [{"op":"add","path":"","value":{"title":"Hello","views":0}}]
patches₂ = [{"op":"replace","path":"/views","value":1}]
```

(already in canonical form). Then:

| Quantity | Value |
|---|---|
| genesis id `g` = `Revision(∅, patches₁)` | `1l2gi2hhm3vt72ls2oufqpkqpsh6uvmll` |
| `bytes(g)` | `5e8c8d1cecdd67fd2e5a750b07aa0f91fd4ab16b` |
| child id `c` = `Revision(g, patches₂)` | `1sywh54kpo3c4ezn2znktvl3avge4zl5d` |
| `bytes(c)` | `962c7ef14f76c5c265bacb553aaf60a989ccafa3` |
| tombstone id `Tombstone(c)` (§3.4) | `1idx6u2b3z42obqmwsgmlzvrfuutks2bq` |
| `bytes(…)` | `40efea683bcf34e0c1969198bcd625a526a96830` |

Parsing (§3.2): an implementation MUST reject text ids of the wrong length, with a
character outside `a–z2–7` after the leading `1`, or with non-zero trailing bits in the
last base32 character (non-canonical encodings), e.g. `1l2gi2hhm3vt72ls2oufqpkqpsh6uvmlm`
(trailing bit set) MUST NOT parse.

Namespace chain (§3.5), over the namespace document `{"read":"public"}`:

```
entry₁ = {"kind":"config","target":"1l2gi2hhm3vt72ls2oufqpkqpsh6uvmll"}
ns_id₁ = 1vmctae4vewju6nvxi374rkrkmyzpdrif
entry₂ = {"kind":"head","resource":"derby","target":"1l2gi2hhm3vt72ls2oufqpkqpsh6uvmll"}
ns_id₂ = Hash(ns_id₁, entry₂) = 1pa2nh6iw2yd2djqfy2wrszd5kglfpxvm
```

## 3. Blob ids (§3.7)

For `bytes` = `hello patchlog\n` (15 bytes):

| Input | Id |
|---|---|
| `type = text/plain`, no nonce | `1m5jj344d7tz7cicfmq53ayhmwuubpmyt` |
| `type = text/plain`, nonce `aaaaaaaaaaaaaaaaaaaaaaaaaa` | `1hdwkfub2zymqzgc75snybxosfk67633s` |

## 4. Grant id and author signatures (§C.3, §C.3.1)

Root block, canonical:

```
{"can":["read","append"],"exp":"2026-10-05T00:00:00Z","groups":["match-desk"],"kid":"ops-2026","ns":["matches"],"rules":[],"sub":"user:bob"}
```

Grant id: `15swdvi5nbnlkv76v7y6k77h52atov6ru`.

Signature input (§C.3.1) for `origin = https://cms.example`, `ns = matches`,
`name = derby`, `parent = g`, `patches = patches₂`:

```
sha256("patchlog-sig-v2\n" ‖ origin ‖ 0x0A ‖ "matches" ‖ 0x0A ‖ "derby" ‖ 0x0A ‖ bytes(g) ‖ 0x0A ‖ patches₂)
= 43bba3f8e86bdd96435153ddb0d704cab7e5e9459087f3fd78c157b6a7102c54
```

With the test Ed25519 key pair below (deterministic, for vectors only):

```
pub:  RuA-BPBo4NqYkx_g6O3FJZEvHe9xVq-EQmmn3F8mRiM
sig:  Ed25519:key-1:Zdm2HSg4Fefj9ZaOYm2nYdW7xyLjKc_6T8CruK76EDEL_H6rnZd_sKdQrlevjtIQDGpiudAJjyHigradmHXXCA
```

The signature MUST verify under `pub` (RFC 8032, strict). A tombstone signature uses the
ASCII bytes `tombstone` in place of `canonical(patches)`.

## 5. Edge-grant cookies (§C.5.3)

Pinned by `TestCookieVector` in the reference (`internal/edge`). For the edge secret
`example edge secret`:

```
derived key = HMAC-SHA256(secret, "patchlog edge grants v1")
            = 3dba7ab1a5240f2d1e3f4922b87f24be07b3e95885e0f515c57d6ac5c13dd708
claims c    = {"exp":1790000900,"kid":"origin","p":"/r/demo/derby"}
name        = __Secure-pl-eg-4390e78526d94754
value       = eyJleHAiOjE3OTAwMDA5MDAsImtpZCI6Im9yaWdpbiIsInAiOiIvci9kZW1vL2RlcmJ5In0.qn5oOZCcn6Au_LourbFpV2VbJ3u-XeiQlwNKAj43Lhw
```

Negative vectors an edge MUST ignore: a value whose claims carry a fourth member; claims
not byte-for-byte canonical (e.g. `{"kid":"origin","exp":1790000900,"p":"…"}` reordered);
a valid MAC over claims re-encoded by the verifier; a cookie whose name doesn't match its
`p`; `exp` in the past; a `p` that covers the path only as a string prefix (`/r/demox`).

## 6. Padding buckets (§E.2.2)

Pinned by the known answers in `internal/seal/pad_test.go` (worked by hand). `PadLen(L) =
max(256, padmé(L))`:

| L | PadLen(L) | | L | PadLen(L) |
|---|---|---|---|---|
| 1 | 256 | | 513 | 544 |
| 255 | 256 | | 1000 | 1024 |
| 256 | 256 | | 4096 | 4096 |
| 257 | 272 | | 1000000 | 1015808 |
| 300 | 304 | | 1048576 | 1048576 |
| 511 | 512 | | 67108864 | 67108864 |

`padmé` rounds up to a multiple of `2^(E−S)` with `E = ⌊log₂ L⌋`, `S = ⌊log₂ E⌋ + 1`;
overhead never exceeds 12%. The values just above a power of two (257, 513) are where
rounding errors show, so they are the important rows.

## 7. Per-resource keys (§E.2.1)

```
K_r = HKDF-SHA256(ikm = K_e, salt = "patchlog-e2", info = ns ‖ 0x0A ‖ name), 32 bytes out
```

Test vector: `K_e = 000102…1f` (bytes 0–31), `ns = demo`, `name = derby`:

```
K_r = 37a2b615272e7bdec36b97f35176a206caa2dbbef43d89b81aa5a4ee874a5c25
```

## 8. Subject sets and combined checkpoints (§B.5, §B.11.5)

```
subjects (sorted, canonical) = ["group:match-desk","user:anna"]
gs  = 17i2rqzsv3o2i5vlfhsklo6fu22jnqwtm

checkpoint = {"cat":"1vmctae4vewju6nvxi374rkrkmyzpdrif","matches":"1pa2nh6iw2yd2djqfy2wrszd5kglfpxvm"}
at  = 1vwnfnoyshruyx4lul4a25rtctooiph5v
```

## 9. Bundle digests (§G.4.1)

The bundle of exactly these two lines (each followed by one `\n`):

```
{"authors":false,"bundle":1,"origin":"https://staging.example"}
{"id":"1l2gi2hhm3vt72ls2oufqpkqpsh6uvmll","kind":"rev","ns":"matches","parent":"","patches":[{"op":"add","path":"","value":{"title":"Hello","views":0}}],"resource":"derby"}
```

has digest `1b3a64kkqf3o6f3rglkgi6ok5hgldbne6`. The digest covers the file bytes as
written; an implementation that re-encodes either line (member order, spacing) MUST NOT
reproduce it.

## 10. Not yet covered (to be added)

- **Plan digests (§F.9):** a worked plan with its canonical form and digest, including a
  precondition written as "step and item" rather than an id.
- **Sealed bundles (§G.5.1.1):** envelope line, one content line, the `last` flag, and the
  rejection cases (reordered, spliced, truncated).
- **Sealed-blob layout (§E.2.2):** a `PLB1` header with its length field and AAD bounds.
- **Biscuit encodings (§C.8):** a token whose blocks fail each acceptance rule (extra
  fact, third-party block, non-Ed25519 signature, non-canonical `grant_block` string).
- **Rendering (§H.1):** a document and its rendered file bytes, including the
  index-like-key ordering trap (`{"10":…,"2":…}` stays in JCS order, not ECMAScript's).
