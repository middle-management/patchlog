# Patch Log — Test vectors

The test vectors are part of the spec: **[SPEC.md, Addendum I](SPEC.md#addendum-i--test-vectors-normative)**
(normative since v0.56). This file no longer carries a copy of them.

The reference reproduces every value of I.1–I.10, and refuses every input Addendum I marks as
rejected, in [`internal/vectors/addendum_i_test.go`](../internal/vectors/addendum_i_test.go).
Each value is computed by the production function the reference uses for it, never by a formula
recomputed in the test: the I-JSON parser and canonicaliser (I.1), the id formulas and the
client's and verifier's recomputation of them (I.2, I.3), grant minting and decoding and author
signatures (I.4), edge-grant cookies (I.5), padding (I.6), per-resource keys (I.7), subject sets
and the tree service's combined checkpoint (I.8), the bundle Writer and Reader (I.9) and file
renderings (I.10). I.1's `400`s and the ids a write answers are also checked against an in-process
deployment. `internal/ids` and `internal/files` pin their own vectors in their package tests.

```
go test ./internal/vectors/ ./internal/ids/ ./internal/files/
```

This file used to be the v0.55 draft of that addendum, printed by `docs/vectorgen`. Both are
retired. The draft listed two inputs as rejected that the spec accepts: the integer literal 10²¹,
whose canonical form is `1e+21` (§3.1), and the "trailing-bit" id
`1l2gi2hhm3vt72ls2oufqpkqpsh6uvmlm`, a valid id since 160 bits fill 32 base32 characters exactly and
leave no padding bits (§3.2). `vectorgen` recomputed the grant id, the signing input, the cookie MAC
and `K_r` with code of its own instead of calling the reference's. When the vectors I.11 lists as
still to come are added, they will be computed through production code too.
