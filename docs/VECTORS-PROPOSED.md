# Patch Log — proposed test vectors (unconfirmed candidates)

**Status: unconfirmed candidates**, computed independently from the v0.85 draft (SPEC.md, SERVICES.md, TOOLS.md) for §I.25, for the reference implementation to confirm. Nothing here is normative until it does. v0.82's C.1, the per-entry half of C.2, and C.3, which the reference reproduced (Open 85), are now §I.22–§I.24. C.4 replaces the rest of C.2; C.5 is new.

`patchlog-vectors-proposed.py` (Python stdlib + `cryptography`) first reproduces every value of Addendum I, §I.1–§I.24, and checks that each occurs in the draft. It aborts on any mismatch, then prints this file. Conventions, keys and the IV `c0 c1 … cb` are Addendum I's. Every plaintext here is illustrative (Addendum I's preface), as §I.19's are.

**Reconfirm in Addendum I.** v0.85 recomputes §I.17 from this script alone (Open 84): it now seals §I.20's accepted bundle, adds a padded variant, and so changes every sealed line, length and sha-256 there. §I.16 prints its last rendering, and §I.21 states the `ops-2027` root block's grant id; those values are unchanged.

## C.4 Whole-response sealing at an index `gs` (§E.2.6, §A.4)

Replaces the whole-response half of the earlier C.2, whose `gs` (§I.8's, of `group:match-desk` and `user:anna`) admits readers a conforming index would seal for per entry (Open 85). An index on its own origin serves private `demo` (epoch 3) to a reader whose grant `demo`'s key `ops-2026`, with I.14's `pub`, verifies, and who would be issued a namespace-wide edge grant there. Its `key:` string (§B.11.9 `gs`), marker (§A.4) and `gs`, over that one marker as §B.11.5 computes it, are

    key:{text(trunc160(sha256(canonical(["ops-2026","A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg"]))))} = key:1gorsoawpfk76fdd6bdqtgqkial3qgvl4
    marker = reads:demo:key:1gorsoawpfk76fdd6bdqtgqkial3qgvl4
    gs     = 1qt3t7wcs3jfhqrrkkunh3mvoi4tyjsrt

so, for the query of §I.23 at `ns_id₂`,

    view = /demo/g/1qt3t7wcs3jfhqrrkkunh3mvoi4tyjsrt/at/1pa2nh6iw2yd2djqfy2wrszd5kglfpxvm?q=a%20b&sort=%2Ftitle
    HKDF-SHA256(K_n, "patchlog-view", view) = 0749995a1c2c67c6158cd8bfaa38fe0782379fbcfdf397929ddccedc3a1b8561

The whole response, sealed under that key with `kid` `demo#3`:

    header    = {"alg":"dir","enc":"A256GCM","kid":"demo#3","pl":{"ns":"demo","view":"/demo/g/1qt3t7wcs3jfhqrrkkunh3mvoi4tyjsrt/at/1pa2nh6iw2yd2djqfy2wrszd5kglfpxvm?q=a%20b&sort=%2Ftitle"}}
    plaintext = {"at":"1pa2nh6iw2yd2djqfy2wrszd5kglfpxvm","hits":[{"/title":["Hello"],"id":"1sywh54kpo3c4ezn2znktvl3avge4zl5d","resource":"derby","score":1.5,"url":"/r/demo/derby/rev/1sywh54kpo3c4ezn2znktvl3avge4zl5d"}]}

    eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwia2lkIjoiZGVtbyMzIiwicGwiOnsibnMiOiJkZW1vIiwidmlldyI6Ii9kZW1vL2cvMXF0
    M3Q3d2NzM2pmaHFycmtrdW5oM212b2k0dHlqc3J0L2F0LzFwYTJuaDZpdzJ5ZDJkanFmeTJ3cnN6ZDVrZ2xmcHh2bT9xPWElMjBiJnNvcnQ9
    JTJGdGl0bGUifX0..wMHCw8TFxsfIycrL.r4RxBjItJp72QfG_q6E5ziirAqcpOviYs5fNbb0SENg4FfPvyfNAlwOrRHLwLdkssaLpyL7Bca
    HhNA_-tPUeXdq6TiwAUgyQ8bN4D5ykZXLB6oB5mY5LVu1nqj03R8J_LGD8pfHm-op--ejVOjt27FCoVJjz7Y7sU1VYpE-uEdxjSj2NnjPe2N
    eWKyK6xVBhI54GtaVNSZsVPIXX2ILrpygIReU9fsYk9d26bHVfEi8yAJ06c2sGbREkUgp3UZvh1w9NsJrwvHbD5qlq.9ZxrxXnWl2IT1pXAH
    lWi3g

Padded (§E.2.2), its plaintext is that canonical JSON (204 bytes) followed by ASCII spaces to its bucket, 256 bytes:

    eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwia2lkIjoiZGVtbyMzIiwicGwiOnsibnMiOiJkZW1vIiwidmlldyI6Ii9kZW1vL2cvMXF0
    M3Q3d2NzM2pmaHFycmtrdW5oM212b2k0dHlqc3J0L2F0LzFwYTJuaDZpdzJ5ZDJkanFmeTJ3cnN6ZDVrZ2xmcHh2bT9xPWElMjBiJnNvcnQ9
    JTJGdGl0bGUifX0..wMHCw8TFxsfIycrL.r4RxBjItJp72QfG_q6E5ziirAqcpOviYs5fNbb0SENg4FfPvyfNAlwOrRHLwLdkssaLpyL7Bca
    HhNA_-tPUeXdq6TiwAUgyQ8bN4D5ykZXLB6oB5mY5LVu1nqj03R8J_LGD8pfHm-op--ejVOjt27FCoVJjz7Y7sU1VYpE-uEdxjSj2NnjPe2N
    eWKyK6xVBhI54GtaVNSZsVPIXX2ILrpygIReU9fsYk9d26bHVfEi8yAJ06c2sGbREkUgp3UZvh1w9NsJrwvHbD5qlqRXtdjWXsufQImtG9M5
    dwEj86hrviBk7vT092qwXLPg8uAp1WB4CiAhRvq7xK2IxjoHMF1A._s-VCi-OLnvKfRMauJWIEQ

## C.5 Grant lines whose `key` doesn't match (§G.4.1)

New in v0.85 (Open 75). Each a change to §I.20's bundle that §G.4.1 now rejects whole; every other check still holds (sha-256 of the bundle):

| Change | sha-256 | Rule |
|---|---|---|
| the grant line's `key.kid` is `ops-2027` | `59dd09cd7d6913eaf8bfc58025bb02f5b27468b757ee351b64d90457ded62920` | a grant line whose `key` has a `kid` other than `root.kid` |
| the grant line's `key.pub` is `Kay64UG8yvCyLhqU000LxzYeUm0L_hLIl5S8kyKWbdc`, the key of seed `20 21 … 3f` (§I.21's `ops-2027`) | `44e7aa12dfb273be81818819f8f53cefb404d031da212971847afd8bdd8b0910` | a grant line whose `key` doesn't verify the `stored` block |

## Underdetermined

- **§C.8, block versions.** The block `version` a conforming token carries isn't stated; §I.14 uses 3. A scope or public key needs Biscuit version 4 and a third-party block 5; §I.21 sets those.
- **§I.12's sealed-bundle envelope.** The ephemeral key of its `wrapped` isn't stated (its `enc` is none of the `xx xx+1 …` keys), so it can be checked only by opening it (it opens to `K_b`), not regenerated. §I.17 reuses it.
- **§B.11.9's `key:` string.** `canonical([kid, pub])` is read with `pub` the key entry's base64url string, as the namespace document lists it (C.4).
- **One IV.** Addendum I seals every line of §I.17 under one `K_b` with the IV `c0 c1 … cb`, as all its JWEs use it; a real sealing draws a fresh IV per JWE (RFC 7518), and the lines' shared ciphertext prefixes show why.
