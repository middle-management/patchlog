# Patch Log — proposed test vectors (unconfirmed candidates)

**Status: unconfirmed candidates**, computed independently from the v0.82 draft (SPEC.md, SERVICES.md) for §I.22, for the reference implementation to confirm. Nothing here is normative until it does. v0.81's P.1–P.7, which the reference confirmed, are now §I.15–§I.21, less the three event rows below, whose `pl` v0.82 changed.

`patchlog-vectors-proposed.py` (Python stdlib + `cryptography`) first reproduces every value of Addendum I, §I.15–§I.21 included, and checks that each occurs in the draft. It aborts on any mismatch, then prints this file. Conventions, keys and the IV `c0 c1 … cb` are Addendum I's; `T` is the tombstone of `c` (§I.2). Every plaintext here is illustrative (Addendum I's preface), as §I.19's are.

## C.1 Resource `purge` and `prune` events, namespace events (§E.2.2)

Sealed under §I.19's keys, with `pl` as v0.82's table gives it. Each event's plaintext is its namespace entry, without `id` and `prev` for a resource event (§7.3):

    purge = {"author":"user:bob","created":"2026-10-04T13:00:00.000Z","grant":{"id":"15swdvi5nbnlkv76v7y6k77h52atov6ru","kid":"ops-2026","sub":"user:bob"},"kind":"purge","resource":"derby","target":"1idx6u2b3z42obqmwsgmlzvrfuutks2bq"}
    prune = {"author":"user:bob","created":"2026-10-04T13:00:00.000Z","grant":{"id":"15swdvi5nbnlkv76v7y6k77h52atov6ru","kid":"ops-2026","sub":"user:bob"},"kind":"prune","resource":"derby","target":"1sywh54kpo3c4ezn2znktvl3avge4zl5d"}

| Payload | Key | `pl` | Plaintext | Tag | Padded |
|---|---|---|---|---|---|
| resource `purge` event | `K_r` | `{"kind":"purge","name":"derby","ns":"demo"}` | `purge` | `2Lr0YlsnReKv3Vu1vzww6w` | `o6qg_FLKKyVd-bUUDCd0WA` |
| resource `prune` event (horizon `c`) | `K_r` | `{"kind":"prune","name":"derby","ns":"demo"}` | `prune` | `DQW969cxsNvKvMFoLcdwHw` | `UqL8Ockwt491woTRn4ov6w` |
| namespace event for `ns_id₂` | `K_n` | `{"event":"1pa2nh6iw2yd2djqfy2wrszd5kglfpxvm","ns":"demo"}` | §I.19's `nsentry₂` | `IegL6XMQn_6bp6mbVNkAhQ` | `zxVQ6oolCdXa4Bl6cJIlXA` |

The namespace event in full:

    eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwia2lkIjoiZGVtbyMzIiwicGwiOnsiZXZlbnQiOiIxcGEybmg2aXcyeWQyZGpxZnkyd3Jz
    emQ1a2dsZnB4dm0iLCJucyI6ImRlbW8ifX0..wMHCw8TFxsfIycrL.u8c251n3WG3uDvexX6uwqBTPKeBvMQlL6b6hdn6BXzGasJsQYlzR2i
    Rxzmt6VvZnsT23l0wx0KocOYbmfx5u4j-_DQ2xvuhBRCpvZdadGJoEhHO6FLSfwwSaX5egIQARrBBTZhH59ABtgAByLNLCl2cC0zdgCD3pmc
    nL3myyHmW8yaZ9F4RPBKS2IfqEh_aB-24mj6LA_qpnyYuKX00RfNsEhfpHqjcOjWbhoDTEtkSho4uTVjf1EIE6uhwDUOG9gsFVNNxGxBQ7zy
    -sK8GKTQhfGPj8HQjolLe_9BL_VXgVkluBiUrdBKvgVi7KwsftAmzaDQA6QAU480SWSSXikQ_OZWFgwxOlaTanElMLFFvBhO-Gj-jZqqEFhV
    vVl4U7mOFcLW3Br1jngs0h7PKg5HU.IegL6XMQn_6bp6mbVNkAhQ

v0.81's forms, `{"kind":…,"name":…,"ns":…}` and a `range` of `[ns_id₁, ns_id₂]`, are no longer accepted.

## C.2 A view key and JWEs under it (§E.2.6)

An index on its own origin serves `demo` (epoch 3, private) to a reader who reads it whole, at §I.8's `gs` and `ns_id₂`, for the query `q` = `a b`, `sort` = `/title`. Its canonical query (§A.5) is `q=a%20b&sort=%2Ftitle`, so

    view = /demo/g/17i2rqzsv3o2i5vlfhsklo6fu22jnqwtm/at/1pa2nh6iw2yd2djqfy2wrszd5kglfpxvm?q=a%20b&sort=%2Ftitle

and, with `info` the view's ASCII bytes,

    HKDF-SHA256(K_n, "patchlog-view", view) = b604f0d131de493a9bd273088c546d4cad7a661bcf8c6eefa0f53de55956a6a5
    HKDF-SHA256(K_r, "patchlog-view", view) = 4a9740243099b77c664dee6d8e810508baf276d8b726ca0b338c98caa9ac6219

The whole response, sealed under the first with `kid` `demo#3`:

    header    = {"alg":"dir","enc":"A256GCM","kid":"demo#3","pl":{"ns":"demo","view":"/demo/g/17i2rqzsv3o2i5vlfhsklo6fu22jnqwtm/at/1pa2nh6iw2yd2djqfy2wrszd5kglfpxvm?q=a%20b&sort=%2Ftitle"}}
    plaintext = {"at":"1pa2nh6iw2yd2djqfy2wrszd5kglfpxvm","hits":[{"/title":["Hello"],"id":"1sywh54kpo3c4ezn2znktvl3avge4zl5d","resource":"derby","score":1.5,"url":"/r/demo/derby/rev/1sywh54kpo3c4ezn2znktvl3avge4zl5d"}]}

    eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwia2lkIjoiZGVtbyMzIiwicGwiOnsibnMiOiJkZW1vIiwidmlldyI6Ii9kZW1vL2cvMTdp
    MnJxenN2M28yaTV2bGZoc2tsbzZmdTIyam5xd3RtL2F0LzFwYTJuaDZpdzJ5ZDJkanFmeTJ3cnN6ZDVrZ2xmcHh2bT9xPWElMjBiJnNvcnQ9
    JTJGdGl0bGUifX0..wMHCw8TFxsfIycrL.nO43ZhkIEiGR3NCfbRCLfjjRIbvRIX_AFNyK1dXgQ-4J4eDZS4tRrQCt2kW_jVP2nMhMafAb6j
    6BNHHkEBvaY5Hmq_0mQXFmJrhMjwzUfElwoeWWLX2De9iy50VmHL1_e4LQMPDCR0y0Ni_zBGf8rv7p_T_3BByvcfPVo9ALIOzB6zzfim59Cj
    -Z9MH8PkFRicxYEUKTJlPZea1m86vtLdHO-hq4srTsX7UV8ubhjNlJel2Nk_lr40JiVwQzj48aE8ZJgiIGZqL5ddPf.0-ynJ3vYxufkyUSYG
    dbJsQ

padded tag `DxIZA9NfybrSZWZV4sjMpg`. The hit sealed per entry instead, under the second, with the hit's sealed values as plaintext:

    header    = {"alg":"dir","enc":"A256GCM","kid":"demo#3","pl":{"name":"derby","ns":"demo","view":"/demo/g/17i2rqzsv3o2i5vlfhsklo6fu22jnqwtm/at/1pa2nh6iw2yd2djqfy2wrszd5kglfpxvm?q=a%20b&sort=%2Ftitle"}}
    plaintext = {"/title":["Hello"],"score":1.5}

    eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwia2lkIjoiZGVtbyMzIiwicGwiOnsibmFtZSI6ImRlcmJ5IiwibnMiOiJkZW1vIiwidmll
    dyI6Ii9kZW1vL2cvMTdpMnJxenN2M28yaTV2bGZoc2tsbzZmdTIyam5xd3RtL2F0LzFwYTJuaDZpdzJ5ZDJkanFmeTJ3cnN6ZDVrZ2xmcHh2
    bT9xPWElMjBiJnNvcnQ9JTJGdGl0bGUifX0..wMHCw8TFxsfIycrL.TZJpva2ZV7PahdlmA_E0rJj0WDX9xRfnqBGhzj3GRJY.QtG0R9eNAA
    RRKqqGNvJIhg

padded tag `aI4EZpDID0edvKf5GA7Sxw`. The hit is then served as `{"id":"1sywh54kpo3c4ezn2znktvl3avge4zl5d","resource":"derby","sealed":"<that JWE>","url":"/r/demo/derby/rev/1sywh54kpo3c4ezn2znktvl3avge4zl5d"}`.

A JWE whose `pl.view` is the same target with `+` for the space, lowercase hex (`%2ftitle`) or the parameters in another order, or with a scheme and host, doesn't match the URL fetched, and the reader rejects it. No `view` has a `min`: a `200` is never served at a URL with one (§A.5).

## C.3 Bundle rejections (§G.4.1)

Each a change to §I.20's bundle, rejected whole (sha-256 of the bundle):

| Change | sha-256 | Rule |
|---|---|---|
| the grant line's `grant`, and both history lines', is `1d7hzis4zva7kl5aa3hi7cr3lxslua25j` (the id of §I.21's `ops-2027` root block) | `0ec81821b866aa5c02558212e4bb1b84640841cfba2457d594eab0730fb0bfcf` | a grant line whose `grant` isn't the id of its `root` |
| the grant line's `stored` is the authority block of §I.21's token whose root block string isn't canonical (`sub` first), validly signed | `027a5892e6e75752703a253d24a4b8e6bb4db92a91bb46fad0c95cb6035a2278` | a grant line whose `stored` block's `grant_block` isn't `canonical(root)` |
| the header with `"x-note":"hi"` | `eff926c75ff1a289375536562a090a02c1fabb11c921abfe43a5b95735548954` | a member §G.4.1 doesn't define |

## Underdetermined

- **§C.8, block versions.** The block `version` a conforming token carries isn't stated; §I.14 uses 3. A scope or public key needs Biscuit version 4 and a third-party block 5; §I.21 sets those.
- **§I.12's sealed-bundle envelope.** The ephemeral key of its `wrapped` isn't stated (its `enc` is none of the `xx xx+1 …` keys), so it can be checked only by opening it (it opens to `K_b`), not regenerated.
