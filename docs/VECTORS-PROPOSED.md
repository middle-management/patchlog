# Patch Log — proposed test vectors (unconfirmed candidates)

**Status: unconfirmed candidates**, computed independently from the v0.81 draft text (SPEC.md, TOOLS.md) for the items §I.15 lists, for the reference implementation to confirm. Nothing here is normative until it does.

Method: `patchlog-vectors-proposed.py` (Python stdlib + `cryptography`) first reproduces, byte for byte, the Addendum I vectors of every kind used below: §I.1 (canonical JSON, including the noncharacter genesis ids), §I.2 (ids, namespace chain), §I.3, §I.4 (grant id, signing digest, signature check), §I.6, §I.7 (`K_r` and `K_n`), §I.9, §I.10, §I.12 (thumbprints, all three HPKE ciphertexts, the `/principal` key; the sealed-bundle envelope by opening it, see Underdetermined), §I.13 (every JWE, tag and sealed blob, the grant under `K_n`) and §I.14 (the whole token, rebuilt from its protobuf with Biscuit's version 1 payloads, and both revocation ids). It aborts on any mismatch. Then it prints this file.

Conventions are Addendum I's: byte strings are hex unless marked, JSON is canonical (§3.1), and `g`, `c`, `patches₁`, `patches₂`, `ns_id₁`, `ns_id₂`, the grant id, `K_e`, `K_r`, `K_n` and keys are those of §I.2–§I.14. Every IV is `c0 c1 … cb`, as in §I.13 (a writer draws a fresh one per payload; vectors fix it). Timestamps are fixed inputs.

## P.1 Plan digests (§F.9)

`release` is `/r/{ns}/{name}/rev/{id}` (§F.9), here a revision of `/r/releases/release-7`, whose genesis document is

    {"branches":{"matches":{"at":"1pa2nh6iw2yd2djqfy2wrszd5kglfpxvm","ns":"matches-r7"}},"name":"release-7"}

(genesis id `1bx3m7usot3btfia44al7op7h4tbzwprh`, by §3.3 over a root `add`). `source.at` values are §I.2's `ns_id`s, used as inputs only. The digest is `text(trunc160(sha256(canonical(plan))))`.

Plan 1, one batch, one append:

    {"batches":[{"items":[{"ifMatch":"1l2gi2hhm3vt72ls2oufqpkqpsh6uvmll","resource":"derby","steps":[[{"op":"replace","path":"/views","value":1}]]}],"ns":"matches","source":{"at":"1pa2nh6iw2yd2djqfy2wrszd5kglfpxvm","ns":"matches-r7"}}],"release":"/r/releases/release-7/rev/1bx3m7usot3btfia44al7op7h4tbzwprh"}

digest `1pjgzny3luqmeyoud4lqoqh4qkmfazvmc`.

Plan 2, two batches in one namespace (as §F.9's steps 2 and 4 might be), with a config change, a delete, a create, a restore and preconditions on the first batch's results. As submitted, its items carry fresh nonces: `derby`'s first step starts with `add /$nonce "abcdefghijklmnopqrstuvwxyz"`, `final`'s root `add` value has `"$nonce":"zyxwvutsrqponmlkjihgfedcba"` (a root operation: an `add` or `replace` at `""`), and the restore of `derby` is just `replace /$nonce "zyxwvutsrqponmlkjihgfedcba"`. `semi`'s step adds a `$nonce` that isn't of the fresh form, which stays. The plan, with fresh nonces removed:

    {"batches":[{"config":{"ifMatch":"1l2gi2hhm3vt72ls2oufqpkqpsh6uvmll","patches":[{"op":"add","path":"/x-release","value":"release-7"}]},"items":[{"ifMatch":"1l2gi2hhm3vt72ls2oufqpkqpsh6uvmll","resource":"derby","steps":[[{"op":"replace","path":"/views","value":1}],"delete"]},{"ifNoneMatch":"*","resource":"final","steps":[[{"op":"add","path":"","value":{"title":"Final"}}]]}],"ns":"cat-season","source":{"at":"1vmctae4vewju6nvxi374rkrkmyzpdrif","ns":"cat-season-r7"}},{"config":{"ifMatch":{"batch":0},"patches":[{"op":"remove","path":"/x-release"}]},"items":[{"ifMatch":{"batch":0,"item":0},"resource":"derby","steps":[[]]},{"ifMatch":"1sywh54kpo3c4ezn2znktvl3avge4zl5d","resource":"semi","steps":[[{"op":"add","path":"/$nonce","value":"not-a-fresh-nonce"}]]}],"ns":"cat-season","source":{"at":"1vmctae4vewju6nvxi374rkrkmyzpdrif","ns":"cat-season-r7"}}],"release":"/r/releases/release-7/rev/1bx3m7usot3btfia44al7op7h4tbzwprh"}

digest `1gb5opshmkfmbtlbfl6r757kmn6ghg523`. Keeping the fresh-nonce ops in the plan gives `14cecare46eelmff7a4i5ozpsy34ibprk`, which is wrong.

## P.2 File renderings (§H.1)

Rendering as §I.10: the document without a top-level fresh `$nonce` and a top-level well-formed `$successor`, laid out from the canonical text. Lengths count the final LF.

`$successor` in the same namespace, well-formed, left out:

    {"$successor":"derby-2","title":"Old"}

renders as these 21 bytes (sha-256 `95c95285328c1d56eaf7e4dd8b1ba60c392bfaa53761355ccea198833ae5fe31`):

    {
      "title": "Old"
    }

`$successor` in another namespace, well-formed, left out:

    {"$successor":"/r/archive/derby","title":"Old"}

renders as these 21 bytes (sha-256 `95c95285328c1d56eaf7e4dd8b1ba60c392bfaa53761355ccea198833ae5fe31`):

    {
      "title": "Old"
    }

`$successor` not of the form of §8.1 (uppercase, so not a name), kept:

    {"$successor":"Derby-2","title":"Old"}

renders as these 48 bytes (sha-256 `04a1f8ba82d0d49bf9a8a149076965e8866a27f0b3df19f44bbb45c6746bb717`):

    {
      "$successor": "Derby-2",
      "title": "Old"
    }

`$nonce` not of the fresh form (uppercase), kept; a nested fresh one, kept:

    {"$nonce":"ABCDEFGHIJKLMNOPQRSTUVWXYZ","a":{"$nonce":"abcdefghijklmnopqrstuvwxyz"}}

renders as these 102 bytes (sha-256 `c67746c9019b8773dc1c558a3b9049db759c7a1fdb16b0aa6fa68d5b33026f0a`):

    {
      "$nonce": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
      "a": {
        "$nonce": "abcdefghijklmnopqrstuvwxyz"
      }
    }

`$nonce` of 25 characters, kept:

    {"$nonce":"abcdefghijklmnopqrstuvwxy","title":"x"}

renders as these 60 bytes (sha-256 `8bd15ae28c23567141a8a5fe4f34285c8d8e0e1a951ba1873abcef928fe76a78`):

    {
      "$nonce": "abcdefghijklmnopqrstuvwxy",
      "title": "x"
    }

Array root: nothing is left out:

    [{"$nonce":"abcdefghijklmnopqrstuvwxyz"},1,[],{}]

renders as these 72 bytes (sha-256 `d137603b109205bf00928b0a7464c301028cc2b06cdc4dce4b88442da439110a`):

    [
      {
        "$nonce": "abcdefghijklmnopqrstuvwxyz"
      },
      1,
      [],
      {}
    ]

Exponents:

    {"a":1e21,"b":1E-7,"c":-0.0000015,"d":123e-20,"e":1e300,"f":5e-324}

renders as these 96 bytes (sha-256 `ce6c041baed107608b8fa6cf79598a0ef01e43843a1ea631f46d91ede1507e04`):

    {
      "a": 1e+21,
      "b": 1e-7,
      "c": -0.0000015,
      "d": 1.23e-18,
      "e": 1e+300,
      "f": 5e-324
    }

## P.3 Sealed bundles (§G.5.1.1)

§I.12's envelope (`id` `auZ4P0-96RtuuItzpI7SRw`, `K_b` `dbe5…6db7`, to the recipient `20 21 … 3f`) seals §I.9's two bundle lines. Line headers:

    line 0: {"alg":"dir","enc":"A256GCM","pl":{"bundle":"auZ4P0-96RtuuItzpI7SRw","line":0}}
    line 1: {"alg":"dir","enc":"A256GCM","pl":{"bundle":"auZ4P0-96RtuuItzpI7SRw","last":true,"line":1}}

The sealed bundle is these three lines, each followed by one `0a` (907 bytes, sha-256 `30bf22f88eb79ccd830d8b5da982a493c9e67b694b3e51a9344934df2dab03a6`):

    {"id":"auZ4P0-96RtuuItzpI7SRw","recipients":[{"kid":"5_RYhfysTyU1BDBnv9LSpAGNHJ_A1_UesBCKoRG370E","suite":"hpke-base-0x0020-0x0001-0x0002","wrapped":"qOEsrFfQ5Y0IhiuiliORWAQzhGlJcMKuQw90ZdV851fEb8UlPgrdP1U8de6PBjNaodTtMiXXXGFcMBEQ3tDUBPy8Q4SkD88eVuu5cHhiB_U"}],"sealedBundle":1}
    eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwicGwiOnsiYnVuZGxlIjoiYXVaNFAwLTk2UnR1dUl0enBJN1NSdyIsImxpbmUiOjB9fQ..wMHCw8TFxsfIycrL.1je8Ze50PqpSOnyuJwmJlIP8Qgp7AuYU2GSMaaqzoFIh-4aQi9zKQGzhopNkHzYN91K1O4uc3tJh32F1FTwu.g-aBsut25PYodIaP85FSPw
    eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwicGwiOnsiYnVuZGxlIjoiYXVaNFAwLTk2UnR1dUl0enBJN1NSdyIsImxhc3QiOnRydWUsImxpbmUiOjF9fQ..wMHCw8TFxsfIycrL.1je0dLgmc-lNKiGhdA2SnJyoVEgnCvlDlSvbNPi3o0s1-t7Hx5POWDq988IiXiFbrBeuMJqQl4huwTMjUnMy2CYHLfAELI95X8VtxLxfpJMMpES9jJl0DIbYOCd6ih8heQ10_mx9EOtrimNVaUv9I9Yavipi5HZsrDC5MsmPzGC7fDw4O8hjjG-2I2QNSCEixHnaCo2EsE1pE6dmBuN1Dt9CnMc9R4gx_WX-7g.kFkKVIEefyfbKVXBCsNtCQ

It decrypts to §I.9's bundle, so `source.bundle` is `1b3a64kkqf3o6f3rglkgi6ok5hgldbne6`; the digest of the sealed bytes, `1gc7sf6eow6om3aynrno2tavespe6m63j`, is not it.

Rejected, each a change to the bundle above (the whole sealed bundle is refused):

| Change | Bytes | sha-256 of the file | Rule |
|--------|-------|---------------------|------|
| line 1's header with `pl` members out of order (non-canonical): `{"alg":"dir","enc":"A256GCM","pl":{"bundle":"auZ4P0-96RtuuItzpI7SRw","line":1,"last":true}}` | line 1 is `eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwicGwiOnsiYnVuZGxlIjoiYXVaNFAwLTk2UnR1dUl0enBJN1NSdyIsImxpbmUiOjEsImxhc3QiOnRydWV9fQ..wMHCw8TFxsfIycrL.1je0dLgmc-lNKiGhdA2SnJyoVEgnCvlDlSvbNPi3o0s1-t7Hx5POWDq988IiXiFbrBeuMJqQl4huwTMjUnMy2CYHLfAELI95X8VtxLxfpJMMpES9jJl0DIbYOCd6ih8heQ10_mx9EOtrimNVaUv9I9Yavipi5HZsrDC5MsmPzGC7fDw4O8hjjG-2I2QNSCEixHnaCo2EsE1pE6dmBuN1Dt9CnMc9R4gx_WX-7g.4YIyOP9alxqDJtbQg02UCw` | `ea43aecec4ac64b816582fa621489ed53fa706d21c45669f366f49657ab5f80a` | header isn't canonical JSON |
| line 1's header with a space after `"pl":` (non-canonical) | header `7b22616c67223a22646972222c22656e63223a224132353647434d222c22706c223a207b2262756e646c65223a2261755a3450302d39365274757549747a704937535277222c226c617374223a747275652c226c696e65223a317d7d` | `2ee9369a6be54795328003bf8e65adcab0ede3515f3499582194c9e52b3f3d59` | header isn't canonical JSON |
| line 1's `pl` with another member, `"ns":"matches"` | line 1 is `eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwicGwiOnsiYnVuZGxlIjoiYXVaNFAwLTk2UnR1dUl0enBJN1NSdyIsImxhc3QiOnRydWUsImxpbmUiOjEsIm5zIjoibWF0Y2hlcyJ9fQ..wMHCw8TFxsfIycrL.1je0dLgmc-lNKiGhdA2SnJyoVEgnCvlDlSvbNPi3o0s1-t7Hx5POWDq988IiXiFbrBeuMJqQl4huwTMjUnMy2CYHLfAELI95X8VtxLxfpJMMpES9jJl0DIbYOCd6ih8heQ10_mx9EOtrimNVaUv9I9Yavipi5HZsrDC5MsmPzGC7fDw4O8hjjG-2I2QNSCEixHnaCo2EsE1pE6dmBuN1Dt9CnMc9R4gx_WX-7g.uXIagADPGdAhtyvJu_gM-A` | `c792cad748b02c609caca285c03f0814643fe9525bda726a8b25297eedf33736` | header or pl has other members |
| line 1's `pl.bundle` is `AAAAAAAAAAAAAAAAAAAAAA` | line 1 is `eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwicGwiOnsiYnVuZGxlIjoiQUFBQUFBQUFBQUFBQUFBQUFBQUFBQSIsImxhc3QiOnRydWUsImxpbmUiOjF9fQ..wMHCw8TFxsfIycrL.1je0dLgmc-lNKiGhdA2SnJyoVEgnCvlDlSvbNPi3o0s1-t7Hx5POWDq988IiXiFbrBeuMJqQl4huwTMjUnMy2CYHLfAELI95X8VtxLxfpJMMpES9jJl0DIbYOCd6ih8heQ10_mx9EOtrimNVaUv9I9Yavipi5HZsrDC5MsmPzGC7fDw4O8hjjG-2I2QNSCEixHnaCo2EsE1pE6dmBuN1Dt9CnMc9R4gx_WX-7g.iQCJP5a5SFxVycF18eYiVg` | `d5d714e391d92b6c8086d23fc9aaaf1520674bd91a3eb9d0bb80132c9b471a31` | pl.bundle differs from id |
| line 1 numbered 2 | line 1 is `eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwicGwiOnsiYnVuZGxlIjoiYXVaNFAwLTk2UnR1dUl0enBJN1NSdyIsImxhc3QiOnRydWUsImxpbmUiOjJ9fQ..wMHCw8TFxsfIycrL.1je0dLgmc-lNKiGhdA2SnJyoVEgnCvlDlSvbNPi3o0s1-t7Hx5POWDq988IiXiFbrBeuMJqQl4huwTMjUnMy2CYHLfAELI95X8VtxLxfpJMMpES9jJl0DIbYOCd6ih8heQ10_mx9EOtrimNVaUv9I9Yavipi5HZsrDC5MsmPzGC7fDw4O8hjjG-2I2QNSCEixHnaCo2EsE1pE6dmBuN1Dt9CnMc9R4gx_WX-7g.mwWoQV9HxFtw7D5isf-Cgw` | `c99ee90c9ca07c6621149b670cd8a0392433d39fb898dc904d7b2c55f8291464` | line numbers not 0, 1, 2… in order |
| no line says `last` (line 1 without it) | line 1 is `eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwicGwiOnsiYnVuZGxlIjoiYXVaNFAwLTk2UnR1dUl0enBJN1NSdyIsImxpbmUiOjF9fQ..wMHCw8TFxsfIycrL.1je0dLgmc-lNKiGhdA2SnJyoVEgnCvlDlSvbNPi3o0s1-t7Hx5POWDq988IiXiFbrBeuMJqQl4huwTMjUnMy2CYHLfAELI95X8VtxLxfpJMMpES9jJl0DIbYOCd6ih8heQ10_mx9EOtrimNVaUv9I9Yavipi5HZsrDC5MsmPzGC7fDw4O8hjjG-2I2QNSCEixHnaCo2EsE1pE6dmBuN1Dt9CnMc9R4gx_WX-7g.zJJLhqznyED1wpuSl5sA3Q` | `568f5b379c76ca5b14d1462260223d8790377e85edd7831b877b47f9828f0d52` | no line says last |
| line 0 says `last`, and line 1 follows it | line 0 is `eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwicGwiOnsiYnVuZGxlIjoiYXVaNFAwLTk2UnR1dUl0enBJN1NSdyIsImxhc3QiOnRydWUsImxpbmUiOjB9fQ..wMHCw8TFxsfIycrL.1je8Ze50PqpSOnyuJwmJlIP8Qgp7AuYU2GSMaaqzoFIh-4aQi9zKQGzhopNkHzYN91K1O4uc3tJh32F1FTwu.fKxlr27E5hHkieH2xIkLdw` | `c389d152c50071d34d49c8a731c7f0dbbd65ba0fb47995c435cf6acba7f2d822` | a line follows the one that says last |
| `0d 0a` after the envelope line | `…7d0d0a` at offset 277 | `1e790de0fce6a5b140cbc2cec3a1c11c35ed1d71b37c1a38df8e5f0484945b40` | a 0x0D: a line not followed by exactly one 0x0A |
| `0d 0a` after the last line | the file ends `…4e7443510d0a` | `4d80d21eaf4a5a972d4489a3c8a0cc7877a387269fc6b46f05dd2e7e3fd6f561` | a 0x0D: a line not followed by exactly one 0x0A |
| the last line without its `0a` | the file ends `…4e744351` | `bb48a88d8a72e71a812c1f709da4646578b7842794c0747706d811fc2bb2201d` | last line lacks its 0x0A |
| a blank line after the last | the file ends `…4e7443510a0a` | `ce77fe793cc9f5e8005805ffe434659dc3939f61e15d65daf6de48f491bacf96` | blank line |
| line 1's tag with its last character changed | line 1 ends `…CsNtCB` | `55482215c25c2d182283c29511966dff78c1125249b63a91f3cefab96aec6124` | line fails to decrypt |

§G.5.1.1 says padding MAY be applied and is removed before the checks; these lines are unpadded.

## P.4 `hostname` and `idn-hostname` (§6.2 step 5)

Instances validated under `{"format":"hostname"}` and `{"format":"idn-hostname"}` (draft 2020-12, format assertions on). Instances are shown as canonical JSON with their UTF-8 bytes.

| Instance | Bytes | `hostname` | `idn-hostname` | Why |
|---|---|---|---|---|
| `"ab--cd"` | `2261622d2d636422` | accept | `422` | RFC 1123 allows hyphens anywhere inside a label; as an IDN label it is R-LDH (`--` in positions 3–4) without the `xn--` prefix, so not an A-label |
| `"·"` | `22c2b722` | `422` | `422` | U+00B7 is CONTEXTO: RFC 5892 A.3 needs `l` before and after it; not LDH for `hostname` |
| `"XN--BCHER-KVA"` | `22584e2d2d42434845522d4b564122` | accept | accept | an uppercase A-label: LDH for `hostname`; for `idn-hostname`, `xn--` matched case-insensitively, decodes to `bücher` and re-encodes to the same label ignoring case |
| `"l·l"` | `226cc2b76c22` | `422` | accept | control: U+00B7 between two `l`s satisfies its CONTEXTO rule |
| `"xn--bcher-kva"` | `22786e2d2d62636865722d6b766122` | accept | accept | control: the lowercase A-label |

The `idna` package (IDNA 2008, which also has no UTS 46 mapping by default) gives the same `idn-hostname` verdicts.

## P.5 Sealed log entries, events, namespace documents and log ranges (§E.2.2)

With §I.7's keys, `kid` `demo#3`, and these plaintexts, canonical as §E.2.2 says: whole §7.1 entries, `parent` `""` for the genesis; §7.4 entries, `prev` `""` for the chain's first; a range's plaintext the array of its entries, `[]` for an empty page; an event's its one entry. The grant reference is `{"id":"15swdvi5nbnlkv76v7y6k77h52atov6ru","kid":"ops-2026","sub":"user:bob"}`, and `via` `["svc:translator"]` an input. Namespace documents, ranges and events are sealed under `K_n`:

    entry_g  = {"author":"user:bob","created":"2026-10-04T12:00:00.000Z","grant":{"id":"15swdvi5nbnlkv76v7y6k77h52atov6ru","kid":"ops-2026","sub":"user:bob"},"id":"1l2gi2hhm3vt72ls2oufqpkqpsh6uvmll","kind":"rev","parent":"","patches":[{"op":"add","path":"","value":{"title":"Hello","views":0}}]}
    entry_c  = {"author":"user:bob","created":"2026-10-04T12:05:00.000Z","grant":{"id":"15swdvi5nbnlkv76v7y6k77h52atov6ru","kid":"ops-2026","sub":"user:bob"},"id":"1sywh54kpo3c4ezn2znktvl3avge4zl5d","kind":"rev","parent":"1l2gi2hhm3vt72ls2oufqpkqpsh6uvmll","patches":[{"op":"replace","path":"/views","value":1}],"via":["svc:translator"]}
    entry_t  = {"author":"user:bob","created":"2026-10-04T12:10:00.000Z","grant":{"id":"15swdvi5nbnlkv76v7y6k77h52atov6ru","kid":"ops-2026","sub":"user:bob"},"id":"1idx6u2b3z42obqmwsgmlzvrfuutks2bq","kind":"tombstone","parent":"1sywh54kpo3c4ezn2znktvl3avge4zl5d"}
    purge    = {"author":"user:bob","created":"2026-10-04T13:00:00.000Z","grant":{"id":"15swdvi5nbnlkv76v7y6k77h52atov6ru","kid":"ops-2026","sub":"user:bob"},"kind":"purge","resource":"derby","target":"1idx6u2b3z42obqmwsgmlzvrfuutks2bq"}
    prune    = {"author":"user:bob","created":"2026-10-04T13:00:00.000Z","grant":{"id":"15swdvi5nbnlkv76v7y6k77h52atov6ru","kid":"ops-2026","sub":"user:bob"},"kind":"prune","resource":"derby","target":"1sywh54kpo3c4ezn2znktvl3avge4zl5d"}
    nsdoc    = {"encryption":{"epoch":3,"level":"sealed"},"keys":[{"alg":"Ed25519","can":["*"],"kid":"ops-2026","pub":"A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg"}],"read":"public"}
    nsentry₁ = {"author":"user:bob","created":"2026-10-04T11:00:00.000Z","grant":{"id":"15swdvi5nbnlkv76v7y6k77h52atov6ru","kid":"ops-2026","sub":"user:bob"},"id":"1vmctae4vewju6nvxi374rkrkmyzpdrif","kind":"config","prev":"","target":"1l2gi2hhm3vt72ls2oufqpkqpsh6uvmll"}
    nsentry₂ = {"author":"user:bob","created":"2026-10-04T12:00:00.000Z","grant":{"id":"15swdvi5nbnlkv76v7y6k77h52atov6ru","kid":"ops-2026","sub":"user:bob"},"id":"1pa2nh6iw2yd2djqfy2wrszd5kglfpxvm","kind":"head","prev":"1vmctae4vewju6nvxi374rkrkmyzpdrif","resource":"derby","target":"1l2gi2hhm3vt72ls2oufqpkqpsh6uvmll"}

`nsentry₁` and `nsentry₂` rehash to §I.2's `ns_id₁` and `ns_id₂`. The `purge` and `prune` events are their namespace entries without `id` and `prev` (§7.3).

| Payload | Key | `pl` | Plaintext | Unpadded tag | Padded tag |
|---|---|---|---|---|---|
| resource log entry of `g` (`rev`) | `K_r` | `{"id":"1l2gi2hhm3vt72ls2oufqpkqpsh6uvmll","kind":"rev","name":"derby","ns":"demo"}` | `entry_g` | `c68oZCDNfPm8VZUXOdRmXg` | `O9Z6SEotAUWkOeYCYpo_Dg` |
| resource log entry of `c` (`rev`, with `via`) | `K_r` | `{"id":"1sywh54kpo3c4ezn2znktvl3avge4zl5d","kind":"rev","name":"derby","ns":"demo"}` | `entry_c` | `pzkHTSbEc_4DelqyHdgd3w` | `eBSxsbW5-2SOW6qeTsv9Rg` |
| resource log entry of the tombstone of `c` | `K_r` | `{"id":"1idx6u2b3z42obqmwsgmlzvrfuutks2bq","kind":"tombstone","name":"derby","ns":"demo"}` | `entry_t` | `qM0CXrHt-MBnP2Mge7t9Dg` | `IDqEgk-5WA7hlci08qsYIA` |
| `purge` event | `K_r` | `{"kind":"purge","name":"derby","ns":"demo"}` | `purge` | `2Lr0YlsnReKv3Vu1vzww6w` | `o6qg_FLKKyVd-bUUDCd0WA` |
| `prune` event (horizon `c`) | `K_r` | `{"kind":"prune","name":"derby","ns":"demo"}` | `prune` | `DQW969cxsNvKvMFoLcdwHw` | `UqL8Ockwt491woTRn4ov6w` |
| namespace document at `ns_id₁` | `K_n` | `{"id":"1vmctae4vewju6nvxi374rkrkmyzpdrif","kind":"doc","ns":"demo"}` | `nsdoc` | `g9GNuYsEUxQIUflrD4Pgrg` | `y3m-vOgPYKJ_ng0H3nB7WA` |
| namespace log range from the start to `ns_id₂` | `K_n` | `{"ns":"demo","range":["","1pa2nh6iw2yd2djqfy2wrszd5kglfpxvm"]}` | `[nsentry₁,nsentry₂]` | `3CUwPfA7GtS8GLr7bQFbuQ` | `iwW5mt5KJ1sbvzneqrT6PA` |
| namespace log range, empty page (`since` `ns_id₂`) | `K_n` | `{"ns":"demo","range":["1pa2nh6iw2yd2djqfy2wrszd5kglfpxvm","1pa2nh6iw2yd2djqfy2wrszd5kglfpxvm"]}` | `[]` | `gFdn5cMoLtKWpkGcZKvRcg` | `81hR8mEqKtouAa1XtJCNqQ` |
| namespace event for `ns_id₂`, a range of its one entry | `K_n` | `{"ns":"demo","range":["1vmctae4vewju6nvxi374rkrkmyzpdrif","1pa2nh6iw2yd2djqfy2wrszd5kglfpxvm"]}` | `nsentry₂` | `yXiFzJA38ZWcmOAZrHWjWA` | `J4Xez2kCZ77d31D4iD6GgQ` |

In full, the first and the last:

    eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwia2lkIjoiZGVtbyMzIiwicGwiOnsiaWQiOiIxbDJnaTJoaG0zdnQ3MmxzMm91ZnFwa3Fwc2g2dXZtbGwiLCJraW5kIjoicmV2IiwibmFtZSI6ImRlcmJ5IiwibnMiOiJkZW1vIn19..wMHCw8TFxsfIycrL.k52_TNJoKtTgS-F18LbSvzC1Wzjpp2eMwwcxR9zeeocp7wTUg2d8tmhTnhTJQIzPSDZ3L_56yorXqCMuKVryC2uCMTHSKs2gMEkixDYnnTk1FVrSMeITi6lXwuziocVQmYJ0IrVjF7l3gGRRLU8VEmtD6Wquc9UCadJw0FttGapmaGPPxQQfwcvFebUPbTW7WDvhqml64ZXzz4r4rCmR9cV3WSsig-gbzfAyF-opZJPTRIvjSmBTKkutRh1tLiHpkwWvjwh_T40DWhE-9oG7-VezKc626mN7tdslpVrd7yawDpeAy2IYh2ph2UXPYFC8WIdEJ6h6LfjaerYclaLAjFQBwxCMGYMkzdVN76fUFy4_ID8S5cFLPQ.c68oZCDNfPm8VZUXOdRmXg

    eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwia2lkIjoiZGVtbyMzIiwicGwiOnsibnMiOiJkZW1vIiwicmFuZ2UiOlsiMXZtY3RhZTR2ZXdqdTZudnhpMzc0cmtya215enBkcmlmIiwiMXBhMm5oNml3MnlkMmRqcWZ5Mndyc3pkNWtnbGZweHZtIl19fQ..wMHCw8TFxsfIycrL.u8c251n3WG3uDvexX6uwqBTPKeBvMQlL6b6hdn6BXzGasJsQYlzR2iRxzmt6VvZnsT23l0wx0KocOYbmfx5u4j-_DQ2xvuhBRCpvZdadGJoEhHO6FLSfwwSaX5egIQARrBBTZhH59ABtgAByLNLCl2cC0zdgCD3pmcnL3myyHmW8yaZ9F4RPBKS2IfqEh_aB-24mj6LA_qpnyYuKX00RfNsEhfpHqjcOjWbhoDTEtkSho4uTVjf1EIE6uhwDUOG9gsFVNNxGxBQ7zy-sK8GKTQhfGPj8HQjolLe_9BL_VXgVkluBiUrdBKvgVi7KwsftAmzaDQA6QAU480SWSSXikQ_OZWFgwxOlaTanElMLFFvBhO-Gj-jZqqEFhVvVl4U7mOFcLW3Br1jngs0h7PKg5HU.yXiFzJA38ZWcmOAZrHWjWA

A resource log range from genesis to `c` is the canonical JSON array of the first two JWEs, `["<entry_g's JWE>","<entry_c's JWE>"]`, served as `application/json`.
That array is 1247 bytes, sha-256 `a1cfeddee66cfb678d2a7fc5f9eaf11666dd1353b43295f16554963fcd78a433`.

## P.6 Full-history lines with `via` (§G.4.1)

A bundle with `"authors": true` exporting `matches/derby` in full (`g`, then `c`), `c` written by a delegatee. The grant is §I.4's root block, and `stored` is the authority block of §I.14's token (the `stored` of §I.13's grant payload); `via` comes from a narrowing block, which `stored` doesn't keep, so any token with that authority block has these lines. `key` is the root key of §I.14, attested. The four lines, each followed by one `0a`:

    {"access":{"matches":"private"},"at":{"matches":"1pa2nh6iw2yd2djqfy2wrszd5kglfpxvm"},"authors":true,"bundle":1,"created":"2026-10-04T14:00:00Z","docs":{"matches/derby":{"head":"1sywh54kpo3c4ezn2znktvl3avge4zl5d","history":"full"}},"origin":"https://staging.example"}
    {"grant":"15swdvi5nbnlkv76v7y6k77h52atov6ru","key":{"alg":"Ed25519","kid":"ops-2026","pub":"A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg"},"ns":"matches","root":{"can":["read","append"],"exp":"2026-10-05T00:00:00Z","groups":["match-desk"],"kid":"ops-2026","ns":["matches"],"rules":[],"sub":"user:bob"},"stored":"CqoBCgtncmFudF9ibG9jawqMAXsiY2FuIjpbInJlYWQiLCJhcHBlbmQiXSwiZXhwIjoiMjAyNi0xMC0wNVQwMDowMDowMFoiLCJncm91cHMiOlsibWF0Y2gtZGVzayJdLCJraWQiOiJvcHMtMjAyNiIsIm5zIjpbIm1hdGNoZXMiXSwicnVsZXMiOltdLCJzdWIiOiJ1c2VyOmJvYiJ9GAMiCgoICIAIEgMYgQgSJAgAEiAlQ7kv8QlVEUdq3INp223ckzZloRl43aFATuEGbKlVnRpAWgaUHLoFLrXYHs2MaIetUEXWGK0SK3h0v5xBRUsBNE2qQ14tB8LGmoIYtimpZPta1sYSQLSXob_gozBFMAKwBCgB"}
    {"author":"user:bob","created":"2026-10-04T12:00:00.000Z","grant":"15swdvi5nbnlkv76v7y6k77h52atov6ru","id":"1l2gi2hhm3vt72ls2oufqpkqpsh6uvmll","kind":"rev","ns":"matches","parent":"","patches":[{"op":"add","path":"","value":{"title":"Hello","views":0}}],"resource":"derby"}
    {"author":"user:bob","created":"2026-10-04T12:05:00.000Z","grant":"15swdvi5nbnlkv76v7y6k77h52atov6ru","id":"1sywh54kpo3c4ezn2znktvl3avge4zl5d","kind":"rev","ns":"matches","parent":"1l2gi2hhm3vt72ls2oufqpkqpsh6uvmll","patches":[{"op":"replace","path":"/views","value":1}],"resource":"derby","via":["svc:translator"]}

1543 bytes, digest `1hywrrzishsfdu5qs4tinxvnb3rs2tcv5`. Both ids recompute, the grant id is over `root`, `stored`'s one `grant_block` string is `canonical(root)` and its signature verifies under `key.pub`.

Rejected: the same bundle without the grant line (a line naming a grant with no earlier grant line; sha-256 `5d0f3f9233e8681d63ffdcb4659049f0c7617bff5eeb1c2ecf3f4d5fe82b2bfc`), and with `"authors":false` in the header (a grant line in a bundle without `"authors": true`; sha-256 `71b8a5ad487898f1b63aaf3aaabc4cc5009328818d2d1c47ee6fbc037660f95a`).

Without authorship: the header with `"authors":false` and both history lines without `author`, `via`, `grant`, `signature`, `created`, `gesture` and `undoes`, no grant line, is accepted (631 bytes, digest `1wmmkh2s4kkveocf5yh4uzoookxmrzptr`). The same with `c`'s line keeping `"via":["svc:translator"]` is rejected whole (a history line with an authorship member in a bundle without `"authors": true`; sha-256 `0721b8e6915c6921de2650a7f2d26732c5426ab6faf5be5a421b64ed711ea18e`):

    {"access":{"matches":"private"},"at":{"matches":"1pa2nh6iw2yd2djqfy2wrszd5kglfpxvm"},"authors":false,"bundle":1,"created":"2026-10-04T14:00:00Z","docs":{"matches/derby":{"head":"1sywh54kpo3c4ezn2znktvl3avge4zl5d","history":"full"}},"origin":"https://staging.example"}
    {"id":"1l2gi2hhm3vt72ls2oufqpkqpsh6uvmll","kind":"rev","ns":"matches","parent":"","patches":[{"op":"add","path":"","value":{"title":"Hello","views":0}}],"resource":"derby"}
    {"id":"1sywh54kpo3c4ezn2znktvl3avge4zl5d","kind":"rev","ns":"matches","parent":"1l2gi2hhm3vt72ls2oufqpkqpsh6uvmll","patches":[{"op":"replace","path":"/views","value":1}],"resource":"derby","via":["svc:translator"]}

## P.7 Biscuit tokens failing §C.8

Each token is §I.14's with one change, built with the same keys (root seed `00 01 … 1f`, next keys `40 41 … 5f` and `60 61 … 7f`, the last as the proof) and Biscuit's version 1 payloads unless stated; a changed authority block shifts the narrowing block's string symbol to the next free index. Each is `401` (§C.8). "Biscuit library" is biscuit-python 0.4's verdict on the signature chain alone, to show that only Patch Log's rule refuses the token where it says *verifies*.

**Authority block with a second fact, `other("x")`.** Rule: a block with other facts. Biscuit library: verifies.

    Eq0CCsABCgtncmFudF9ibG9jawqMAXsiY2FuIjpbInJlYWQiLCJhcHBlbmQiXSwiZXhwIjoiMjAyNi0xMC0wNVQwMDowMDowMFoiLCJncm91
    cHMiOlsibWF0Y2gtZGVzayJdLCJraWQiOiJvcHMtMjAyNiIsIm5zIjpbIm1hdGNoZXMiXSwicnVsZXMiOltdLCJzdWIiOiJ1c2VyOmJvYiJ9
    CgVvdGhlcgoBeBgDIgoKCAiACBIDGIEIIgoKCAiCCBIDGIMIEiQIABIgJUO5L_EJVRFHatyDadtt3JM2ZaEZeN2hQE7hBmypVZ0aQEl7OJMN
    mq894Ni30iWMke5cJ2OqiI5RA1fzkgw21X8klE_8_3reMOmR2k_MGsxYK4Bk-H0efPf3oD5coDCY2QMoARqfAQozCiN7ImNhbiI6WyJyZWFk
    Il0sInZpYSI6InN2YzpyZWFkZXIifRgDIgoKCAiACBIDGIQIEiQIABIgF0VTtFbd38aQjsqxwQH-arIeK6oGF3lbfUOmNIKZP9UaQCnsv-5R
    KUfz0GfMcWyyUR9AQAzbAbR0dMCVcCMEEAG5h-VUhEoOdyLnHYdCP8KSmtszEiXDCFmUSjVQYzyzIgkoASIiCiBgYWJjZGVmZ2hpamtsbW5v
    cHFyc3R1dnd4eXp7fH1-fw

**Authority block with a rule, `r($x) <- grant_block($x)`.** Rule: a block with rules. Biscuit library: verifies.

    ErMCCsYBCgtncmFudF9ibG9jawqMAXsiY2FuIjpbInJlYWQiLCJhcHBlbmQiXSwiZXhwIjoiMjAyNi0xMC0wNVQwMDowMDowMFoiLCJncm91
    cHMiOlsibWF0Y2gtZGVzayJdLCJraWQiOiJvcHMtMjAyNiIsIm5zIjpbIm1hdGNoZXMiXSwicnVsZXMiOltdLCJzdWIiOiJ1c2VyOmJvYiJ9
    CgFyCgF4GAMiCgoICIAIEgMYgQgqFAoICIIIEgMIgwgSCAiACBIDCIMIEiQIABIgJUO5L_EJVRFHatyDadtt3JM2ZaEZeN2hQE7hBmypVZ0a
    QEMeFlIWVhD2Mtcln82NbVdrUASHXczfAbe6BXbNL-ckjiXV9DLdJoQJ0krlHDLOcuswj2ybY1-rZyTd0EwQYwEoARqfAQozCiN7ImNhbiI6
    WyJyZWFkIl0sInZpYSI6InN2YzpyZWFkZXIifRgDIgoKCAiACBIDGIQIEiQIABIgF0VTtFbd38aQjsqxwQH-arIeK6oGF3lbfUOmNIKZP9Ua
    QHUztUGasSvrO7Suj4TG5Di4dlZ0CwHYkDRcLbNbo7Ic4R1nnfc-DgZWMoDVsns4AbFfexyrRKsMabEAhK26uwkoASIiCiBgYWJjZGVmZ2hp
    amtsbW5vcHFyc3R1dnd4eXp7fH1-fw

**Authority block with a check, `check if grant_block($x)`.** Rule: a block with checks. Biscuit library: verifies.

    EqwCCr8BCgtncmFudF9ibG9jawqMAXsiY2FuIjpbInJlYWQiLCJhcHBlbmQiXSwiZXhwIjoiMjAyNi0xMC0wNVQwMDowMDowMFoiLCJncm91
    cHMiOlsibWF0Y2gtZGVzayJdLCJraWQiOiJvcHMtMjAyNiIsIm5zIjpbIm1hdGNoZXMiXSwicnVsZXMiOltdLCJzdWIiOiJ1c2VyOmJvYiJ9
    CgF4GAMiCgoICIAIEgMYgQgyEAoOCgIIGxIICIAIEgMIgggSJAgAEiAlQ7kv8QlVEUdq3INp223ckzZloRl43aFATuEGbKlVnRpAR1-NRajf
    ujomdVRR4Y7NEys6r2hBj27PmGzcByaALHhXdUPyl3STVkPivhgE9-X9YMP1tDCRiHSL7PccL97aCSgBGp8BCjMKI3siY2FuIjpbInJlYWQi
    XSwidmlhIjoic3ZjOnJlYWRlciJ9GAMiCgoICIAIEgMYgwgSJAgAEiAXRVO0Vt3fxpCOyrHBAf5qsh4rqgYXeVt9Q6Y0gpk_1RpAuDzGw1w6
    nvkKUnXJwODHwG0Txr4xMtmWR5jkVbm9dW6HJXkzPSFugR6_qP0d0oM6h8GgrjTcocmRhTV9TgZBBigBIiIKIGBhYmNkZWZnaGlqa2xtbm9w
    cXJzdHV2d3h5ent8fX5_

**Authority block with a block scope (`scope` = `previous`, field 7), block version 4.** Rule: a block with scopes. Biscuit library: verifies.

    EpsCCq4BCgtncmFudF9ibG9jawqMAXsiY2FuIjpbInJlYWQiLCJhcHBlbmQiXSwiZXhwIjoiMjAyNi0xMC0wNVQwMDowMDowMFoiLCJncm91
    cHMiOlsibWF0Y2gtZGVzayJdLCJraWQiOiJvcHMtMjAyNiIsIm5zIjpbIm1hdGNoZXMiXSwicnVsZXMiOltdLCJzdWIiOiJ1c2VyOmJvYiJ9
    GAQiCgoICIAIEgMYgQg6AggBEiQIABIgJUO5L_EJVRFHatyDadtt3JM2ZaEZeN2hQE7hBmypVZ0aQCPImRRGP2qQCBEvD5UGJjcOC4U6XgOr
    cDpuBHq0wKgnZTnmeZ5ZhKYTOuNMh2hkDKHi5NyYLjZg7qwnw-rZ5QwoARqfAQozCiN7ImNhbiI6WyJyZWFkIl0sInZpYSI6InN2YzpyZWFk
    ZXIifRgDIgoKCAiACBIDGIIIEiQIABIgF0VTtFbd38aQjsqxwQH-arIeK6oGF3lbfUOmNIKZP9UaQDniuBfVIBOgnCxj2ylpuYG6c3iWjnOi
    ZZoXyNGhTSDLHPAlxlFinctu8ojYx5olBu9SItvPqqjzoD0WcXWx2w4oASIiCiBgYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXp7fH1-fw

**Authority block with a public key (field 8, the Ed25519 key of seed `80 81 … 9f`), block version 4.** Rule: a block with public keys. Biscuit library: verifies.

    Er0CCtABCgtncmFudF9ibG9jawqMAXsiY2FuIjpbInJlYWQiLCJhcHBlbmQiXSwiZXhwIjoiMjAyNi0xMC0wNVQwMDowMDowMFoiLCJncm91
    cHMiOlsibWF0Y2gtZGVzayJdLCJraWQiOiJvcHMtMjAyNiIsIm5zIjpbIm1hdGNoZXMiXSwicnVsZXMiOltdLCJzdWIiOiJ1c2VyOmJvYiJ9
    GAQiCgoICIAIEgMYgQhCJAgAEiDNFLN_lW6VMZT_f7c7PYHcxWHWGnU4CUt8PhpkPuXzqhIkCAASICVDuS_xCVURR2rcg2nbbdyTNmWhGXjd
    oUBO4QZsqVWdGkByv1Hig7-CrVs2aXKwUSJGYV0hZsZbaehLhuUC8F6jtzvMjjZN7z84L-sHbAmV7qw77Vpwrgmq2Fsi2rY3hf0BKAEanwEK
    MwojeyJjYW4iOlsicmVhZCJdLCJ2aWEiOiJzdmM6cmVhZGVyIn0YAyIKCggIgAgSAxiCCBIkCAASIBdFU7RW3d_GkI7KscEB_mqyHiuqBhd5
    W31DpjSCmT_VGkA4kg3TCo-O4gUJ5XiGUJf3JuP7ZY-84tILst34mtgIENMEG5R2eWad-hVFgGG-aGSRgDj7DB3t2qQSrpb5W-wPKAEiIgog
    YGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn8

**Authority block with context `"x"`.** Rule: a non-empty context. Biscuit library: verifies.

    EpoCCq0BCgtncmFudF9ibG9jawqMAXsiY2FuIjpbInJlYWQiLCJhcHBlbmQiXSwiZXhwIjoiMjAyNi0xMC0wNVQwMDowMDowMFoiLCJncm91
    cHMiOlsibWF0Y2gtZGVzayJdLCJraWQiOiJvcHMtMjAyNiIsIm5zIjpbIm1hdGNoZXMiXSwicnVsZXMiOltdLCJzdWIiOiJ1c2VyOmJvYiJ9
    GAMiCgoICIAIEgMYgQgSAXgSJAgAEiAlQ7kv8QlVEUdq3INp223ckzZloRl43aFATuEGbKlVnRpAUPmaULUy5RF5lG2FHxaVvzrhUae6iNmH
    nh55uMN5YQCOQxJJzkWjjQ3o3I-OITfeit0zhNSYQ0XnlV-GVVGOBygBGp8BCjMKI3siY2FuIjpbInJlYWQiXSwidmlhIjoic3ZjOnJlYWRl
    ciJ9GAMiCgoICIAIEgMYgggSJAgAEiAXRVO0Vt3fxpCOyrHBAf5qsh4rqgYXeVt9Q6Y0gpk_1RpAmp68almcrK-Mzu0DEEM6ZUD6N8idRK88
    JCiz1Zx1Q06hmUb6Gz8P24LcWpuJIO2qITvk52VILDtW67NMEu0sCCgBIiIKIGBhYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ent8fX5_

**Authority block with an unused symbol `"unused"`.** Rule: a symbol the block adds that its own fact doesn't use. Biscuit library: verifies.

    Ep8CCrIBCgtncmFudF9ibG9jawqMAXsiY2FuIjpbInJlYWQiLCJhcHBlbmQiXSwiZXhwIjoiMjAyNi0xMC0wNVQwMDowMDowMFoiLCJncm91
    cHMiOlsibWF0Y2gtZGVzayJdLCJraWQiOiJvcHMtMjAyNiIsIm5zIjpbIm1hdGNoZXMiXSwicnVsZXMiOltdLCJzdWIiOiJ1c2VyOmJvYiJ9
    CgZ1bnVzZWQYAyIKCggIgAgSAxiBCBIkCAASICVDuS_xCVURR2rcg2nbbdyTNmWhGXjdoUBO4QZsqVWdGkABHkzjKHlk1FObwQnJLmA_JaFW
    9ERQ3WbPKZEy-zknWU06zOjg7nKgoScjeO9saJceXIrNQXZ8p2du2V8eIMcOKAEanwEKMwojeyJjYW4iOlsicmVhZCJdLCJ2aWEiOiJzdmM6
    cmVhZGVyIn0YAyIKCggIgAgSAxiDCBIkCAASIBdFU7RW3d_GkI7KscEB_mqyHiuqBhd5W31DpjSCmT_VGkCF05c_PmlYcjFsYplLVcsM-81k
    RpSfC7VuDJL0MUjmln8LMpY-0jvZ3JHTZ1RTC6wN26iAz74ycJQWysl9xU0HKAEiIgogYGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9
    fn8

**Authority block adding the narrowing block's string as a third symbol, which only the narrowing block uses (it adds no symbols and its fact is `grant_block` of symbol 1026).** Rule: a symbol the block adds that its own fact doesn't use, judged per block. Biscuit library: verifies.

    ErwCCs8BCgtncmFudF9ibG9jawqMAXsiY2FuIjpbInJlYWQiLCJhcHBlbmQiXSwiZXhwIjoiMjAyNi0xMC0wNVQwMDowMDowMFoiLCJncm91
    cHMiOlsibWF0Y2gtZGVzayJdLCJraWQiOiJvcHMtMjAyNiIsIm5zIjpbIm1hdGNoZXMiXSwicnVsZXMiOltdLCJzdWIiOiJ1c2VyOmJvYiJ9
    CiN7ImNhbiI6WyJyZWFkIl0sInZpYSI6InN2YzpyZWFkZXIifRgDIgoKCAiACBIDGIEIEiQIABIgJUO5L_EJVRFHatyDadtt3JM2ZaEZeN2h
    QE7hBmypVZ0aQNLkziAVYiQ9Kse5KI3wTLTk0O9IqxEkkhj9-2QHU9jXtI9A0cT45WdWauYECQwPCzvRBwIoL7ThM9ai-xXOYAQoARp6Cg4Y
    AyIKCggIgAgSAxiCCBIkCAASIBdFU7RW3d_GkI7KscEB_mqyHiuqBhd5W31DpjSCmT_VGkD073dRSsrJFv-DLYHazlyPesuHGJFEdxAHBaIV
    06Hmnpl9XshSYxTVZk1dqUF9DfIZns-MgOJZ5I6NqFMOLrENKAEiIgogYGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn8

**Narrowing block appended as a third-party block, signed by the key of seed `80 81 … 9f`.** Rule: a third-party block. Biscuit library: verifies.

    EpcCCqoBCgtncmFudF9ibG9jawqMAXsiY2FuIjpbInJlYWQiLCJhcHBlbmQiXSwiZXhwIjoiMjAyNi0xMC0wNVQwMDowMDowMFoiLCJncm91
    cHMiOlsibWF0Y2gtZGVzayJdLCJraWQiOiJvcHMtMjAyNiIsIm5zIjpbIm1hdGNoZXMiXSwicnVsZXMiOltdLCJzdWIiOiJ1c2VyOmJvYiJ9
    GAMiCgoICIAIEgMYgQgSJAgAEiAlQ7kv8QlVEUdq3INp223ckzZloRl43aFATuEGbKlVnRpAWgaUHLoFLrXYHs2MaIetUEXWGK0SK3h0v5xB
    RUsBNE2qQ14tB8LGmoIYtimpZPta1sYSQLSXob_gozBFMAKwBCgBGpYCCkAKC2dyYW50X2Jsb2NrCiN7ImNhbiI6WyJyZWFkIl0sInZpYSI6
    InN2YzpyZWFkZXIifRgFIgoKCAiACBIDGIEIEiQIABIgF0VTtFbd38aQjsqxwQH-arIeK6oGF3lbfUOmNIKZP9UaQNbQ-oX6pQ79jfsayswb
    -rCyc2lrufPqxcB0jaOiWsmZ-rJRDa4pNUo082MJgyBlIsJxzMBYpCHvTofJ3By8OwUiaApAMepp01be37N-SFI_cZG0PhW2GwwAQi1s5TUb
    Ozd21YFEcPHuA4TqU8g1cDKZo2u4z9hJyRQ4LprOd2nPrifWDhIkCAASIM0Us3-VbpUxlP9_tzs9gdzFYdYadTgJS3w-GmQ-5fOqKAEiIgog
    YGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn8

**Authority block signed over Biscuit's version 0 payload (no `version` field).** Rule: a signature not over the version 1 payload. Biscuit library: verifies.

    EpUCCqoBCgtncmFudF9ibG9jawqMAXsiY2FuIjpbInJlYWQiLCJhcHBlbmQiXSwiZXhwIjoiMjAyNi0xMC0wNVQwMDowMDowMFoiLCJncm91
    cHMiOlsibWF0Y2gtZGVzayJdLCJraWQiOiJvcHMtMjAyNiIsIm5zIjpbIm1hdGNoZXMiXSwicnVsZXMiOltdLCJzdWIiOiJ1c2VyOmJvYiJ9
    GAMiCgoICIAIEgMYgQgSJAgAEiAlQ7kv8QlVEUdq3INp223ckzZloRl43aFATuEGbKlVnRpAR390ES6m124CT6-KfW2uw4Dz91xj3lHTZ2wi
    GCUREGUqs3kk7wCcinN8DPoiBXLEX7PoVBedXK_PoFGVIzKGABqfAQozCiN7ImNhbiI6WyJyZWFkIl0sInZpYSI6InN2YzpyZWFkZXIifRgD
    IgoKCAiACBIDGIIIEiQIABIgF0VTtFbd38aQjsqxwQH-arIeK6oGF3lbfUOmNIKZP9UaQHIVW_i9u7EX4ZcJWY7KitWIGP4iXhkBNLMlaeGh
    u40nYiYCSwC8Th4q7ykp_Ra6FZqi5MijSY5f95vf7ZoZ5g4oASIiCiBgYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXp7fH1-fw

**Narrowing block signed over the version 0 payload.** Rule: a signature not over the version 1 payload. Biscuit library: verifies.

    EpcCCqoBCgtncmFudF9ibG9jawqMAXsiY2FuIjpbInJlYWQiLCJhcHBlbmQiXSwiZXhwIjoiMjAyNi0xMC0wNVQwMDowMDowMFoiLCJncm91
    cHMiOlsibWF0Y2gtZGVzayJdLCJraWQiOiJvcHMtMjAyNiIsIm5zIjpbIm1hdGNoZXMiXSwicnVsZXMiOltdLCJzdWIiOiJ1c2VyOmJvYiJ9
    GAMiCgoICIAIEgMYgQgSJAgAEiAlQ7kv8QlVEUdq3INp223ckzZloRl43aFATuEGbKlVnRpAWgaUHLoFLrXYHs2MaIetUEXWGK0SK3h0v5xB
    RUsBNE2qQ14tB8LGmoIYtimpZPta1sYSQLSXob_gozBFMAKwBCgBGp0BCjMKI3siY2FuIjpbInJlYWQiXSwidmlhIjoic3ZjOnJlYWRlciJ9
    GAMiCgoICIAIEgMYgggSJAgAEiAXRVO0Vt3fxpCOyrHBAf5qsh4rqgYXeVt9Q6Y0gpk_1RpAcA3tGSSm6ajG_NROGP6AFsVAKl3cr85rtTGG
    kGEuLIYZx_xGlNa3SHvsSTqPbayA-5_XuAMkQx0BprCDi6z8CCIiCiBgYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXp7fH1-fw

**Root block string not canonical (`sub` first).** Rule: a `grant_block` string not equal to its canonical form. Biscuit library: verifies.

    EpcCCqoBCgtncmFudF9ibG9jawqMAXsic3ViIjoidXNlcjpib2IiLCJjYW4iOlsicmVhZCIsImFwcGVuZCJdLCJleHAiOiIyMDI2LTEwLTA1
    VDAwOjAwOjAwWiIsImdyb3VwcyI6WyJtYXRjaC1kZXNrIl0sImtpZCI6Im9wcy0yMDI2IiwibnMiOlsibWF0Y2hlcyJdLCJydWxlcyI6W119
    GAMiCgoICIAIEgMYgQgSJAgAEiAlQ7kv8QlVEUdq3INp223ckzZloRl43aFATuEGbKlVnRpAcl6tmCuIQr0Sf8VOrjwrXfu5dML1lbYTZoGY
    Ft3bUFjx0_Ubf-ngNMynTpbJNv_NnyFEnJuWdAsksz79PWAgBSgBGp8BCjMKI3siY2FuIjpbInJlYWQiXSwidmlhIjoic3ZjOnJlYWRlciJ9
    GAMiCgoICIAIEgMYgggSJAgAEiAXRVO0Vt3fxpCOyrHBAf5qsh4rqgYXeVt9Q6Y0gpk_1RpA_HTtOWbEtTXzBQQpwi8l-P65addwtyDxQAoI
    xFGVFhdAcZkw7Jeknj2qBTmHjTtDt4OQKBWnOfcXMZh7eAeZDSgBIiIKIGBhYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ent8fX5_

**Root block string not I-JSON (`can` twice).** Rule: a `grant_block` string that isn't I-JSON. Biscuit library: verifies.

    EqYCCrkBCgtncmFudF9ibG9jawqbAXsiY2FuIjpbInJlYWQiXSwiY2FuIjpbInJlYWQiLCJhcHBlbmQiXSwiZXhwIjoiMjAyNi0xMC0wNVQw
    MDowMDowMFoiLCJncm91cHMiOlsibWF0Y2gtZGVzayJdLCJraWQiOiJvcHMtMjAyNiIsIm5zIjpbIm1hdGNoZXMiXSwicnVsZXMiOltdLCJz
    dWIiOiJ1c2VyOmJvYiJ9GAMiCgoICIAIEgMYgQgSJAgAEiAlQ7kv8QlVEUdq3INp223ckzZloRl43aFATuEGbKlVnRpAjGh-c7mWOMteDUc5
    GfxjQIwXZIie-JZKwXHwH_4dxFgGDSOq8uN9jmYRVcirj1EL9GLN3ZCFIIMMMUCK0xP4DygBGp8BCjMKI3siY2FuIjpbInJlYWQiXSwidmlh
    Ijoic3ZjOnJlYWRlciJ9GAMiCgoICIAIEgMYgggSJAgAEiAXRVO0Vt3fxpCOyrHBAf5qsh4rqgYXeVt9Q6Y0gpk_1RpApGaErwqXXddS9gqB
    eZNppXDuAIkS8OhiIZYLzilPtOcb8y3HRkSM8XWq8s_qZEGH0oJyT9yVGaVxVA7i-wmNCygBIiIKIGBhYmNkZWZnaGlqa2xtbm9wcXJzdHV2
    d3h5ent8fX5_

**Narrowing block string not canonical (`via` first).** Rule: a `grant_block` string not equal to its canonical form. Biscuit library: verifies.

    EpcCCqoBCgtncmFudF9ibG9jawqMAXsiY2FuIjpbInJlYWQiLCJhcHBlbmQiXSwiZXhwIjoiMjAyNi0xMC0wNVQwMDowMDowMFoiLCJncm91
    cHMiOlsibWF0Y2gtZGVzayJdLCJraWQiOiJvcHMtMjAyNiIsIm5zIjpbIm1hdGNoZXMiXSwicnVsZXMiOltdLCJzdWIiOiJ1c2VyOmJvYiJ9
    GAMiCgoICIAIEgMYgQgSJAgAEiAlQ7kv8QlVEUdq3INp223ckzZloRl43aFATuEGbKlVnRpAWgaUHLoFLrXYHs2MaIetUEXWGK0SK3h0v5xB
    RUsBNE2qQ14tB8LGmoIYtimpZPta1sYSQLSXob_gozBFMAKwBCgBGp8BCjMKI3sidmlhIjoic3ZjOnJlYWRlciIsImNhbiI6WyJyZWFkIl19
    GAMiCgoICIAIEgMYgggSJAgAEiAXRVO0Vt3fxpCOyrHBAf5qsh4rqgYXeVt9Q6Y0gpk_1RpAVmrKLY4WSXy7s6htcC8ZlgHUk27hc6QU-d86
    -AbaHeqvEYEk3ojYPQHHtkBUiNwA-i8Iektt8lUzk3Kn7zP5BigBIiIKIGBhYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ent8fX5_

**Narrowing block signed with P-256 (authority's next key: P-256, scalar `40 41 … 5f`; deterministic ECDSA, RFC 6979, DER).** Rule: a signature that isn't Ed25519. Biscuit library: verifies.

    EpgCCqoBCgtncmFudF9ibG9jawqMAXsiY2FuIjpbInJlYWQiLCJhcHBlbmQiXSwiZXhwIjoiMjAyNi0xMC0wNVQwMDowMDowMFoiLCJncm91
    cHMiOlsibWF0Y2gtZGVzayJdLCJraWQiOiJvcHMtMjAyNiIsIm5zIjpbIm1hdGNoZXMiXSwicnVsZXMiOltdLCJzdWIiOiJ1c2VyOmJvYiJ9
    GAMiCgoICIAIEgMYgQgSJQgBEiEDaOx88IzUEG5DsU3olUJlIr0KRRUMAn5Fx5U0NNdH57oaQHqHeWsBki_VRw5_8nE22sfRBPmpIuiY5eck
    pKxrRRpEmrz_6jBY1QWYWZby29V0EsfPmL932WIyUZwYa012gwMoARqnAQozCiN7ImNhbiI6WyJyZWFkIl0sInZpYSI6InN2YzpyZWFkZXIi
    fRgDIgoKCAiACBIDGIIIEiQIABIgF0VTtFbd38aQjsqxwQH-arIeK6oGF3lbfUOmNIKZP9UaSDBGAiEAoajS-Qur0ZnLwOeRJaVyop_4vsQ7
    -KcdWOcI0HT8XYUCIQC6FhLr9EruwScelqszavV4ejXoGcqtywOBF80k-sFX6igBIiIKIGBhYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ent8
    fX5_

**Authority signature with `S + L` in place of `S`.** Rule: an Ed25519 signature that isn't strict (`S < L`). Biscuit library: refuses (BiscuitValidationError).

    EpcCCqoBCgtncmFudF9ibG9jawqMAXsiY2FuIjpbInJlYWQiLCJhcHBlbmQiXSwiZXhwIjoiMjAyNi0xMC0wNVQwMDowMDowMFoiLCJncm91
    cHMiOlsibWF0Y2gtZGVzayJdLCJraWQiOiJvcHMtMjAyNiIsIm5zIjpbIm1hdGNoZXMiXSwicnVsZXMiOltdLCJzdWIiOiJ1c2VyOmJvYiJ9
    GAMiCgoICIAIEgMYgQgSJAgAEiAlQ7kv8QlVEUdq3INp223ckzZloRl43aFATuEGbKlVnRpAWgaUHLoFLrXYHs2MaIetUEXWGK0SK3h0v5xB
    RUsBNE2XF1SKISXZ8li1rcyHXtpv1sYSQLSXob_gozBFMAKwFCgBGp8BCjMKI3siY2FuIjpbInJlYWQiXSwidmlhIjoic3ZjOnJlYWRlciJ9
    GAMiCgoICIAIEgMYgggSJAgAEiAXRVO0Vt3fxpCOyrHBAf5qsh4rqgYXeVt9Q6Y0gpk_1RpAmkL2iVmnS3RAE2GyQOA7eDsLWGSE_QwUzTtk
    YqyO9-v3sqKclQiVM6vMbvfMbHuT7XqCedi7XnYN_K1hia5PBCgBIiIKIGBhYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ent8fX5_

**Wrong `kid`.** The root block names `kid` `ops-2027` and is signed by the root key above (seed `00 01 … 1f`), in a namespace whose `keys` list `ops-2026` with `pub` `A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg` and `ops-2027` with `pub` `Kay64UG8yvCyLhqU000LxzYeUm0L_hLIl5S8kyKWbdc` (seed `20 21 … 3f`). It fails verification like any bad signature (`401`); Biscuit library, under the `ops-2027` key: refuses (BiscuitValidationError); under the root key: verifies.

    EpcCCqoBCgtncmFudF9ibG9jawqMAXsiY2FuIjpbInJlYWQiLCJhcHBlbmQiXSwiZXhwIjoiMjAyNi0xMC0wNVQwMDowMDowMFoiLCJncm91
    cHMiOlsibWF0Y2gtZGVzayJdLCJraWQiOiJvcHMtMjAyNyIsIm5zIjpbIm1hdGNoZXMiXSwicnVsZXMiOltdLCJzdWIiOiJ1c2VyOmJvYiJ9
    GAMiCgoICIAIEgMYgQgSJAgAEiAlQ7kv8QlVEUdq3INp223ckzZloRl43aFATuEGbKlVnRpAu-gwaE_qNuMT-3TIHQFkGRx28PgT3Qs7xmmq
    oUovqFTdPPtiiFR-X8ktpRvWwc0xN_KLRHaI5fMfNGNtnF3vDSgBGp8BCjMKI3siY2FuIjpbInJlYWQiXSwidmlhIjoic3ZjOnJlYWRlciJ9
    GAMiCgoICIAIEgMYgggSJAgAEiAXRVO0Vt3fxpCOyrHBAf5qsh4rqgYXeVt9Q6Y0gpk_1RpAtiLICY5OX_83a517DhTHhIr8RhXN-poWBLls
    DeMRPJ9006SE3zvfK3OOuEskZ1vQyqu9d1opOlc2yImulUkuDCgBIiIKIGBhYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ent8fX5_

## Skipped

- Nothing on §I.15's list was skipped outright: biscuit-python 0.4.0 installed from pip, and served only to encode Datalog rules and checks and to cross-check signature chains; every token was signed here.
- Not attempted, beyond the list: a *sealed* Biscuit token as an accepted control (biscuit-python 0.4 has no `seal`, and the version 1 sealing payload isn't in the Patch Log text); the `rootKeyId` field (§C.8 says it doesn't name the key, not that it is refused); padded sealed-bundle lines.

## Underdetermined text

- **§C.8, block versions.** Not a text gap for rejection, but the block `version` a conforming token carries isn't stated; §I.14 uses 3. A scope or public key needs Biscuit version 4 and a third-party block 5; the vectors set those.
- **Addendum I itself, §I.12's sealed-bundle envelope.** The ephemeral key of its `wrapped` isn't stated (its `enc`, `a8e12cac…ce757`, is none of the `xx xx+1 …` keys), so it can be checked only by opening it (it opens to `K_b`), not regenerated as §I.12's other HPKE values can.
