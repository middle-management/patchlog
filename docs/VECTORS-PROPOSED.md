# Patch Log — proposed test vectors (unconfirmed candidates)

**Status: unconfirmed candidates**, computed independently from the v0.89 draft (SPEC.md, SERVICES.md, TOOLS.md), for the reference implementation to confirm. Nothing here is normative until it does. The reference has reproduced every earlier candidate, now in Addendum I (§I.22–§I.26 and §I.24's key rows). v0.89's derived keys (§E.2.1) change §I.7, §I.12, §I.13, §I.19 and §I.23 and add §I.27, recomputed here from the text; the reference has yet to confirm those. No other candidate vector is open; what follows are the points the text leaves underdetermined, and the one vector still missing, a sealed Biscuit token accepted (§C.8, §I.28).

`patchlog-vectors-proposed.py` (Python stdlib + `cryptography`) first reproduces every value of Addendum I, §I.1–§I.27, and checks that each occurs in the draft. It aborts on any mismatch, then prints this file. Conventions, keys and the IV `c0 c1 … cb` are Addendum I's. Every plaintext here is illustrative (Addendum I's preface), as §I.19's are.

## Underdetermined

- **§C.8, block versions.** The block `version` a conforming token carries isn't stated; §I.14 uses 3. A scope or public key needs Biscuit version 4 and a third-party block 5; §I.21 sets those.
- **§I.12's sealed-bundle envelope.** The ephemeral key of its `wrapped` isn't stated (its `enc` is none of the `xx xx+1 …` keys), so it can be checked only by opening it (it opens to `K_b`), not regenerated. §I.17 reuses it.
- **§7.9's `key:` string.** `canonical([kid, pub])` is read with `pub` the key entry's base64url string, as the namespace document lists it (§I.26).
- **One IV.** Addendum I seals every line of §I.17 under one `K_b` with the IV `c0 c1 … cb`, as all its JWEs use it; a real sealing draws a fresh IV per JWE (RFC 7518), and the lines' shared ciphertext prefixes show why.
