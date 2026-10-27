// Package vectors pins the spec's normative test vectors (Addendum I) to the
// reference's production code. It holds tests only: each reproduces an
// Addendum I value, or refuses an input marked as rejected, through the
// function the reference itself computes it with (jsonv, ids, sig, grant,
// edge, seal, grantcheck, tree, bundle, files, verify, client and, for the
// `400` verdicts and the ids a write answers, the server), never through a
// formula recomputed in the test (§1 "Byte-exact definitions").
//
// The vectors are the spec's: SPEC.md Addendum I is the source, and a value
// changes here only when it changes there.
package vectors
