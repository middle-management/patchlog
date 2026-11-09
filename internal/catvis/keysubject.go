package catvis

import (
	"crypto/sha256"

	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/jsonv"
)

// KeyPrefix prefixes the subject binding a filtered-read gs to its grant's
// key (KeySubject); View ignores it, as it does "partial" and "scope:…".
const KeyPrefix = "key:"

// KeySubject is the subject that binds a §B.11.9 gs to the key its grant
// came from, by kid and pub, the pub member string as the key's entry has
// it: key:{text(trunc160(sha256(canonical([kid, pub]))))}. FilteredSubjects'
// scope digest names no key, so without it readers through two keys with
// the same scope rules would share a gs, and so one stored row, whose kid
// and pub, those of its last exchange, would judge both keys' cookies: a
// cookie from a key whose pub was replaced would read on once a reader of
// the other key exchanged (§B.11.9 gs: "403 ... a key ... they came from is
// ... no longer accepted"; §C.4). Services needn't compute the same gs
// (§B.11.5); the origin and the index both add it, so theirs still agree.
func KeySubject(kid, pub string) string {
	sum := sha256.Sum256(jsonv.Canonical(jsonv.FromGo([]any{kid, pub})))
	return KeyPrefix + ids.FromBytes(sum[:ids.Size]).String()
}
