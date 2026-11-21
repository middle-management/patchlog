package core

import (
	"encoding/base64"
	"strings"

	"github.com/middle-management/patchlog/internal/jsonv"
)

// jweProtected reads a compact JWE's protected header without a key, and
// without judging it beyond its being a JSON object: what a stored
// sealing binds (kid, pl) and whether it carries a zip member, which
// legacy sealings did (§E.2.2, §E.3.1).
func jweProtected(jwe string) (map[string]any, bool) {
	seg, _, ok := strings.Cut(jwe, ".")
	if !ok {
		return nil, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		return nil, false
	}
	v, err := jsonv.Parse(raw)
	if err != nil {
		return nil, false
	}
	m, ok := v.(map[string]any)
	return m, ok
}

// snapshotHeaderServable reports, from its protected header alone,
// whether a stored prune snapshot is §E.3.1's for revision id of
// resource name of ns: pl exactly {ns, name, id}, no zip, and kid naming
// ns. At a tombstone horizon id is the tombstone's parent. A legacy one
// (pl.id the tombstone, a pre-v0.63 pl kind, or zip) is not, and /rev
// answers 410 pruned where it would serve it (stored.md item 4).
func snapshotHeaderServable(jwe, ns, name, id string) bool {
	h, ok := jweProtected(jwe)
	if !ok {
		return false
	}
	if _, zip := h["zip"]; zip {
		return false
	}
	pl, _ := h["pl"].(map[string]any)
	kid, _ := h["kid"].(string)
	i := strings.LastIndexByte(kid, '#')
	if len(pl) != 3 || i <= 0 || kid[:i] != ns {
		return false
	}
	return pl["ns"] == ns && pl["name"] == name && pl["id"] == id
}
