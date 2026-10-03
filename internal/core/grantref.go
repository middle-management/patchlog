package core

// Grant references of namespace entries (§5, §7.4). Each entry written on
// a request stores the id of the grant it was written under
// (ns_log.grant_id, D.2), and the log serves it as
// "grant": { "id", "sub", "kid" }: the grant id in text form (§C.3, §3.2)
// and its root sub and kid, read from the stored grant. Merge tools and the
// janitor match the root sub and kid against merge.authors (§F.3, §F.6).
//
// Entries written on a request while authentication is disabled (§1)
// serve "grant": null instead (ns_log.no_auth, tx.noAuth), which merge
// tools and the janitor match on the author alone while GET / says
// "auth": "disabled". Entries the server writes itself (propagated purges,
// mirrored schemas, purges applied from a remote base, retention's prunes,
// rotations) serve no grant at all. Neither do entries of databases from
// before grant references that the migration couldn't give one
// (backfillNSGrants, db.go), nor those a development server wrote before
// v0.38, which stored nothing to tell them from the server's own.

import (
	"database/sql"
	"errors"
	"fmt"
	"sync"

	"github.com/middle-management/patchlog/internal/grant"
	"github.com/middle-management/patchlog/internal/ids"
)

// grantRoot is the root sub and kid of a stored grant.
type grantRoot struct{ sub, kid string }

// grantRootCache caches grantRoot by grant id. A grant id determines the
// root block (§C.3), so an entry never goes stale; the cache is bounded by
// starting over when it is full.
type grantRootCache struct {
	mu sync.Mutex
	m  map[ids.ID]grantRoot
}

const grantRootMax = 4096

func (c *grantRootCache) get(id ids.ID) (grantRoot, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	r, ok := c.m[id]
	return r, ok
}

func (c *grantRootCache) put(id ids.ID, r grantRoot) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m == nil || len(c.m) >= grantRootMax {
		c.m = map[ids.ID]grantRoot{}
	}
	c.m[id] = r
}

// grantRef is the grant reference a namespace entry serves for the grant
// stored under id (§7.4). The root sub and kid are stored in plaintext next
// to the grant (storeGrantBlocks), so reading a log never needs the key
// store; only a grant stored encrypted by a version from before that is
// decrypted. It is nil if the grant isn't stored or doesn't parse, which a
// server that stores every grant it records never sees: the entry then
// serves no grant, and counts for no one's merge.authors.
func (t *tx) grantRef(id []byte) map[string]any {
	gid := ids.FromBytes(id)
	r, ok := t.e.grantRoots.get(gid)
	if !ok {
		var blocks []byte
		var sub, kid sql.NullString
		err := t.QueryRow(`SELECT blocks, root_sub, root_kid FROM grants WHERE id = ?`, id).Scan(&blocks, &sub, &kid)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		t.must(err)
		if sub.Valid {
			r = grantRoot{sub: sub.String, kid: kid.String}
		} else {
			if isSealed(string(blocks)) {
				// Encrypted at rest under the deployment key of grants
				// (§E.1), before root_sub was stored.
				plain, err := openRow(t.dek(grantsDEK, false), grantAAD(id), blocks)
				if err != nil {
					panic(encUnavailable(fmt.Sprintf("the stored grant %s does not decrypt: %v", gid, err)))
				}
				blocks = plain
			}
			g, err := grant.ParseStored(blocks)
			if err != nil || len(g.Blocks) == 0 {
				return nil
			}
			r = grantRoot{sub: g.Blocks[0].Sub, kid: g.Blocks[0].Kid}
		}
		t.e.grantRoots.put(gid, r)
	}
	return map[string]any{"id": gid.String(), "sub": r.sub, "kid": r.kid}
}
