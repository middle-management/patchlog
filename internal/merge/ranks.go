package merge

import (
	"context"
	"fmt"

	"github.com/middle-management/patchlog/internal/client"
)

// Protection ranks (§2.1): public < private = sealed < e2e.
const (
	rankPublic  = 1
	rankPrivate = 2 // and sealed
	rankE2E     = 3
)

// protection is what a namespace's rank depends on: its encryption level
// and its read mode ("grant" when the document has none).
type protection struct {
	level string // "", "at-rest", "sealed" or "e2e"
	read  string
}

// docProtection reads a namespace document's protection.
func docProtection(doc map[string]any) protection {
	enc, _ := doc["encryption"].(map[string]any)
	lv, _ := enc["level"].(string)
	read, _ := doc["read"].(string)
	if read == "" {
		read = "grant"
	}
	return protection{level: lv, read: read}
}

// source is the rank as a source (§2.1): e2e at E3, sealed at E2 whatever
// its read, otherwise public or private by its read.
func (p protection) source() (int, string) {
	switch {
	case p.level == "e2e":
		return rankE2E, "e2e"
	case p.level == "sealed":
		return rankPrivate, "sealed"
	case p.read == "public":
		return rankPublic, "public"
	}
	return rankPrivate, "private"
}

// target is the rank as a target (§2.1): as a source, except that a sealed
// namespace whose read is public is public.
func (p protection) target() (int, string) {
	if p.level == "sealed" && p.read == "public" {
		return rankPublic, "public (sealed, read public)"
	}
	return p.source()
}

// nsProtection reads a namespace's protection from its current document,
// a sealed one with the client's keys (§E.2.3): without them its read, and
// so its rank as a target, can't be judged.
func nsProtection(ctx context.Context, c *client.Client, ns string) (protection, error) {
	h, err := c.NSHead(ctx, ns)
	if err != nil {
		return protection{}, err
	}
	d, err := c.NSDoc(ctx, ns, h.ID)
	if err != nil {
		return protection{}, fmt.Errorf("merge: judging the protection of %s (§2.1): %w", ns, err)
	}
	return docProtection(d.Value), nil
}

// checkSuccessorRank refuses a successor that ranks below the old branch
// (§F.5): a rebase never replays into one, created or resumed.
func checkSuccessorRank(old, succ protection, oldNS, succNS string) error {
	sr, sn := old.source()
	tr, tn := succ.target()
	if tr < sr {
		return fmt.Errorf("merge: %s ranks %s as a target, below %s, which ranks %s as a source (§2.1): a rebase never replays into a successor that ranks below the old branch (§F.5)", succNS, tn, oldNS, sn)
	}
	return nil
}
