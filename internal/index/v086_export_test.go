package index

import "context"

// CheckedHead is the ns_id the grant checker holds ns's document at,
// reading it if it holds none (tests).
func (ix *Index) CheckedHead(ctx context.Context, ns string) string {
	cfg, err := ix.checker.Config(ctx, ns)
	if err != nil {
		return ""
	}
	return cfg.Head
}
