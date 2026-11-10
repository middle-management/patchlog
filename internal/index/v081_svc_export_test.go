package index

import (
	"context"
	"slices"

	"github.com/middle-management/patchlog/internal/catvis"
	"github.com/middle-management/patchlog/internal/jsonv"
)

// PlantPartial adds "partial" to the recorded subjects of every g: marker
// (edge_gs and the filters kept in memory), as an exchange under an
// earlier draft recorded a set that left out some groups (§B.11.5).
func (ix *Index) PlantPartial(ctx context.Context) error {
	rows, err := ix.db.QueryContext(ctx, `SELECT marker, subjects FROM edge_gs`)
	if err != nil {
		return err
	}
	got := map[string][]string{}
	for rows.Next() {
		var m, s string
		if err := rows.Scan(&m, &s); err != nil {
			rows.Close()
			return err
		}
		subs, _ := decodeStrings(s)
		got[m] = append(subs, catvis.Partial)
	}
	rows.Close()
	for m, subs := range got {
		slices.Sort(subs)
		l := make([]any, len(subs))
		for i, x := range subs {
			l[i] = x
		}
		if _, err := ix.db.ExecContext(ctx, `UPDATE edge_gs SET subjects = ? WHERE marker = ?`, string(jsonv.Canonical(l)), m); err != nil {
			return err
		}
	}
	ix.fmu.Lock()
	for m := range got {
		delete(ix.filters, m)
	}
	ix.fmu.Unlock()
	return nil
}
