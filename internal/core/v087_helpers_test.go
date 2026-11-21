package core

// visibleHead reports whether name's current head is visible to fv
// (§7.9 Visible), for tests written before visibility was per revision.
func (fv *fview) visibleHead(t *tx, name string) bool {
	return fv.visible(t, name, t.resolve(fv.fs.n, name, nil).head)
}
