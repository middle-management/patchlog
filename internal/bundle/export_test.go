package bundle

// KeepSnapshotTrees makes an import keep its snapshot documents as the
// trees the Reader parses, as imports did before they kept their canonical
// forms (ImportOptions.keepTrees), for tests that compare the two.
func KeepSnapshotTrees(opt *ImportOptions) { opt.keepTrees = true }
