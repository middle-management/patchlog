package dav

// SetTreePage sets the entries a page of a tree service's listing asks
// for (treePage), so tests page small folders.
func SetTreePage(s *Server, n int) { s.ts.page = n }
