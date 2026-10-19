package dav

// SetTreePage sets the entries a page of a tree service's listing asks
// for (treePage), so tests page small folders.
func SetTreePage(s *Server, n int) { s.ts.page = n }

// Views is what the server keeps of the catalogs' graphs and folders'
// listings tokens read (views): its entries and their cost.
func Views(s *Server) (int, int) {
	s.viewMu.Lock()
	defer s.viewMu.Unlock()
	return s.views.Len(), s.views.Bytes()
}

// SetIDUsers bounds the token ids whose users the server keeps (idUsers),
// over every user and per user, and empties them, so tests reach the
// bounds with a few hundred logins.
func SetIDUsers(s *Server, all, perUser int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.idUsers.init(all, perUser)
}
