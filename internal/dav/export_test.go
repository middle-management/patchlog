package dav

// SetIDUsers bounds the token ids whose users the server keeps (idUsers),
// over every user and per user, and empties them, so tests reach the
// bounds with a few hundred logins.
func SetIDUsers(s *Server, all, perUser int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.idUsers.init(all, perUser)
}
