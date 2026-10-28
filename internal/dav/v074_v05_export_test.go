package dav

// ServeSealed makes the server read ns/name at rev as the core serves a
// sealed revision to a gateway holding no keys (client.ErrNoKeys, §H.7),
// as if it had read it so.
func ServeSealed(s *Server, ns, name, rev string) {
	s.keep(docKey(ns, name, rev), &docEntry{sealed: true})
}
