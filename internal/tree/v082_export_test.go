package tree

// BeforeUnkept sets f to run as a listing that is neither stored nor kept
// (one for a single reader) has been computed, before the purges applied
// since it took its kept generation are checked (tests: a purge applied
// meanwhile); nil unsets it.
func (s *Service) BeforeUnkept(f func()) {
	if f == nil {
		s.beforeUnkept.Store(nil)
		return
	}
	s.beforeUnkept.Store(&f)
}
