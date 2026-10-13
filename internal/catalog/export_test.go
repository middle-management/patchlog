package catalog

// SetAfterDecide sets a function POST /read-grants runs after each try
// decides its items, before it checks whether the checkpoint moved
// (tests); nil removes it.
func (s *Service) SetAfterDecide(f func(try int)) {
	if f == nil {
		s.afterDecide.Store(nil)
		return
	}
	s.afterDecide.Store(&f)
}
