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

// FailVerify sets f to fail the verification of callers' grants for the
// catalog with the error it returns, if any (tests); nil unsets it.
func (s *Service) FailVerify(f func() error) {
	if f == nil {
		s.verifyHook.Store(nil)
		return
	}
	s.verifyHook.Store(&f)
}
