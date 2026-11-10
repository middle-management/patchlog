package tree

// AfterStop sets f to run as a stop (purgeStopped) has marked its
// namespace stopped and left the graph's lock, before the purges it then
// makes (tests: a reader meanwhile); nil unsets it.
func (s *Service) AfterStop(f func(ns string)) {
	if f == nil {
		s.afterStop.Store(nil)
		return
	}
	s.afterStop.Store(&f)
}
