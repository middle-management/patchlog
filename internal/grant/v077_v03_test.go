package grant

// unreadableChain is a CheckAt error that couldn't read the chain.
type unreadableChain struct{ transient bool }

func (e *unreadableChain) Error() string         { return "cannot read the chain" }
func (e *unreadableChain) ChainUnreadable() bool { return e.transient }
