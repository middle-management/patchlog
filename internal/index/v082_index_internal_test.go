package index

import (
	"errors"
	"fmt"
	"testing"
)

// TestV082WorseUpstream (SVC-15i; §C.5.2): of the failures to read
// upstream that one exchange meets, across its grants and across the
// namespaces one grant names, the first lasting one answers (502), and
// one for now (503 behind) only where none is lasting, whatever their
// order.
func TestV082WorseUpstream(t *testing.T) {
	transient := error(&rootErr{fmt.Errorf("down: %w", fakeTransient{})})
	transient2 := error(&rootErr{fmt.Errorf("still down: %w", fakeTransient{})})
	lasting := errors.New("a namespace document that can't be read")
	lasting2 := errors.New("another")
	for _, c := range []struct {
		name string
		errs []error
		want error
	}{
		{"one transient", []error{transient}, transient},
		{"transient then lasting", []error{transient, lasting}, lasting},
		{"lasting then transient", []error{lasting, transient}, lasting},
		{"two transient: the first", []error{transient, transient2}, transient},
		{"two lasting: the first", []error{lasting, lasting2}, lasting},
		{"transient, lasting, lasting", []error{transient, lasting, lasting2}, lasting},
	} {
		var got error
		for _, e := range c.errs {
			got = worseUpstream(got, e)
		}
		if got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}

// fakeTransient is a transport failure, as client.Transient reads one.
type fakeTransient struct{}

func (fakeTransient) Error() string   { return "connection refused" }
func (fakeTransient) Timeout() bool   { return true }
func (fakeTransient) Temporary() bool { return true }
