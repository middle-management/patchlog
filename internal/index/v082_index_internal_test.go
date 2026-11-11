package index

import (
	"errors"
	"fmt"
	"testing"

	"github.com/middle-management/patchlog/internal/grant"
)

// TestV082WorseUpstream (SVC-15i; §C.4, §C.5.2): of the failures to read
// upstream that one exchange meets, across its grants and across the
// namespaces one grant names, the first lasting one answers (502), and
// one for now (503 behind) only where none is lasting, whatever their
// order.
func TestV082WorseUpstream(t *testing.T) {
	lasting, transient := error(fakeChain{false}), error(fakeChain{true})
	doc := errors.New("a namespace document that can't be read")
	joined := errors.Join(&grant.AuthError{Status: 403, Msg: grant.RequireAtRefusal}, fakeChain{true})
	for _, c := range []struct {
		name string
		errs []error
		want error
	}{
		{"one transient", []error{transient}, transient},
		{"transient then lasting", []error{transient, lasting}, lasting},
		{"lasting then transient", []error{lasting, transient}, lasting},
		{"two transient: the first", []error{joined, transient}, joined},
		{"two lasting: the first", []error{doc, lasting}, doc},
		{"transient, document, lasting", []error{transient, doc, lasting}, doc},
		{"a root for now, then a lasting chain", []error{&rootErr{fmt.Errorf("down: %w", fakeTransient{})}, lasting}, lasting},
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
