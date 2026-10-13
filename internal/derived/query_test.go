package derived

import (
	"net/url"
	"testing"
)

// TestCanonicalQuery: the form of §A.5 "Canonical URLs".
func TestCanonicalQuery(t *testing.T) {
	for _, c := range []struct {
		name string
		in   string
		drop []string
		want string
	}{
		{"empty", "", nil, ""},
		{"only dropped", "min=a:1", []string{"min"}, ""},
		{"names sorted", "q=x&limit=2&after=4", nil, "?after=4&limit=2&q=x"},
		{"values sorted bytewise", "facet[/b]=2&facet[/b]=10", nil, "?facet%5B%2Fb%5D=10&facet%5B%2Fb%5D=2"},
		{"name before value", "a=2&ab=1&a=1", nil, "?a=1&a=2&ab=1"},
		{"space is %20", "q=two+words", nil, "?q=two%20words"},
		{"plus is %2B", "q=a%2Bb", nil, "?q=a%2Bb"},
		{"reserved bytes", "ref=/r/x/y%23e&t=a:b,c", nil, "?ref=%2Fr%2Fx%2Fy%23e&t=a%3Ab%2Cc"},
		{"unreserved stay", "q=A-z.0_9~", nil, "?q=A-z.0_9~"},
		{"uppercase hex", "q=%c3%a5", nil, "?q=%C3%A5"},
		{"utf-8 bytes order", "q=%C3%A5&q=z", nil, "?q=z&q=%C3%A5"},
		{"empty value", "unordered", nil, "?unordered="},
		{"drop", "min=1&q=x&min=2", []string{"min"}, "?q=x"},
	} {
		v, err := url.ParseQuery(c.in)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if got := CanonicalQuery(v, c.drop...); got != c.want {
			t.Errorf("%s: CanonicalQuery(%q) = %q, want %q", c.name, c.in, got, c.want)
		}
		// The form is a fixed point.
		if c.want != "" {
			w, _ := url.ParseQuery(c.want[1:])
			if got := CanonicalQuery(w); got != c.want {
				t.Errorf("%s: not a fixed point: %q → %q", c.name, c.want, got)
			}
		}
	}
}
