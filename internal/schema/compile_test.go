package schema

import (
	"testing"

	"github.com/middle-management/patchlog/internal/jsv"
)

// testSchema is a schema compiled for a test with a Rules' options.
type testSchema struct{ s *jsv.Schema }

func (x testSchema) Validate(v any) error { return x.s.Validate(v, jsv.ValidateOptions{}) }

func compileOpts(t *testing.T, o jsv.Options, doc any) testSchema {
	t.Helper()
	s, err := jsv.Compile(doc, "urn:test", o)
	if err != nil {
		t.Fatal(err)
	}
	return testSchema{s}
}
