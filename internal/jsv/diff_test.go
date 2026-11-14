package jsv

import (
	"fmt"
	"math/rand"
	"path/filepath"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/schema"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

// The differential tests hold jsv to the verdicts of the library the
// server uses today, configured as internal/schema configures it: draft
// 2020-12, formats asserted, patterns read by internal/pattern.

type libLoader func(string) (any, error)

func (f libLoader) Load(url string) (any, error) { return f(url) }

func libCompile(doc any, load func(string) (any, error)) (sch *jsonschema.Schema, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic: %v", r)
		}
	}()
	c := jsonschema.NewCompiler()
	schema.V073.Configure(c)
	if load == nil {
		load = func(url string) (any, error) { return nil, fmt.Errorf("refusing to load %q", url) }
	}
	c.UseLoader(libLoader(load))
	if err := c.AddResource(defaultBase, doc); err != nil {
		return nil, err
	}
	return c.Compile(defaultBase)
}

// repoOptions are the Options that correspond to the library as the
// repository configures it. idn-email and idn-hostname, which
// internal/schema adds to the library, are not exported by it and stay
// unchecked here.
func repoOptions(load func(string) (any, error)) Options {
	return Options{
		Load:         load,
		AssertFormat: true,
		Regexp: func(p string) (Matcher, error) {
			re, err := schema.V073.CompileRegexp(p)
			if err != nil {
				return nil, err
			}
			return re, nil
		},
	}
}

// TestDifferentialSuite runs every schema and instance of the suite,
// optional tests included, through both validators.
func TestDifferentialSuite(t *testing.T) {
	dir := suiteDir(t)
	load := suiteLoader(dir)
	compared, bothRefuse := 0, 0
	for _, sub := range []string{"", "optional", "optional/format"} {
		for _, path := range suiteFiles(t, dir, sub) {
			name := filepath.Base(path)
			if strings.HasPrefix(name, "idn-") {
				continue // formats internal/schema adds and does not export
			}
			for _, c := range readSuiteFile(t, path) {
				if m, ok := c.Schema.(map[string]any); ok {
					if f, _ := m["format"].(string); strings.HasPrefix(f, "idn-") {
						continue
					}
				}
				lib, lerr := libCompile(c.Schema, load)
				sch, jerr := Compile(c.Schema, "", repoOptions(load))
				if (lerr == nil) != (jerr == nil) {
					key := name + ": " + c.Description
					if why, ok := knownCompileDifferences[key]; ok {
						t.Logf("known difference: %s: %s", key, why)
						continue
					}
					t.Errorf("%s: %s: compile disagrees:\n  library: %v\n  jsv:     %v", name, c.Description, lerr, jerr)
					continue
				}
				if lerr != nil {
					bothRefuse++
					continue
				}
				for _, tc := range c.Tests {
					le, je := lib.Validate(tc.Data), sch.Validate(tc.Data, ValidateOptions{})
					compared++
					if (le == nil) != (je == nil) {
						key := name + ": " + c.Description + " / " + tc.Description
						if why, ok := knownVerdictDifferences[key]; ok {
							t.Logf("known difference: %s: %s", key, why)
							continue
						}
						t.Errorf("%s: %s / %s (suite says valid=%v):\n  library: %v\n  jsv:     %v", name, c.Description, tc.Description, tc.Valid, le, je)
					}
				}
			}
		}
	}
	t.Logf("%d instances compared; %d schemas refused by both", compared, bothRefuse)
}

// Where the two are known to differ, and why.
var (
	knownCompileDifferences = map[string]string{
		"cross-draft.json: refs to historic drafts are processed as historic drafts": "jsv implements draft 2020-12 only and refuses a schema of another draft with an *UnsupportedError",
	}
	knownVerdictDifferences = map[string]string{}
)

// TestDifferentialRandom validates generated documents, most of them
// nearly valid, against hand-written schemas with both validators.
func TestDifferentialRandom(t *testing.T) {
	const perSchema = 3000
	for _, ts := range testSchemas {
		t.Run(ts.name, func(t *testing.T) {
			raw := mustJSON(ts.schema)
			lib, err := libCompile(raw, nil)
			if err != nil {
				t.Fatal(err)
			}
			sch, err := Compile(raw, "", repoOptions(nil))
			if err != nil {
				t.Fatal(err)
			}
			r := rand.New(rand.NewSource(1))
			valid := 0
			for i := 0; i < perSchema; i++ {
				g := &generator{r: r, root: raw, noise: []float64{0, 0.02, 0.1}[i%3]}
				doc := g.gen(raw, 0)
				le, je := lib.Validate(doc), sch.Validate(doc, ValidateOptions{})
				if (le == nil) != (je == nil) {
					t.Fatalf("disagree on %s:\n  library: %v\n  jsv:     %v", jsonText(doc), le, je)
				}
				if je == nil {
					valid++
				}
			}
			t.Logf("%d documents, %d valid, %d invalid", perSchema, valid, perSchema-valid)
			if valid < perSchema/10 || valid > perSchema*9/10 {
				t.Errorf("the documents do not exercise both verdicts: %d of %d valid", valid, perSchema)
			}
		})
	}
}
