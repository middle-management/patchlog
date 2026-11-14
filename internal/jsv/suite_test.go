package jsv

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// The official JSON Schema Test Suite is not in the repository: point
// JSON_SCHEMA_TEST_SUITE at a checkout of
// github.com/json-schema-org/JSON-Schema-Test-Suite to run these tests.
const suiteEnv = "JSON_SCHEMA_TEST_SUITE"

type suiteCase struct {
	Description string `json:"description"`
	Schema      any    `json:"schema"`
	Tests       []struct {
		Description string `json:"description"`
		Data        any    `json:"data"`
		Valid       bool   `json:"valid"`
	} `json:"tests"`
}

func suiteDir(t testing.TB) string {
	dir := os.Getenv(suiteEnv)
	if dir == "" {
		t.Skip(suiteEnv + " is not set")
	}
	return dir
}

func readSuiteFile(t testing.TB, path string) []suiteCase {
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var cases []suiteCase
	if err := json.Unmarshal(data, &cases); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return cases
}

// suiteFiles lists the test files of a directory of the suite, relative to
// tests/draft2020-12.
func suiteFiles(t testing.TB, dir, sub string) []string {
	matches, err := filepath.Glob(filepath.Join(dir, "tests", "draft2020-12", sub, "*.json"))
	if err != nil || len(matches) == 0 {
		t.Fatalf("no test files in %s (%v)", filepath.Join(dir, sub), err)
	}
	sort.Strings(matches)
	return matches
}

// suiteLoader serves the suite's remotes directory as
// http://localhost:1234/, as the suite asks.
func suiteLoader(dir string) func(string) (any, error) {
	return func(uri string) (any, error) {
		rest, ok := strings.CutPrefix(uri, "http://localhost:1234/")
		if !ok {
			return nil, fmt.Errorf("no such document: %s", uri)
		}
		data, err := os.ReadFile(filepath.Join(dir, "remotes", filepath.FromSlash(rest)))
		if err != nil {
			return nil, err
		}
		var v any
		if err := json.Unmarshal(data, &v); err != nil {
			return nil, err
		}
		return v, nil
	}
}

// runSuiteFile runs one file and returns how many tests passed and the
// failures.
func runSuiteFile(t testing.TB, dir, path string, assertFormat bool) (passed int, failures []string) {
	for _, c := range readSuiteFile(t, path) {
		sch, err := Compile(c.Schema, "", Options{Load: suiteLoader(dir), AssertFormat: assertFormat})
		if err != nil {
			failures = append(failures, fmt.Sprintf("%s: compile: %v", c.Description, err))
			continue
		}
		for _, tc := range c.Tests {
			err := sch.Validate(tc.Data, ValidateOptions{})
			if (err == nil) == tc.Valid {
				passed++
				continue
			}
			failures = append(failures, fmt.Sprintf("%s / %s: want valid=%v, got %v", c.Description, tc.Description, tc.Valid, err))
		}
	}
	return passed, failures
}

// TestSuiteRequired runs every required test of draft 2020-12. Format is an
// annotation there (format.json expects malformed values to pass).
func TestSuiteRequired(t *testing.T) {
	dir := suiteDir(t)
	total := 0
	for _, path := range suiteFiles(t, dir, "") {
		passed, failures := runSuiteFile(t, dir, path, false)
		total += passed
		for _, f := range failures {
			t.Errorf("%s: %s", filepath.Base(path), f)
		}
	}
	t.Logf("%d required tests passed", total)
}

// TestSuiteOptional runs the optional tests for information: it logs what
// fails and fails nothing.
func TestSuiteOptional(t *testing.T) {
	dir := suiteDir(t)
	for _, sub := range []string{"optional", "optional/format"} {
		for _, path := range suiteFiles(t, dir, sub) {
			passed, failures := runSuiteFile(t, dir, path, sub == "optional/format")
			t.Logf("%s/%s: %d passed, %d failed", sub, filepath.Base(path), passed, len(failures))
			for _, f := range failures {
				t.Logf("    %s", f)
			}
		}
	}
}
