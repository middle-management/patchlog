// Package testenv applies knobs of the test suite, read from the
// environment, to the engines tests start, so a whole run can exercise
// deployment settings that tests otherwise leave at their defaults:
//
//	PATCHLOG_TEST_LOG_PAGE_SIZE=2 go test ./...
//
// starts the test servers of API consumers (clienttest, bundles) with a log
// page size of 2 (§6.6), so every client that reads a log range must follow
// its pages (§7.1 Paging), and /heads pages after two items. It combines
// with PATCHLOG_TEST_PG (pgtest). The server package's own tests assert
// single raw answers and leave it alone; its paging tests set the page size
// themselves.
package testenv

import (
	"fmt"
	"os"
	"strconv"

	"github.com/middle-management/patchlog/internal/core"
)

// LogPageSizeEnv names the log page size test servers use.
const LogPageSizeEnv = "PATCHLOG_TEST_LOG_PAGE_SIZE"

// LogPageSize returns the log page size of PATCHLOG_TEST_LOG_PAGE_SIZE, or 0
// when it isn't set. A value that isn't a positive integer panics, so a typo
// doesn't silently run the defaults.
func LogPageSize() int {
	v := os.Getenv(LogPageSizeEnv)
	if v == "" {
		return 0
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 {
		panic(fmt.Sprintf("%s=%q: want a positive integer", LogPageSizeEnv, v))
	}
	return n
}

// Apply sets the knobs on o, before core.Open. A log page size a test sets
// itself (anything but the default) wins over the environment.
func Apply(o *core.Options) {
	n := LogPageSize()
	if n == 0 {
		return
	}
	if o.Maximums == (core.Limits{}) {
		// What core.Open would default them to.
		o.Maximums = o.Limits
		if o.Maximums == (core.Limits{}) {
			o.Maximums = core.DefaultLimits()
		}
	}
	if l := o.Maximums.LogPageSize; l == 0 || l == core.DefaultLimits().LogPageSize {
		o.Maximums.LogPageSize = n
	}
}
