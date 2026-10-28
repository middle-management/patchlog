package core

import (
	"bytes"
	"errors"
	"log"
	"os"
	"strings"
	"testing"
)

// A runtime fault in a check is logged with its stack (panicErr); a
// panicked error, as t.must raises for a failed statement, is not.
func TestPanicErrLogsRuntimeFaults(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)
	_, err := ddbCheck(func() int { var m map[string]*int; return *m["x"] })
	if err == nil || !strings.Contains(buf.String(), "TestPanicErrLogsRuntimeFaults") {
		t.Fatalf("err %v, log %q", err, buf.String())
	}
	buf.Reset()
	ddbCheck(func() int { panic(errors.New("a failed statement")) })
	if strings.Contains(buf.String(), "a failed statement") {
		t.Fatalf("logged %q", buf.String())
	}
}
