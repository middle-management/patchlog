package testenv

// The storage backend under test. The suites that test through the API
// (the server package's HTTP tests, and every package whose tests start a
// clienttest server) take their database from DB, so one run exercises
// whichever backend the environment names:
//
//	go test ./...                                         # SQLite, in memory
//	PATCHLOG_TEST_PG=postgres://… go test ./...           # Postgres (pgtest)
//	PATCHLOG_TEST_BACKEND=dynamodb DDB_ENDPOINT=http://localhost:8000 \
//	    go test ./internal/server/ ./internal/client/...  # DynamoDB Local
//
// Independently, PATCHLOG_TEST_BLOBS (BlobsEnv) moves their blob bytes from
// a temporary directory to S3.
//
// A backend that implements less than the spec (DynamoDB, docs/DYNAMODB.md
// §13) says so, and the harness turns that into a skip rather than a
// failure, so tests carry no per-backend annotations:
//
//   - core.Open refusing an option with core.ErrUnsupported (encryption at
//     rest, blob storage, authentication) skips the test (SkipUnsupported);
//   - an answer of 501 {"code":"unsupported"} skips it (Unsupported), as a
//     feature the backend hasn't built.
//
// A skip ends a test only from its own goroutine. A 501 a service's
// handler meets, calling the core from a goroutine of its own, can't skip
// the test; RecordUnsupported notes it on the server, and the test's
// failure names it.
//
// Every other difference fails, except the backend's known divergences
// (known_<backend>.txt, Known): tests that run and answer differently
// from the spec, listed with why, skipped until fixed — the backend's
// to-do list. PATCHLOG_TEST_KNOWN=run runs them anyway.

import (
	"bufio"
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/core"
	"github.com/middle-management/patchlog/internal/ddb"
	"github.com/middle-management/patchlog/internal/pgtest"
	"github.com/middle-management/patchlog/internal/s3blobs"
)

// The backend knobs.
const (
	BackendEnv = "PATCHLOG_TEST_BACKEND" // "sqlite" (default), "postgres", "dynamodb"
	DDBEnv     = "DDB_ENDPOINT"          // DynamoDB Local's URL, for "dynamodb"
	KnownEnv   = "PATCHLOG_TEST_KNOWN"   // "run": don't skip known divergences
)

// The backends.
const (
	SQLite   = "sqlite"
	Postgres = "postgres"
	DynamoDB = "dynamodb"
)

// Backend names the backend under test: PATCHLOG_TEST_BACKEND, else
// Postgres when PATCHLOG_TEST_PG is set (pgtest), else SQLite. An unknown
// name panics, so a typo doesn't silently run SQLite.
func Backend() string {
	switch v := os.Getenv(BackendEnv); v {
	case "":
		if pgtest.Enabled() {
			return Postgres
		}
		return SQLite
	case SQLite, Postgres, DynamoDB:
		return v
	default:
		panic(fmt.Sprintf("%s=%q: want %q, %q or %q", BackendEnv, v, SQLite, Postgres, DynamoDB))
	}
}

var tables atomic.Int64

// DB returns a database for one test on the backend under test: SQLite in
// memory, a Postgres database of the pool (pgtest.DB), or a fresh
// DynamoDB table, deleted when the test ends.
func DB(t testing.TB) string {
	t.Helper()
	if Backend() != DynamoDB {
		return pgtest.DB(t)
	}
	return newTable(t)
}

// NewDB is DB for a test that reopens its database, or opens several
// engines on it: a fresh database it may keep (pgtest.NewDB), or a table;
// on SQLite, a file in the test's temporary directory.
func NewDB(t testing.TB) string {
	t.Helper()
	switch Backend() {
	case DynamoDB:
		return newTable(t)
	case Postgres:
		return pgtest.NewDB(t)
	}
	return filepath.Join(t.TempDir(), "test.db")
}

func newTable(t testing.TB) string {
	t.Helper()
	ep := os.Getenv(DDBEnv)
	if ep == "" {
		t.Fatalf("%s=%s needs %s (DynamoDB Local's URL)", BackendEnv, DynamoDB, DDBEnv)
	}
	url := fmt.Sprintf("dynamodb://test-%d-%d?region=us-east-1&endpoint=%s", time.Now().UnixNano(), tables.Add(1), ep)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := ddb.CreateTable(ctx, url); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ddb.DeleteTable(context.Background(), url) })
	return url
}

// BlobsEnv picks the blob store the harnesses give the engines they start
// by default (Blobs): unset, a temporary directory per test; an s3:// URL
// (internal/s3blobs), a prefix of that bucket per test, emptied when the
// test ends. The bucket is created if missing, and credentials come from
// the AWS chain:
//
//	AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test \
//	PATCHLOG_TEST_BLOBS='s3://patchlog-test?region=us-east-1&endpoint=http://localhost:8333' \
//	    go test ./...
const BlobsEnv = "PATCHLOG_TEST_BLOBS"

var (
	s3Once  sync.Once
	s3Store *s3blobs.Store
	s3Err   error
	s3Seq   atomic.Int64
)

// Blobs sets the blob store of an engine a harness starts (BlobsEnv).
func Blobs(t testing.TB, o *core.Options) {
	t.Helper()
	url := os.Getenv(BlobsEnv)
	if url == "" {
		o.BlobDir = t.TempDir()
		return
	}
	s3Once.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if s3Store, s3Err = s3blobs.Open(ctx, url); s3Err == nil {
			s3Err = s3Store.CreateBucket(ctx)
		}
	})
	if s3Err != nil {
		t.Fatalf("%s: %v", BlobsEnv, s3Err)
	}
	s := s3Store.Sub(fmt.Sprintf("test-%d-%d", time.Now().UnixNano(), s3Seq.Add(1)))
	o.BlobStore = s
	t.Cleanup(func() {
		ctx := context.Background()
		var names []string
		s.List(ctx, func(name string, _ int64, _ time.Time) error {
			names = append(names, name)
			return nil
		})
		for _, n := range names {
			s.Remove(ctx, n)
		}
	})
}

// SkipUnsupported skips the test when core.Open refused an option the
// backend doesn't implement (core.ErrUnsupported).
func SkipUnsupported(t testing.TB, err error) {
	t.Helper()
	if errors.Is(err, core.ErrUnsupported) {
		t.Skipf("%s backend: %v", Backend(), err)
	}
}

// Unsupported skips the test when an answer is the backend's 501
// {"code":"unsupported"}: a feature it hasn't built. Harnesses call it on
// every answer they read, from the test's goroutine.
func Unsupported(t testing.TB, status int, body []byte) {
	t.Helper()
	if status != 501 {
		return
	}
	var b struct{ Code, Message string }
	if json.Unmarshal(body, &b) == nil && b.Code == "unsupported" {
		t.Skipf("%s backend: %s", Backend(), b.Message)
	}
}

// RecordUnsupported wraps a test server's handler to note its 501
// {"code":"unsupported"} answers, and logs them if the test fails: the
// failure then follows from a feature the backend hasn't built, met where
// Unsupported couldn't skip.
func RecordUnsupported(t testing.TB, h http.Handler) http.Handler {
	var mu sync.Mutex
	seen := map[string]bool{}
	t.Cleanup(func() {
		mu.Lock()
		defer mu.Unlock()
		if t.Failed() && len(seen) > 0 {
			for msg := range seen {
				t.Logf("%s backend answered 501 unsupported during this test: %s", Backend(), msg)
			}
		}
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := &statusRecorder{ResponseWriter: w}
		h.ServeHTTP(rec, r)
		if rec.status != http.StatusNotImplemented {
			return
		}
		var b struct{ Code, Message string }
		if json.Unmarshal(rec.body.Bytes(), &b) == nil && b.Code == "unsupported" {
			mu.Lock()
			seen[b.Message] = true
			mu.Unlock()
		}
	})
}

// statusRecorder notes an answer's status, and keeps a 501's body.
type statusRecorder struct {
	http.ResponseWriter
	status int
	body   bytes.Buffer
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	if r.status == http.StatusNotImplemented {
		r.body.Write(b)
	}
	return r.ResponseWriter.Write(b)
}

// Unwrap lets http.ResponseController reach the server's writer.
func (r *statusRecorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }

// Flush passes streaming answers on (event streams).
func (r *statusRecorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Goroutine is the calling goroutine's id, to tell a test's own goroutine
// from others (a skip ends only the former).
func Goroutine() uint64 {
	var buf [64]byte
	b := buf[:runtime.Stack(buf[:], false)]
	b = bytes.TrimPrefix(b, []byte("goroutine "))
	n, _ := strconv.ParseUint(string(b[:bytes.IndexByte(b, ' ')]), 10, 64)
	return n
}

//go:embed known_*.txt
var knownFiles embed.FS

var (
	knownOnce sync.Once
	known     map[string]string // "pkg/TestName" → why
)

// Known skips a test listed among the backend's known divergences
// (known_<backend>.txt: one "pkg/TestName why" a line, pkg the test's
// directory name, "pkg/*" for a whole package, # comments), unless
// PATCHLOG_TEST_KNOWN=run. Harnesses
// call it as they start a server; subtests are matched by their top-level
// test.
func Known(t testing.TB) {
	t.Helper()
	if os.Getenv(KnownEnv) == "run" {
		return
	}
	knownOnce.Do(loadKnown)
	pkg := testPkg()
	why, ok := known[pkg+"/"+strings.SplitN(t.Name(), "/", 2)[0]]
	if !ok {
		why, ok = known[pkg+"/*"]
	}
	if ok {
		t.Skipf("known divergence on %s: %s (%s=run runs it)", Backend(), why, KnownEnv)
	}
}

func loadKnown() {
	known = map[string]string{}
	f, err := knownFiles.Open("known_" + Backend() + ".txt")
	if err != nil {
		return // none listed
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, why, _ := strings.Cut(line, " ")
		known[key] = strings.TrimSpace(why)
	}
}

// testPkg is the directory name of the _test.go file on the stack: the
// package whose test is running, whichever harness package asks.
func testPkg() string {
	pcs := make([]uintptr, 32)
	frames := runtime.CallersFrames(pcs[:runtime.Callers(2, pcs)])
	for {
		f, more := frames.Next()
		if strings.HasSuffix(f.File, "_test.go") {
			return filepath.Base(filepath.Dir(f.File))
		}
		if !more {
			return ""
		}
	}
}
