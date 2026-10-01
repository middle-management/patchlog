package schemaimport

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/middle-management/patchlog/internal/jsonv"
)

// Defaults for Options.
const (
	DefaultMaxDocs  = 100
	DefaultMaxBytes = 32 << 20
	DefaultTimeout  = 30 * time.Second
)

// limitError reports that a fetch limit was reached; it always ends the import.
type limitError string

func (e limitError) Error() string { return string(e) }

// fetcher loads documents over http(s) and from local files, within the
// limits of Options.
type fetcher struct {
	hc       *http.Client
	timeout  time.Duration
	maxDocs  int
	maxBytes int64
	docs     int
	bytes    int64
}

func newFetcher(opt Options) *fetcher {
	f := &fetcher{hc: opt.HTTPClient, timeout: opt.Timeout, maxDocs: opt.MaxDocs, maxBytes: opt.MaxBytes}
	if f.timeout <= 0 {
		f.timeout = DefaultTimeout
	}
	if f.maxDocs <= 0 {
		f.maxDocs = DefaultMaxDocs
	}
	if f.maxBytes <= 0 {
		f.maxBytes = DefaultMaxBytes
	}
	if f.hc == nil {
		f.hc = &http.Client{Transport: http.DefaultTransport.(*http.Transport).Clone()}
	} else {
		cp := *f.hc
		f.hc = &cp
	}
	f.hc.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return errors.New("too many redirects")
		}
		if req.URL.Scheme != "http" && req.URL.Scheme != "https" {
			return fmt.Errorf("redirect to %s is not http(s)", req.URL.Scheme)
		}
		return nil
	}
	return f
}

// sourceURL turns a command-line argument into an absolute URL: an http(s)
// URL as is, anything else a local file path.
func sourceURL(arg string) (*url.URL, error) {
	if strings.HasPrefix(arg, "http://") || strings.HasPrefix(arg, "https://") {
		u, err := url.Parse(arg)
		if err != nil || u.Host == "" {
			return nil, fmt.Errorf("invalid URL %q", arg)
		}
		u.Fragment, u.RawFragment = "", ""
		return u, nil
	}
	if strings.HasPrefix(arg, "file://") {
		u, err := url.Parse(arg)
		if err != nil {
			return nil, fmt.Errorf("invalid URL %q", arg)
		}
		u.Fragment, u.RawFragment = "", ""
		return u, nil
	}
	if strings.Contains(arg, "://") {
		return nil, fmt.Errorf("%q: only http(s) URLs and local files are supported", arg)
	}
	abs, err := filepath.Abs(arg)
	if err != nil {
		return nil, err
	}
	return &url.URL{Scheme: "file", Path: filepath.ToSlash(abs)}, nil
}

// fetch loads and parses the document at u (no fragment). It returns the
// final URL after redirects, which may differ from u.
func (f *fetcher) fetch(ctx context.Context, u *url.URL) (any, *url.URL, error) {
	if f.docs >= f.maxDocs {
		return nil, nil, limitError(fmt.Sprintf("more than %d documents (raise -max-docs)", f.maxDocs))
	}
	f.docs++
	remaining := f.maxBytes - f.bytes
	var body []byte
	final := u
	switch u.Scheme {
	case "file":
		fh, err := os.Open(filepath.FromSlash(u.Path))
		if err != nil {
			return nil, nil, err
		}
		defer fh.Close()
		body, err = io.ReadAll(io.LimitReader(fh, remaining+1))
		if err != nil {
			return nil, nil, err
		}
	case "http", "https":
		ctx, cancel := context.WithTimeout(ctx, f.timeout)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
		if err != nil {
			return nil, nil, err
		}
		req.Header.Set("Accept", "application/schema+json, application/json;q=0.9, */*;q=0.1")
		res, err := f.hc.Do(req)
		if err != nil {
			return nil, nil, err
		}
		defer res.Body.Close()
		if res.StatusCode != 200 {
			return nil, nil, fmt.Errorf("GET %s: %s", u, res.Status)
		}
		body, err = io.ReadAll(io.LimitReader(res.Body, remaining+1))
		if err != nil {
			return nil, nil, fmt.Errorf("GET %s: %w", u, err)
		}
		final = res.Request.URL
		final.Fragment, final.RawFragment = "", ""
	default:
		return nil, nil, fmt.Errorf("%s: only http(s) and local files are fetched", u)
	}
	if int64(len(body)) > remaining {
		return nil, nil, limitError(fmt.Sprintf("documents exceed %d bytes in total (raise -max-bytes)", f.maxBytes))
	}
	f.bytes += int64(len(body))
	// A UTF-8 byte order mark is not JSON, but some servers send one.
	body = bytes.TrimPrefix(body, []byte{0xEF, 0xBB, 0xBF})
	v, err := jsonv.Parse(body)
	if err != nil {
		return nil, nil, fmt.Errorf("%s: not I-JSON: %w", u, err)
	}
	return v, final, nil
}
