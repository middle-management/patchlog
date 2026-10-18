package client

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strconv"
)

// BlobStream is a blob being read (§7.8 Reading), streamed rather than
// read whole: Status is 200, or 206 for a range, and Body is the caller's
// to close.
type BlobStream struct {
	Status int
	Header http.Header
	Body   io.ReadCloser
}

// OpenBlob opens blob bid of ns/name for reading from byte from on (0:
// all of it; otherwise a Range request, which a server may answer whole,
// 200). The bytes aren't checked against the id, as GetBlob checks them. A
// pending or unknown blob is a 404 *APIError, a pruned or purged one a 410,
// and a sealed namespace's 302 (§E.2.2) an error.
func (c *Client) OpenBlob(ctx context.Context, ns, name, bid string, from int64) (*BlobStream, error) {
	if err := checkRes(ns, name); err != nil {
		return nil, err
	}
	if err := checkID("blob", bid); err != nil {
		return nil, err
	}
	path := "/r/" + ns + "/" + name + "/blob/" + bid
	hr, err := http.NewRequestWithContext(ctx, "GET", c.base+path, nil)
	if err != nil {
		return nil, err
	}
	c.setAuth(hr)
	if from > 0 {
		hr.Header.Set("Range", "bytes="+strconv.FormatInt(from, 10)+"-")
	}
	res, err := c.hc.Do(hr)
	if err != nil {
		return nil, err
	}
	switch res.StatusCode {
	case http.StatusOK, http.StatusPartialContent:
		return &BlobStream{Status: res.StatusCode, Header: res.Header, Body: res.Body}, nil
	}
	defer res.Body.Close()
	if res.StatusCode == http.StatusFound {
		return nil, fmt.Errorf("client: blob %s/%s/%s is sealed for delivery (§E.2.2): read it with GetBlobRef", ns, name, bid)
	}
	b, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	return nil, (&response{status: res.StatusCode, header: res.Header, body: b, method: "GET", path: path}).apiError()
}
