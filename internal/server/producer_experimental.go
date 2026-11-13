package server

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/middle-management/patchlog/internal/core"
)

// EXPERIMENTAL, not in the spec (docs/SPEC-FEEDBACK.md, v0.82 Open 91):
// X-Experimental-Producer: {id};{epoch};{seq} is a single resource
// write's retry key (core/producer.go).
const producerHeader = "X-Experimental-Producer"

// producerOf parses the header, or returns nil without one.
func producerOf(r *http.Request) (*core.Producer, error) {
	h := r.Header.Get(producerHeader)
	if h == "" {
		return nil, nil
	}
	parts := strings.Split(h, ";")
	bad := badInput(producerHeader + " is {id};{epoch};{seq}, with a non-empty id of at most 128 bytes and non-negative integers")
	if len(parts) != 3 || parts[0] == "" || len(parts[0]) > 128 {
		return nil, bad
	}
	e, err1 := strconv.ParseInt(parts[1], 10, 64)
	q, err2 := strconv.ParseInt(parts[2], 10, 64)
	if err1 != nil || err2 != nil || e < 0 || q < 0 {
		return nil, bad
	}
	return &core.Producer{ID: parts[0], Epoch: e, Seq: q}, nil
}
