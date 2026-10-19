package client

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"time"
)

// PrincipalInfo is the answer of GET /ns/{ns}/principal (§7.4): what the
// client's grant is in a namespace, verified there, and what a writer
// needs from the namespace document, which a grant limited to some
// resources can't read (§2.1, §C.7).
type PrincipalInfo struct {
	// Principal is the principal of §6.4.1: id, groups, roles, attrs, via
	// and grant. It is nil with authentication disabled (§1), and Sub and
	// Kid are "".
	Principal map[string]any
	Sub, Kid  string // the root block's sub and signing key (§C.1)
	// Can are the verbs the grant's blocks allow, with roles only those an
	// effective role lists; Roles its effective roles.
	Can, Roles []string
	Writer     WriterInfo
	Config     string // the config revision in force (X-Config-Revision)
	Raw        map[string]any
}

// WriterInfo is what a writer needs from a namespace document (§7.4).
type WriterInfo struct {
	Frozen             bool
	Successor          string // "" if none
	NonceRequired      bool   // every patch set adds a fresh $nonce (§C.7, §E.2.5)
	SignaturesRequired bool   // every write carries a Signature (§C.3.1)
	Level              string // "at-rest", "sealed", "e2e", or "" without encryption
	// Limits are the limits in force, with the deployment's defaults and
	// maximums applied, keyed and written as §6.6 writes them.
	Limits map[string]any
}

// Size is a size or count limit of Limits, such as "patchSetSize".
func (w WriterInfo) Size(key string) (int64, bool) {
	n, ok := w.Limits[key].(float64)
	return int64(n), ok
}

// Duration is a duration limit of Limits, such as "retryWindow".
func (w WriterInfo) Duration(key string) (time.Duration, bool) {
	s, ok := w.Limits[key].(string)
	if !ok {
		return 0, false
	}
	d, err := parseISODuration(s)
	return d, err == nil
}

// Rate is a rate limit of Limits, such as "ratePerPrincipal": per second,
// and the bucket size.
func (w WriterInfo) Rate(key string) (rate, burst float64, ok bool) {
	m, _ := w.Limits[key].(map[string]any)
	rate, rok := m["rate"].(float64)
	burst, bok := m["burst"].(float64)
	return rate, burst, rok && bok
}

// HasVerb reports whether p.Can lists verb.
func (p *PrincipalInfo) HasVerb(verb string) bool {
	for _, v := range p.Can {
		if v == verb {
			return true
		}
	}
	return false
}

// NSPrincipal asks GET /ns/{ns}/principal (§7.4) with the client's grant:
// only the ns check and verification apply, so a grant limited to some
// resources, or without read, gets it too. A grant that can't be used, or
// none, is 401 even in a public namespace; a purged namespace is 410
// (IsPurged). A server before v0.55 answers 404. Unlike Principal, which
// decodes the bearer without verifying it, this is the server's verdict.
func (c *Client) NSPrincipal(ctx context.Context, ns string) (*PrincipalInfo, error) {
	if err := checkNS(ns); err != nil {
		return nil, err
	}
	r, err := c.do(ctx, "GET", "/ns/"+ns+"/principal", nil, nil)
	if err != nil {
		return nil, err
	}
	if r.status != 200 {
		return nil, r.apiError()
	}
	obj := r.obj()
	p := &PrincipalInfo{Kid: str(obj, "kid"), Can: strList(obj["can"]), Roles: strList(obj["roles"]),
		Config: r.header.Get("X-Config-Revision"), Raw: obj}
	if pr, ok := obj["principal"].(map[string]any); ok {
		p.Principal, p.Sub = pr, str(pr, "id")
	}
	w, _ := obj["writer"].(map[string]any)
	p.Writer.Frozen, _ = w["frozen"].(bool)
	p.Writer.Successor = str(w, "successor")
	p.Writer.NonceRequired = str(w, "nonce") == "required"
	p.Writer.SignaturesRequired = str(w, "signatures") == "required"
	p.Writer.Level = str(w, "level")
	p.Writer.Limits, _ = w["limits"].(map[string]any)
	return p, nil
}

var isoDurRe = regexp.MustCompile(`^P(?:(\d+)Y)?(?:(\d+)M)?(?:(\d+)W)?(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+(?:\.\d+)?)S)?)?$`)

// parseISODuration reads an ISO 8601 duration as §6.6 writes them, years
// as 365 days and months as 30, as the server does.
func parseISODuration(s string) (time.Duration, error) {
	m := isoDurRe.FindStringSubmatch(s)
	if m == nil || s == "P" || s[len(s)-1] == 'T' {
		return 0, fmt.Errorf("client: invalid duration %q", s)
	}
	var d time.Duration
	units := []time.Duration{365 * 24 * time.Hour, 30 * 24 * time.Hour, 7 * 24 * time.Hour, 24 * time.Hour, time.Hour, time.Minute}
	for i, u := range units {
		if m[i+1] != "" {
			n, err := strconv.ParseInt(m[i+1], 10, 64)
			if err != nil {
				return 0, fmt.Errorf("client: invalid duration %q", s)
			}
			d += time.Duration(n) * u
		}
	}
	if m[7] != "" {
		f, err := strconv.ParseFloat(m[7], 64)
		if err != nil {
			return 0, fmt.Errorf("client: invalid duration %q", s)
		}
		d += time.Duration(f * float64(time.Second))
	}
	return d, nil
}
