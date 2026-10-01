package schemaimport

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"
)

// ErrFetchDisabled is what a client from DisabledClient answers.
var ErrFetchDisabled = errors.New("fetching URLs is disabled on this server (serve -schema-fetch)")

// DisabledClient is an HTTP client that fetches nothing.
func DisabledClient() *http.Client {
	return &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, ErrFetchDisabled })}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// GuardedClient is an HTTP client for a server that fetches URLs on behalf
// of its callers, with the checks that keep it from being a way into the
// network it sits in:
//
//   - With a non-empty allowlist, only those hosts are fetched, redirects
//     and references included. An entry is a host name or IP, or host:port.
//   - A host that is not on the allowlist is refused if any address it
//     resolves to is loopback, private, link-local, multicast or
//     unspecified (and the connection goes to the address checked, so the
//     name can't change under it). A host on the allowlist is trusted.
//   - Environment proxy settings are ignored: the check has to see the
//     address that is dialled.
func GuardedClient(allow []string) *http.Client {
	g := &guard{allow: map[string]bool{}}
	for _, h := range allow {
		if h = strings.ToLower(strings.TrimSpace(h)); h != "" {
			g.allow[h] = true
		}
	}
	d := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	g.dial = d.DialContext
	return &http.Client{Transport: &http.Transport{
		Proxy:                 nil,
		DialContext:           g.dialContext,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 20 * time.Second,
		MaxIdleConnsPerHost:   2,
		IdleConnTimeout:       30 * time.Second,
	}}
}

type guard struct {
	allow map[string]bool
	dial  func(ctx context.Context, network, addr string) (net.Conn, error)
}

func (g *guard) dialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	host = strings.ToLower(host)
	listed := g.allow[host] || g.allow[net.JoinHostPort(host, port)]
	if len(g.allow) > 0 && !listed {
		return nil, fmt.Errorf("%s is not on the list of hosts schemas may be fetched from", host)
	}
	if listed {
		return g.dial(ctx, network, addr)
	}
	var ips []netip.Addr
	if ip, err := netip.ParseAddr(host); err == nil {
		ips = []netip.Addr{ip}
	} else {
		rs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		if err != nil {
			return nil, err
		}
		ips = rs
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("%s does not resolve", host)
	}
	for _, ip := range ips {
		if blocked(ip) {
			return nil, fmt.Errorf("%s resolves to %s: private, loopback and link-local addresses are not fetched", host, ip.Unmap())
		}
	}
	var last error
	for _, ip := range ips {
		c, err := g.dial(ctx, network, net.JoinHostPort(ip.Unmap().String(), port))
		if err == nil {
			return c, nil
		}
		last = err
	}
	return nil, last
}

var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// blocked reports whether ip is an address a server must not fetch from on
// a caller's say-so.
func blocked(ip netip.Addr) bool {
	ip = ip.Unmap()
	return !ip.IsValid() || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() || ip.IsUnspecified() || ip.IsInterfaceLocalMulticast() || cgnat.Contains(ip) ||
		(ip.Is4() && ip.As4()[0] == 0)
}

// BlockedAddr is blocked for the textual form of an IP address.
func BlockedAddr(s string) bool {
	ip, err := netip.ParseAddr(s)
	return err != nil || blocked(ip)
}
