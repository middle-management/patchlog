package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/middle-management/patchlog/internal/core"
	"github.com/middle-management/patchlog/internal/sig"
)

// followPurgesArgs are serve's flags for following the purges of trusted
// origins after imports (§G.1).
type followPurgesArgs struct {
	FollowPurgesFrom     []string      `arg:"--follow-purges-from,separate" placeholder:"ORIGIN" help:"an origin this deployment imports from and trusts, as import batches' source.origin records it (e.g. https://staging.example): its later purges of the names imported, and its namespace purges, are applied here as the server's own entries, in the namespace, its upstream namespace and their branches (§G.1); repeatable. A source naming an origin not listed purges nothing"`
	FollowPurgesImporter []string      `arg:"--follow-purges-importer,separate" placeholder:"ORIGIN=PRINCIPAL" help:"a principal (root sub, as namespace entries record the author) that imports from a --follow-purges-from origin: only its import batches, under a grant that may purge the names they write, are followed (§G.1); repeatable, and each origin needs at least one"`
	FollowPurgesBearer   []string      `arg:"--follow-purges-bearer,separate" placeholder:"ORIGIN=GRANT" help:"grant sent to a --follow-purges-from origin to read its namespace logs (repeatable)"`
	FollowPurgesURL      []string      `arg:"--follow-purges-url,separate" placeholder:"ORIGIN=URL" help:"reach a --follow-purges-from origin through URL instead (repeatable)"`
	FollowPurgesInterval time.Duration `arg:"--follow-purges-interval" default:"5m" placeholder:"DURATION" help:"how often the origins' logs are followed (0 disables following)"`
}

// options builds core's FollowPurgesOptions; own is the deployment's
// origin, which can't be followed.
func (a followPurgesArgs) options(own string) (core.FollowPurgesOptions, error) {
	o := core.FollowPurgesOptions{Interval: a.FollowPurgesInterval}
	if o.Interval == 0 {
		o.Interval = -1
	}
	if len(a.FollowPurgesFrom) > 0 {
		o.Origins = map[string]core.PurgeOrigin{}
	}
	for _, origin := range a.FollowPurgesFrom {
		if !sig.CanonicalOrigin(origin) {
			return o, fmt.Errorf("--follow-purges-from %q: want an origin as source.origin records it, scheme://host[:port] in lowercase without a default port or path", origin)
		}
		if origin == own {
			return o, fmt.Errorf("--follow-purges-from %s is this deployment's own origin", origin)
		}
		o.Origins[origin] = core.PurgeOrigin{}
	}
	for _, f := range []struct {
		flag string
		kvs  []string
		set  func(*core.PurgeOrigin, string)
	}{
		{"--follow-purges-importer", a.FollowPurgesImporter, func(p *core.PurgeOrigin, v string) { p.Importers = append(p.Importers, v) }},
		{"--follow-purges-bearer", a.FollowPurgesBearer, func(p *core.PurgeOrigin, v string) { p.Bearer = v }},
		{"--follow-purges-url", a.FollowPurgesURL, func(p *core.PurgeOrigin, v string) { p.BaseURL = v }},
	} {
		for _, kv := range f.kvs {
			origin, v, ok := strings.Cut(kv, "=")
			p, listed := o.Origins[origin]
			if !ok || v == "" {
				return o, fmt.Errorf("%s %q: want ORIGIN=VALUE", f.flag, kv)
			}
			if !listed {
				return o, fmt.Errorf("%s: %s is not a --follow-purges-from origin", f.flag, origin)
			}
			f.set(&p, v)
			o.Origins[origin] = p
		}
	}
	for origin, p := range o.Origins {
		if len(p.Importers) == 0 {
			// Any writer can assert a source: without the principals that
			// import from it, nothing of the origin's can be followed.
			return o, fmt.Errorf("--follow-purges-from %s: name the principals that import from it with --follow-purges-importer %s=PRINCIPAL (§G.1)", origin, origin)
		}
	}
	return o, nil
}
