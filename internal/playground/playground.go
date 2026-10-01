// Package playground serves a small, dependency-free web UI for exploring the
// patch-log HTTP API (§7). The assets are embedded, need no build step and no
// network access, and talk to the API on the same origin.
package playground

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed static
var assets embed.FS

// Prefix is the URL path the playground is served under.
const Prefix = "/playground/"

// csp keeps the page honest: everything is same-origin, nothing external.
// Images may come from blob: URLs, for the previews of fetched blobs (§7.8).
const csp = "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; " +
	"img-src 'self' data: blob:; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"

// Handler serves the playground under /playground/. Mount it at that prefix;
// a request for /playground (no slash) is redirected.
func Handler() http.Handler {
	sub, err := fs.Sub(assets, "static")
	if err != nil {
		panic(err)
	}
	files := http.StripPrefix(Prefix, http.FileServer(http.FS(sub)))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == Prefix[:len(Prefix)-1] {
			http.Redirect(w, r, Prefix, http.StatusFound)
			return
		}
		h := w.Header()
		h.Set("Cache-Control", "no-cache")
		h.Set("Content-Security-Policy", csp)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		files.ServeHTTP(w, r)
	})
}
