package tree_test

import (
	"testing"

	"github.com/middle-management/patchlog/internal/ids"
)

// TestAnonymousSubjectSetRedirect (§B.11.5): in a public catalog, an
// anonymous read of a subject set's URL redirects to the public URL
// space, and no shared cache keeps that redirect: an edge serves what it
// holds under a subject set's URL to every reader with that subject set's
// edge grant, who would be sent to the public listing.
func TestAnonymousSubjectSetRedirect(t *testing.T) {
	t.Parallel()
	w := setup(t)
	w.seed(t)
	x := startSvc(t, w.c, svcOpts{})
	x.caughtUp("cat", "matches")
	at := x.s.At()
	gs := ids.FromBytes(make([]byte, ids.Size)).String()
	for _, path := range []string{"/cat/g/" + gs + "/at/" + at + "/roots", "/cat/g/all/at/" + at + "/roots"} {
		r := x.raw(path, "")
		if r.status != 302 || r.header.Get("Location") != "/cat/at/"+at+"/roots" ||
			r.header.Get("Cache-Control") != "private, no-cache" || r.header.Get("CDN-Cache-Control") != "no-store" {
			t.Errorf("%s: %d %v", path, r.status, r.header)
		}
	}
	// The public URL space's own pointer stays public.
	if r := x.raw("/cat/roots", ""); r.status != 302 || r.header.Get("Cache-Control") != "public, max-age=0, s-maxage=1, stale-while-revalidate=5" {
		t.Errorf("public pointer: %d %v", r.status, r.header)
	}
}
