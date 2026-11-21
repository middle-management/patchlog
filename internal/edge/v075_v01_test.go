package edge

import (
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/ids"
)

// §2.1 Edge prefix, §7.9: ParseCorePrefix takes /ns/{ns}/view/{view} with view
// an id in its canonical text, the origin's key vouches for it, and
// ParsePrefix keeps refusing it.
func TestV075ParseCorePrefix(t *testing.T) {
	t.Parallel()
	vid := ids.Of([]byte("x")).String()
	for p, want := range map[string]Prefix{
		"/r/demo/a":            {NS: "demo", Resource: "a"},
		"/r/demo":              {NS: "demo"},
		"/ns/demo":             {NS: "demo"},
		"/ns/demo/view/" + vid: {NS: "demo", View: vid},
	} {
		if got, ok := ParseCorePrefix(p); !ok || got != want {
			t.Errorf("%s: %+v %v", p, got, ok)
		}
	}
	for _, p := range []string{"/ns/demo/view/all", "/ns/demo/view/xyz", "/ns/demo/view/", "/r/demo/view/" + vid, "/ns/demo/view/" + vid + "/at",
		"/ns/demo/x/" + vid, "/ns/-x/view/" + vid, "/demo/view/" + vid} {
		if got, ok := ParseCorePrefix(p); ok {
			t.Errorf("%s accepted: %+v", p, got)
		}
	}
	if _, _, ok := ParsePrefix("/ns/demo/view/" + vid); ok {
		t.Error("ParsePrefix takes the g form")
	}
	c := NewCookies("", nil)
	if !c.VouchesFor("/ns/demo/view/"+vid) || c.VouchesFor("/ns/demo/view/all") {
		t.Error("VouchesFor")
	}
	now := time.Unix(1_800_000_000, 0)
	ck := c.Issue(Claims{Prefix: "/ns/demo/view/" + vid, Exp: now.Add(time.Minute).Unix()}, now)
	if cl, err := c.Verify(ck.Value, now); err != nil || cl.Prefix != "/ns/demo/view/"+vid {
		t.Errorf("Verify: %v %v", cl, err)
	}
}
