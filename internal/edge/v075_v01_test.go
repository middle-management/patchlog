package edge

import (
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/ids"
)

// §2.1 Edge prefix, §B.11.9: ParseCorePrefix takes /ns/{ns}/g/{gs} with gs
// an id in its canonical text, the origin's key vouches for it, and
// ParsePrefix keeps refusing it.
func TestV075ParseCorePrefix(t *testing.T) {
	t.Parallel()
	gs := ids.Of([]byte("x")).String()
	for p, want := range map[string]Prefix{
		"/r/demo/a":        {NS: "demo", Resource: "a"},
		"/r/demo":          {NS: "demo"},
		"/ns/demo":         {NS: "demo"},
		"/ns/demo/g/" + gs: {NS: "demo", GS: gs},
	} {
		if got, ok := ParseCorePrefix(p); !ok || got != want {
			t.Errorf("%s: %+v %v", p, got, ok)
		}
	}
	for _, p := range []string{"/ns/demo/g/all", "/ns/demo/g/xyz", "/ns/demo/g/", "/r/demo/g/" + gs, "/ns/demo/g/" + gs + "/at",
		"/ns/demo/x/" + gs, "/ns/-x/g/" + gs, "/demo/g/" + gs} {
		if got, ok := ParseCorePrefix(p); ok {
			t.Errorf("%s accepted: %+v", p, got)
		}
	}
	if _, _, ok := ParsePrefix("/ns/demo/g/" + gs); ok {
		t.Error("ParsePrefix takes the g form")
	}
	c := NewCookies("", nil)
	if !c.VouchesFor("/ns/demo/g/"+gs) || c.VouchesFor("/ns/demo/g/all") {
		t.Error("VouchesFor")
	}
	now := time.Unix(1_800_000_000, 0)
	ck := c.Issue(Claims{Prefix: "/ns/demo/g/" + gs, Exp: now.Add(time.Minute).Unix()}, now)
	if cl, err := c.Verify(ck.Value, now); err != nil || cl.Prefix != "/ns/demo/g/"+gs {
		t.Errorf("Verify: %v %v", cl, err)
	}
}
