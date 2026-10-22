package verify_test

import (
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/verify"
)

// §6.2 step 3 (GB-8): a genesis applies to the document null, as the
// server applied the create, so test "" null and a root replace replay,
// whatever the starting document; a restore still applies to the last
// live document.
func TestV073P15ReplayGenesisOnNull(t *testing.T) {
	ps := func(s string) any { return jsonv.MustParse([]byte(s)) }
	entries := []client.LogEntry{
		{ID: "g", Kind: "rev", HasPatches: true, Patches: ps(`[{"op":"test","path":"","value":null},{"op":"add","path":"","value":{"n":1}}]`)},
		{ID: "t", Parent: "g", Kind: "tombstone"},
		{ID: "r", Parent: "t", Kind: "rev", HasPatches: true, Patches: ps(`[{"op":"add","path":"/m","value":2}]`)},
	}
	doc, live, err := verify.Replay(nil, false, entries)
	if err != nil || !live || string(jsonv.Canonical(doc)) != `{"m":2,"n":1}` {
		t.Fatalf("replay: %v %v %v", doc, live, err)
	}
	doc, live, err = verify.Replay(map[string]any{"old": true}, false, []client.LogEntry{
		{ID: "g", Kind: "rev", HasPatches: true, Patches: ps(`[{"op":"replace","path":"","value":{"b":true}}]`)},
	})
	if err != nil || !live || string(jsonv.Canonical(doc)) != `{"b":true}` {
		t.Fatalf("root replace: %v %v %v", doc, live, err)
	}
}
