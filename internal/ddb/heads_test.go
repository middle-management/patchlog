package ddb

import (
	"context"
	"strings"
	"testing"
)

// HeadsAt lists the heads a log entry saw (§7.4): names created later
// are absent, a head moved later is the one before, and a delete followed
// by a restore answers the tombstone at entries between the two — the
// case HIST# items alone don't settle (deletes put none).
func TestLocalHeadsAt(t *testing.T) {
	s := newLocalStore(t)
	ctx := context.Background()
	_, nsID := mustCreateNS(t, s, "h")
	a1 := mustWrite(t, s, "h", "a", "", `[{"op":"add","path":"","value":{"v":1}}]`)
	b1 := mustWrite(t, s, "h", "b", "", `[{"op":"add","path":"","value":{}}]`)
	d, err := s.DeleteResource(ctx, "h", "a", Pre{IfMatch: a1.ID}, "", "", "alice", nil)
	if err != nil {
		t.Fatal(err)
	}
	c1 := mustWrite(t, s, "h", "c", "", `[{"op":"add","path":"","value":{}}]`)
	a2 := mustWrite(t, s, "h", "a", d.ID, `[{"op":"add","path":"","value":{"v":2}}]`)

	at := func(id string, limit int) string {
		t.Helper()
		var out []string
		for after := ""; ; {
			page, next, found, err := s.HeadsAt(ctx, "h", id, after, limit)
			if err != nil || !found {
				t.Fatalf("heads at %s: %v %v", id, found, err)
			}
			for _, h := range page {
				switch {
				case h.Tombstoned && h.Created != 0 && h.Digest == nil:
					out = append(out, h.Name+"~"+h.ID)
				case !h.Tombstoned && h.Created != 0 && len(h.Digest) == 32 && h.Size > 0:
					out = append(out, h.Name+"="+h.ID)
				default:
					t.Fatalf("heads at %s: metadata of %+v", id, h)
				}
			}
			if after = next; after == "" {
				return strings.Join(out, ",")
			}
		}
	}
	want := func(parts ...string) string { return strings.Join(parts, ",") }
	for _, c := range []struct{ id, want string }{
		{nsID, ""},
		{a1.NSID, want("a=" + a1.ID)},
		{b1.NSID, want("a="+a1.ID, "b="+b1.ID)},
		{d.NSID, want("a~"+d.ID, "b="+b1.ID)},
		{c1.NSID, want("a~"+d.ID, "b="+b1.ID, "c="+c1.ID)},
		{a2.NSID, want("a="+a2.ID, "b="+b1.ID, "c="+c1.ID)},
	} {
		for _, limit := range []int{0, 1, 2} {
			if got := at(c.id, limit); got != c.want {
				t.Errorf("at %s, pages of %d: %s, want %s", c.id, limit, got, c.want)
			}
		}
	}
	if _, _, found, err := s.HeadsAt(ctx, "h", "nope", "", 0); err != nil || found {
		t.Fatalf("unknown entry: %v %v", found, err)
	}
}
