package ddbstore

import (
	"context"
	"testing"
)

// HeadAt is a resource's head as of a log entry (§7.4's /heads at an
// entry, core's resolve asOf): absent before its create, the one before a
// later move, and the tombstone at entries between a delete and the
// restore that followed — the case HIST# items alone don't settle
// (deletes put none).
func TestLocalHeadAt(t *testing.T) {
	s := newLocalStore(t)
	ctx := context.Background()
	_, nsID := mustCreateNS(t, s, "h")
	a1 := mustWrite(t, s, "h", "a", "", `[{"op":"add","path":"","value":{"v":1}}]`)
	b1 := mustWrite(t, s, "h", "b", "", `[{"op":"add","path":"","value":{}}]`)
	d := mustWrite(t, s, "h", "a", a1.ID, "")
	c1 := mustWrite(t, s, "h", "c", "", `[{"op":"add","path":"","value":{}}]`)
	a2 := mustWrite(t, s, "h", "a", d.ID, `[{"op":"add","path":"","value":{"v":2}}]`)

	head := func(entry, name string) string {
		t.Helper()
		pos, err := s.EntryPos(ctx, "h", entry)
		if err != nil || pos == 0 {
			t.Fatalf("entry %s: %d %v", entry, pos, err)
		}
		h, err := s.HeadAt(ctx, "h", name, pos)
		switch {
		case err != nil:
			t.Fatal(err)
		case h == nil:
			return ""
		case h.Tombstoned && h.Created != 0 && h.Digest == nil:
			return "~" + h.ID
		case !h.Tombstoned && h.Created != 0 && len(h.Digest) == 32 && h.Size > 0:
			return "=" + h.ID
		}
		t.Fatalf("%s at %s: metadata of %+v", name, entry, h)
		return ""
	}
	for _, c := range []struct{ entry, a, b, c string }{
		{nsID, "", "", ""},
		{a1.NSID, "=" + a1.ID, "", ""},
		{b1.NSID, "=" + a1.ID, "=" + b1.ID, ""},
		{d.NSID, "~" + d.ID, "=" + b1.ID, ""},
		{c1.NSID, "~" + d.ID, "=" + b1.ID, "=" + c1.ID},
		{a2.NSID, "=" + a2.ID, "=" + b1.ID, "=" + c1.ID},
	} {
		if got := [3]string{head(c.entry, "a"), head(c.entry, "b"), head(c.entry, "c")}; got != [3]string{c.a, c.b, c.c} {
			t.Errorf("at %s: %v, want %v", c.entry, got, [3]string{c.a, c.b, c.c})
		}
	}
}
