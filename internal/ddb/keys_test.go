package ddb

import "testing"

func TestPadPos(t *testing.T) {
	for _, n := range []uint64{0, 1, 42, 999999999999} {
		s := padPos(n)
		if len(s) != posDigits {
			t.Fatalf("padPos(%d) = %q, want %d digits", n, s, posDigits)
		}
		back, err := parsePos(s)
		if err != nil || back != n {
			t.Fatalf("parsePos(padPos(%d)) = %d, %v", n, back, err)
		}
	}
	// Byte order is chain order.
	if !(padPos(1) < padPos(2)) || !(padPos(2) < padPos(10)) || !(padPos(10) < padPos(100)) {
		t.Fatal("padded positions do not sort in chain order")
	}
}

func TestKeyOrder(t *testing.T) {
	// /heads: resources list in byte order of name.
	if keyRes("d", "a").SK >= keyRes("d", "b").SK {
		t.Fatal("RES# keys do not sort by name")
	}
	// A begins_with(RES#) query never matches a revision: REV# sorts
	// after every RES# of its name... and nothing sorts between RES#name
	// and RES#name+1.
	if keyRev("d", "a", 1).SK < keyRes("d", "a").SK {
		t.Fatal("REV# sorts before RES#: resource listings would match revisions")
	}
	// The namespace's items share one partition.
	for _, k := range []Key{
		keyMeta("d"), keyTip("d"), keyCfg("d", 1), keyLog("d", 1),
		keyRes("d", "a"), keyRev("d", "a", 1), keyDocHead("d", "a"), keyHist("d", "a", 1),
	} {
		if k.PK != "NS#d" {
			t.Fatalf("key %+v outside the namespace's partition", k)
		}
	}
	// Log entries sort in chain order.
	if keyLog("d", 10).SK <= keyLog("d", 2).SK {
		t.Fatal("LOG# keys do not sort in chain order")
	}
	// #META and #TIP sort before every chain item ("#" < alnum).
	if !(keyMeta("d").SK < keyCfg("d", 1).SK) || !(keyTip("d").SK < keyLog("d", 1).SK) {
		t.Fatal("meta keys do not sort first")
	}
}

func TestNSIDKey(t *testing.T) {
	k := keyNSID("demo", "1abc")
	if k.PK != "NSID#demo#1abc" || k.SK != "#" {
		t.Fatalf("keyNSID = %+v", k)
	}
	// Entry ids are unique per namespace, not globally: the namespace is
	// part of the marker's key.
	if keyNSID("a", "1abc").PK == keyNSID("b", "1abc").PK {
		t.Fatal("NSID markers of two namespaces share a key")
	}
}
