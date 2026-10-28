package ddbstore

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
	// The namespace's registry, chains, log and resource items share its
	// partition; a resource's own items are under its key.
	for _, k := range []Key{keyMeta("d"), keyTip("d"), keyCfg("d", 1), keyLog("d", 1), keyRes("d", "a")} {
		if k.PK != "NS#d" {
			t.Fatalf("key %+v outside the namespace's partition", k)
		}
	}
	for _, k := range []Key{
		keyRev("d", "a", 1), keyDocHead("d", "a"), keyHist("d", "a", 1), keySnap("d", "a", 1),
		keyBlob("d", "a", "b"), keyDEK("d", "a"), keyE2ESnap("d", "a", 1), keyBlobEpoch("d", "a", "b", 1), keyArch("d", "a", 1, 2),
	} {
		if k.PK != "R#d#a" {
			t.Fatalf("key %+v outside the resource's partition", k)
		}
		if pk, every := partitionOf("d", k.SK); pk != k.PK || every {
			t.Fatalf("partitionOf(%q) = %q, %v, want %q", k.SK, pk, every, k.PK)
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

// A prefix names the partition of its items: a resource type with a name
// its resource's, without one every resource's, the rest the namespace's.
func TestPartitionOf(t *testing.T) {
	for _, c := range []struct {
		prefix, pk string
		every      bool
	}{
		{"REV#a#", "R#d#a", false},
		{"BLOBEPOCH#a.b#x#", "R#d#a.b", false},
		{"DEK#", "", true},
		{"SNAP#", "", true},
		{"LOG#", "NS#d", false},
		{"RES#", "NS#d", false},
		{"PEND#a#", "NS#d", false},
		{"GEST#g#", "NS#d", false},
	} {
		if pk, every := partitionOf("d", c.prefix); pk != c.pk || every != c.every {
			t.Errorf("partitionOf(%q) = %q, %v, want %q, %v", c.prefix, pk, every, c.pk, c.every)
		}
	}
	for pk, ns := range map[string]string{"NS#d": "d", "R#d#a": "d", "R#d-1#a.b": "d-1"} {
		if got := nsOfPK(pk); got != ns {
			t.Errorf("nsOfPK(%q) = %q, want %q", pk, got, ns)
		}
	}
}
