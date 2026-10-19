package dav

import (
	"fmt"
	"testing"
)

// idUsers over its bound: the verifying namespace keeping the most ids
// gives way, then its issuer keeping the most, then that issuer's least
// recently verified; a user over its own bound loses its least recently
// verified. A flood of one key holder's subs, of the kids it adds to its
// namespace, or of a second issuer of alice's namespace, pushes out only
// its own ids, and alice's idle one stays.
func TestIDUsersBounds(t *testing.T) {
	const all, perUser = 16, 4
	u := func(ns, kid, sub string) idUser {
		return idUser{user: ns + "\x00" + kid + "\x00" + sub, vns: ns, issuer: ns + "\x00" + kid}
	}
	for _, flood := range []string{"subs", "kids", "issuer"} {
		var x idUsers
		x.init(all, perUser)
		x.put("alice", u("alpha", "k", "alice"))
		x.put("bob", u("docs", "k", "bob"))
		for i := 0; i < 10*all; i++ {
			switch flood {
			case "subs":
				x.put(fmt.Sprintf("m%d", i), u("mal", "mk", fmt.Sprintf("m%d", i)))
			case "kids":
				x.put(fmt.Sprintf("m%d", i), u("mal", fmt.Sprintf("mk%d", i), "m"))
			case "issuer":
				x.put(fmt.Sprintf("m%d", i), u("alpha", "mk", fmt.Sprintf("m%d", i)))
			}
		}
		if len(x.ids) != all {
			t.Errorf("%s: %d ids kept, want %d", flood, len(x.ids), all)
		}
		for _, id := range []string{"alice", "bob", fmt.Sprintf("m%d", 10*all-1)} {
			if _, ok := x.get(id); !ok {
				t.Errorf("%s: %s pushed out", flood, id)
			}
		}
		if _, ok := x.get("m0"); ok {
			t.Errorf("%s: the flood's first id kept", flood)
		}
	}
	var x idUsers
	x.init(all, perUser)
	for i := 0; i < 2*perUser; i++ {
		x.put(fmt.Sprintf("n%d", i), u("docs", "k", "mallory"))
	}
	for i := 0; i < 2*perUser; i++ {
		if _, ok := x.get(fmt.Sprintf("n%d", i)); ok != (i >= perUser) {
			t.Errorf("mallory's narrowing %d kept: %v", i, ok)
		}
	}
	// Verified again as another user, the id is that user's alone.
	x.put("n7", u("alpha", "k", "mallory"))
	if got, _ := x.get("n7"); got.vns != "alpha" || x.users[u("docs", "k", "mallory").user].Len() != perUser-1 || x.nss["docs"].n != perUser-1 || x.nss["alpha"].n != 1 {
		t.Errorf("n7 verified again by alpha: %+v, docs %d, alpha %d", got, x.nss["docs"].n, x.nss["alpha"].n)
	}
}
