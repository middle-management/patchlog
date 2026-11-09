package catvis

import (
	"reflect"
	"strings"
	"testing"
)

// TestV076V01KeySubject (§B.11.9 gs): the key subject differs by kid and
// by pub, can't be confused by a kid holding the separator, and is ignored
// by a View as "partial" and "scope:…" are.
func TestV076V01KeySubject(t *testing.T) {
	t.Parallel()
	subs := map[string]bool{}
	for _, k := range [][2]string{{"fan", "p1"}, {"fan2", "p1"}, {"fan", "p2"}, {"a:b", "c"}, {"a", "b:c"}} {
		s := KeySubject(k[0], k[1])
		if !strings.HasPrefix(s, KeyPrefix) || subs[s] {
			t.Fatalf("%v: %s", k, s)
		}
		subs[s] = true
	}
	if KeySubject("fan", "p1") != KeySubject("fan", "p1") {
		t.Fatal("not deterministic")
	}
	w1, g1 := whoOf([]string{"group:fans", "user:li", "scope:x"})
	w2, g2 := whoOf([]string{"group:fans", "user:li", "scope:x", KeySubject("fan", "p1")})
	if !reflect.DeepEqual(w1, w2) || !reflect.DeepEqual(g1, g2) {
		t.Fatalf("whoOf counts the key subject: %+v %v, %+v %v", w1, g1, w2, g2)
	}
}
