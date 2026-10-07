package catalog_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

// §B.5: items in listings carry their content URL and current head. In a
// private content namespace (read "grant"), every item a reader may see
// (§B.11.5) carries them, in children and in subtree.
func TestPrivateListingsCarryHeadAndURL(t *testing.T) {
	w := setup(t)
	w.seed()
	w.start()
	w.caughtUp()
	list := func(path, token string) map[string]any {
		t.Helper()
		r := w.do("GET", path, token, nil)
		if r.status != 302 {
			t.Fatalf("GET %s: %d %v", path, r.status, r.body)
		}
		r = w.do("GET", r.header.Get("Location"), token, nil)
		if r.status != 200 {
			t.Fatalf("GET %s: %d %v", path, r.status, r.body)
		}
		return r.body
	}
	var check func(who string, v any) int
	check = func(who string, v any) int {
		n := 0
		switch x := v.(type) {
		case []any:
			for _, e := range x {
				n += check(who, e)
			}
		case map[string]any:
			if x["kind"] == "item" {
				n++
				name := x["name"].(string)
				ns, res, _ := strings.Cut(name, ".")
				h := must(w.ops.Head(context.Background(), ns, res))
				if x["head"] != h.ID || !strings.HasSuffix(fmt.Sprint(x["url"]), "/r/"+ns+"/"+res+"/rev/"+h.ID) {
					t.Errorf("%s: item %s without its head and url: %v (head %s)", who, name, x, h.ID)
				}
			}
			for _, k := range []string{"children", "tree"} {
				if c, ok := x[k]; ok {
					n += check(who, c)
				}
			}
		}
		return n
	}
	for _, c := range []struct{ who, token, of string }{
		{"fan", w.caller("user:fred", "fan-club"), "season"},
		{"li", w.caller("user:li", "fan-club"), "season"},
		{"eic", w.caller("user:eve", "editors-in-chief"), "rumours"},
		{"fan on derbies", w.caller("user:fred", "fan-club"), "derbies"},
		{"admin", w.opsKey.Grant(t, w.s.Now(), "user:ann", []string{"cat", "matches"}, []string{"read"}), "season"},
	} {
		for _, op := range []string{"children", "subtree"} {
			p := "/cat/" + op + "?of=" + c.of
			b := list(p, c.token)
			if n := check(c.who+" "+p, b); n == 0 {
				t.Errorf("%s %s: no items listed: %v", c.who, p, b)
			}
		}
	}
}
