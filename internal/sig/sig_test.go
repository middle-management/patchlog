package sig

import (
	"crypto/ed25519"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/ids"
)

func testKey() Key {
	return Key{Kid: "k1", Priv: ed25519.NewKeyFromSeed(make([]byte, 32))}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	k := testKey()
	signers, err := ParseSigners([]any{k.Entry()})
	if err != nil {
		t.Fatal(err)
	}
	parent := ids.Of([]byte("p"))
	patches := []byte(`[{"op":"add","path":"/a","value":1}]`)
	h := k.SignPatches("https://cms.example", "ns", "doc", &parent, patches)
	s, err := Parse(h)
	if err != nil {
		t.Fatal(err)
	}
	if len(strings.Split(h, ":")[2]) != 86 {
		t.Fatalf("sig length: %q", h)
	}
	sg, ok := Find(signers, s.Kid)
	if !ok || !Verify(sg, s, Digest("https://cms.example", "ns", "doc", &parent, patches)) {
		t.Fatal("signature does not verify")
	}
	// Bound to origin, namespace, resource and parent.
	for _, d := range [][]byte{
		Digest("https://other.example", "ns", "doc", &parent, patches),
		Digest("https://cms.example", "ns2", "doc", &parent, patches),
		Digest("https://cms.example", "ns", "doc2", &parent, patches),
		Digest("https://cms.example", "ns", "doc", nil, patches),
	} {
		if Verify(sg, s, d) {
			t.Fatal("signature verified against another input")
		}
	}
}

func TestTombstoneIsNotEmptyAppend(t *testing.T) {
	k := testKey()
	parent := ids.Of([]byte("p"))
	tomb := Digest("o", "ns", "d", &parent, nil)
	empty := Digest("o", "ns", "d", &parent, []byte("[]"))
	if string(tomb) == string(empty) {
		t.Fatal("tombstone and empty append share a digest")
	}
	s, _ := Parse(k.SignTombstone("o", "ns", "d", parent))
	sg, _ := ParseSigners([]any{k.Entry()})
	if Verify(sg[0], s, empty) || !Verify(sg[0], s, tomb) {
		t.Fatal("tombstone signature confusion")
	}
}

func TestParseSignersRejects(t *testing.T) {
	good := testKey().Entry()
	with := func(k string, v any) map[string]any {
		m := map[string]any{}
		for a, b := range good {
			m[a] = b
		}
		if v == nil {
			delete(m, k)
		} else {
			m[k] = v
		}
		return m
	}
	for name, v := range map[string]any{
		"not array": map[string]any{},
		"extra":     []any{with("use", "sig")},
		"alg":       []any{with("alg", "ES256")},
		"colon kid": []any{with("kid", "a:b")},
		"no kid":    []any{with("kid", nil)},
		"padded":    []any{with("pub", good["pub"].(string)+"=")},
		"dup":       []any{good, good},
	} {
		if _, err := ParseSigners(v); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestParseKey(t *testing.T) {
	k, err := ParseKey("bot:" + b64.EncodeToString(make([]byte, 32)))
	if err != nil || k.Kid != "bot" {
		t.Fatal(k, err)
	}
	if _, err := ParseKey("nokid"); err == nil {
		t.Fatal("accepted a key without kid")
	}
}
