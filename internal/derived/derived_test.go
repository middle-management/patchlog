package derived

import (
	"errors"
	"testing"

	"github.com/middle-management/patchlog/internal/seal"
)

func TestSealOpen(t *testing.T) {
	ke := seal.NewKey()
	k := Key{NS: "n", Epoch: 3, K: ke, Pad: true}
	v := View{NS: "n", Target: "/n/at/x?q=a"}
	keyOf := func(kid string) []byte {
		if kid == "n#3" {
			return ke
		}
		return nil
	}
	jwe, err := SealView(k, v, map[string]any{"hits": []any{"a"}})
	if err != nil {
		t.Fatal(err)
	}
	h, err := seal.ParseHeader(jwe)
	if err != nil || h.Kid != "n#3" || h.Zip != "" {
		t.Fatalf("header %+v %v", h, err)
	}
	pt, err := OpenView(jwe, keyOf, v)
	if err != nil || len(pt) != 256 || !seal.IsPadded(h, pt) {
		t.Fatalf("open: %d %v", len(pt), err)
	}
	if _, err := OpenView(jwe, keyOf, View{NS: "n", Target: "/n/at/x?q=b"}); !errors.Is(err, seal.ErrMismatch) {
		t.Fatalf("other view: %v", err)
	}
	if _, err := OpenView(jwe, func(string) []byte { return nil }, v); !errors.Is(err, ErrNoKey) {
		t.Fatalf("no key: %v", err)
	}
	item, err := SealItem(k, v, "r", map[string]any{"score": 1})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenItem(item, ItemKey(keyOf, "n", "r"), v, "n", "r"); err != nil {
		t.Fatalf("item: %v", err)
	}
	if _, err := OpenItem(item, keyOf, v, "n", "r"); !errors.Is(err, seal.ErrDecrypt) {
		t.Fatalf("item under K_e: %v", err)
	}
	if _, err := OpenItem(item, ItemKey(keyOf, "n", "s"), v, "n", "s"); err == nil {
		t.Fatal("item as another resource")
	}
}

func TestRecipientKey(t *testing.T) {
	_, priv, err := seal.GenerateRecipient()
	if err != nil {
		t.Fatal(err)
	}
	p, err := ParseRecipientKey(EncodeRecipientKey(priv) + "\n")
	if err != nil || !p.Equal(priv) {
		t.Fatalf("round trip: %v", err)
	}
	if _, err := ParseRecipientKey("short"); err == nil {
		t.Fatal("short key accepted")
	}
}
