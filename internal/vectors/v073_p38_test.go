package vectors_test

// Checks of the stored vectors that hold whatever the generators compute:
// a payload sealed for a row of §E.2.2 is the payload a conforming server
// seals there, every /keys entry read opens to its key, and no group
// stores the reference's error text.

import (
	"bytes"
	"crypto/ecdh"
	"encoding/hex"
	"slices"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/seal"
	"github.com/middle-management/patchlog/internal/vectors/golden"
)

type storedVectors struct {
	Vectors []map[string]any `json:"vectors"`
}

func loadVectors(t *testing.T, name string) storedVectors {
	t.Helper()
	var f storedVectors
	if !golden.Load(t, name, &f) {
		t.Fatalf("testdata/%s.json is missing", name)
	}
	return f
}

// TestSealedPlaintextsServed: the grant row seals GET /ns/{ns}/grants/{gid}'s
// answer { id, root, stored } (§C.3.1), the range row the entries §7.4
// serves, with id, prev, author and created, the purge event row the
// namespace entry without id and prev (§7.3), and the resource log entry
// rows the entries §7.1 serves, author and created included (core
// LogEntry.value).
func TestSealedPlaintextsServed(t *testing.T) {
	t.Parallel()
	want := map[string][]string{
		"grant":                          {"id", "root", "stored"},
		"namespace log range":            {"author", "created", "id", "kind", "prev", "resource", "target"},
		"resource purge event":           {"created", "kind", "resource", "target"},
		"resource log entry (rev)":       {"author", "created", "id", "kind", "patches"},
		"resource log entry (tombstone)": {"author", "created", "id", "kind", "parent"},
	}
	seen := 0
	for _, v := range loadVectors(t, "sealed").Vectors {
		members, ok := want[v["name"].(string)]
		if !ok {
			continue
		}
		seen++
		pt := jsonv.MustParse([]byte(v["plaintext"].(string)))
		if a, ok := pt.([]any); ok {
			pt = a[0]
		}
		var got []string
		for k := range pt.(map[string]any) {
			got = append(got, k)
		}
		slices.Sort(got)
		if !slices.Equal(got, members) {
			t.Errorf("%s: plaintext members %v, want %v", v["name"], got, members)
		}
	}
	if seen != len(want) {
		t.Errorf("%d of the %d rows found", seen, len(want))
	}
}

// TestWrappedKeysOpen: every /keys entry the reference reads opens, under
// the name it is read with, to the key the vector gives.
func TestWrappedKeysOpen(t *testing.T) {
	t.Parallel()
	recipient := x25519(t, recipientSeed)
	for _, v := range loadVectors(t, "wrappedkeys").Vectors {
		if v["verdict"] != "accept" {
			continue
		}
		w, err := seal.ParseWrappedKey([]byte(v["entry"].(string)))
		if err != nil {
			t.Fatalf("%s: %v", v["name"], err)
		}
		key, _ := v["key"].(string)
		if key == "" {
			t.Errorf("%s: accepted without a key", v["name"])
			continue
		}
		want, _ := hex.DecodeString(key)
		got, err := seal.UnwrapRelayed(recipient, w, []*ecdh.PublicKey{x25519(t, senderSeed).PublicKey()})
		if err != nil || !bytes.Equal(got, want) {
			t.Errorf("%s: opens to %x, %v, want %s", v["name"], got, err, key)
		}
	}
}

// TestSealedBundleRules: each rejected sealed bundle names the rule it
// breaks. Since v0.74 the strict framing, canonical envelope and last
// beside pl are rules (§G.5.1.1), so those cases are rejected, not
// informative.
func TestSealedBundleRules(t *testing.T) {
	t.Parallel()
	strict := []string{"last beside pl (as written before v0.73)", "a blank line between sealed lines", "envelope not canonical",
		"protected header not canonical", "CRLF line ends", "no 0x0A after the last line", "an extra pl member"}
	seen := map[string]bool{}
	for _, v := range loadVectors(t, "sealedbundle").Vectors {
		name := v["name"].(string)
		seen[name] = true
		if _, ok := v["because"]; ok {
			t.Errorf("%s: stores the reference's error text", name)
		}
		if _, ok := v["informative"]; ok {
			t.Errorf("%s: marked informative", name)
		}
		rule, _ := v["rule"].(string)
		switch {
		case slices.Contains(strict, name) && v["verdict"] != "reject":
			t.Errorf("%s: not rejected (§G.5.1.1, v0.74)", name)
		case v["verdict"] == "reject" && !strings.Contains(rule, "§G."):
			t.Errorf("%s: rejected without the rule of §G.5.1.1 or §G.4.1 it breaks", name)
		}
	}
	for _, name := range strict {
		if !seen[name] {
			t.Errorf("no vector %q", name)
		}
	}
}
