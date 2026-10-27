package playground

import (
	"crypto/ecdh"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

const wrappedKeysHarness = `
const fs = require('fs');
const [sealJS, vecJSON, recipient, sender] = process.argv.slice(2);
require(sealJS);
const Z = globalThis.PLSeal;
const vec = JSON.parse(fs.readFileSync(vecJSON, 'utf8'));
(async () => {
  const id = await Z.identityFromPrivate(recipient);
  const out = [];
  for (const v of vec.vectors) {
    let got;
    try {
      got = { key: Z.hex(await Z.unwrapRelayedKey(id, JSON.parse(v.entry), [sender])) };
    } catch (e) { got = { err: e.message }; }
    out.push({ name: v.name, verdict: v.verdict, want: v.key || '', ...got });
  }
  console.log(JSON.stringify(out));
})();
`

// w4x (P38 x the playground), §E.2.3: the playground's /keys reader
// (seal.js unwrapRelayedKey) takes the entries of wrappedkeys.json as the
// Go readers do (seal.ParseWrappedKey): it rejects every rejected entry,
// name and resource differing, another suite and a from that isn't a
// thumbprint included, and opens every accepted one to the vector's key.
func TestV073W4xPlaygroundWrappedKeysVectors(t *testing.T) {
	t.Parallel()
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed")
	}
	seq := func(n byte) []byte {
		b := make([]byte, 32)
		for i := range b {
			b[i] = n + byte(i)
		}
		return b
	}
	recipient, err := ecdh.X25519().NewPrivateKey(seq(0x20))
	if err != nil {
		t.Fatal(err)
	}
	sender, err := ecdh.X25519().NewPrivateKey(seq(0x40))
	if err != nil {
		t.Fatal(err)
	}
	h := filepath.Join(t.TempDir(), "harness.js")
	if err := os.WriteFile(h, []byte(wrappedKeysHarness), 0o644); err != nil {
		t.Fatal(err)
	}
	sealJS, _ := filepath.Abs("static/seal.js")
	vecJSON, _ := filepath.Abs("../vectors/testdata/wrappedkeys.json")
	out, err := exec.Command(node, h, sealJS, vecJSON, b64.EncodeToString(recipient.Bytes()), b64.EncodeToString(sender.PublicKey().Bytes())).CombinedOutput()
	if err != nil {
		t.Fatalf("node: %v\n%s", err, out)
	}
	var got []struct{ Name, Verdict, Want, Key, Err string }
	if err := json.Unmarshal(out, &got); err != nil || len(got) == 0 {
		t.Fatalf("node output %s: %v", out, err)
	}
	rejects := 0
	for _, g := range got {
		switch g.Verdict {
		case "accept":
			if g.Err != "" || g.Key != g.Want {
				t.Errorf("%s: the playground opens it to %q (%s), want %s", g.Name, g.Key, g.Err, g.Want)
			}
		case "reject":
			rejects++
			if g.Err == "" {
				t.Errorf("%s: the playground accepts it (%s), the vector rejects it", g.Name, g.Key)
			}
		}
	}
	if rejects == 0 {
		t.Fatal("no rejected entries in wrappedkeys.json")
	}
}
