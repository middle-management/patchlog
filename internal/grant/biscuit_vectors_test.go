package grant

// Interoperability vectors. Regenerate nothing: they are fixed inputs.

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
)

// Samples from the Biscuit specification repository
// (github.com/eclipse-biscuit/biscuit, samples/current), produced by the
// reference implementation (biscuit-rust), with their root key pair and
// the revocation ids (block signatures) the samples list. Their blocks hold
// ordinary Datalog, so they are not grants; they check the wire format and
// signature scheme: v0 and v1 signature payloads, sealing, third-party
// blocks and non-Ed25519 keys.
const (
	sampleRootPub  = "1055c750b1a1505937af1537c626ba3263995c33a64758aaafb1275b0312e284"
	sampleRootPriv = "99e87b0e9158531eeeb503ff15266e2b23c2a2507b138c9d1b1f2ab458df2d61"
)

var specSamples = []struct {
	name, token string
	ok          bool
	sigs        []string
}{
	{"test001_basic.bc", "EqcBCj0KBWZpbGUxCgVmaWxlMhgDIg0KCwgEEgMYgAgSAhgAIg0KCwgEEgMYgQgSAhgAIg0KCwgEEgMYgAgSAhgBEiQIABIgEFXHULGhUFk3rxU3xia6MmOZXDOmR1iqr7EnWwMS4oQaQHWVoRKh61uBpuOYhS5hGLf1uMu_9FJ3jmVRAOX7T6qNOir1L-LE-VJIeWBWdfriatvEeD4Mr8Q1IvqCOF85bAMalQEKKwoBMBgDMiQKIgoCCBsSBwgCEgMIgggSBggDEgIYABILCAQSAwiCCBICGAASJAgAEiDUQk0eEpEzoUeX40zcX6nap0wrG2eq_k-10bM-vdpa0RpARfTBT52ej6BE1ovnouyM3bg19XXHuRPsWb1jbHCsrpqQ25BkugswhCkO0MQiu7cXAJKohPXgICsx6SNbvMFlDSIiCiDKQdqwhZDtpEIxtvz0uxEMhSsk8DC_mWqJ8CzMxX618Q==", true, []string{"7595a112a1eb5b81a6e398852e6118b7f5b8cbbff452778e655100e5fb4faa8d3a2af52fe2c4f9524879605675fae26adbc4783e0cafc43522fa82385f396c03", "45f4c14f9d9e8fa044d68be7a2ec8cddb835f575c7b913ec59bd636c70acae9a90db9064ba0b3084290ed0c422bbb7170092a884f5e0202b31e9235bbcc1650d"}},
	{"test005_invalid_signature.bc", "EqcBCj0KBWZpbGUxCgVmaWxlMhgDIg0KCwgEEgMYgAgSAhgAIg0KCwgEEgMYgQgSAhgAIg0KCwgEEgMYgAgSAhgBEiQIABIgEFXHULGhUFk3rxU3xia6MmOZXDOmR1iqr7EnWwMS4oQaQHaVoRKh61uBpuOYhS5hGLf1uMu_9FJ3jmVRAOX7T6qNOir1L-LE-VJIeWBWdfriatvEeD4Mr8Q1IvqCOF85bAMalQEKKwoBMBgDMiQKIgoCCBsSBwgCEgMIgggSBggDEgIYABILCAQSAwiCCBICGAASJAgAEiDUQk0eEpEzoUeX40zcX6nap0wrG2eq_k-10bM-vdpa0RpARfTBT52ej6BE1ovnouyM3bg19XXHuRPsWb1jbHCsrpqQ25BkugswhCkO0MQiu7cXAJKohPXgICsx6SNbvMFlDSIiCiDKQdqwhZDtpEIxtvz0uxEMhSsk8DC_mWqJ8CzMxX618Q==", false, []string{}},
	{"test020_sealed.bc", "EqcBCj0KBWZpbGUxCgVmaWxlMhgDIg0KCwgEEgMYgAgSAhgAIg0KCwgEEgMYgQgSAhgAIg0KCwgEEgMYgAgSAhgBEiQIABIgEFXHULGhUFk3rxU3xia6MmOZXDOmR1iqr7EnWwMS4oQaQHWVoRKh61uBpuOYhS5hGLf1uMu_9FJ3jmVRAOX7T6qNOir1L-LE-VJIeWBWdfriatvEeD4Mr8Q1IvqCOF85bAMalQEKKwoBMBgDMiQKIgoCCBsSBwgCEgMIgggSBggDEgIYABILCAQSAwiCCBICGAASJAgAEiDUQk0eEpEzoUeX40zcX6nap0wrG2eq_k-10bM-vdpa0RpARfTBT52ej6BE1ovnouyM3bg19XXHuRPsWb1jbHCsrpqQ25BkugswhCkO0MQiu7cXAJKohPXgICsx6SNbvMFlDSJCEkCfIpa5yKK-ahepkwhc6RvDyntWIW_VMsGtUkqV47nLtsU8Y7kjVdFJBJGfc-ijQ23RAEcD5tGR54nVtqdgbpYE", true, []string{"7595a112a1eb5b81a6e398852e6118b7f5b8cbbff452778e655100e5fb4faa8d3a2af52fe2c4f9524879605675fae26adbc4783e0cafc43522fa82385f396c03", "45f4c14f9d9e8fa044d68be7a2ec8cddb835f575c7b913ec59bd636c70acae9a90db9064ba0b3084290ed0c422bbb7170092a884f5e0202b31e9235bbcc1650d"}},
	{"test024_third_party.bc", "ErABCkYYBCIICgYIBBICGAAyEgoQCgIIGxIGCA8SAhgNIgIQAEIkCAASIKzdbVtTv-5Hi_aJ-OAS_nmIv3VePXxRUpR6vBSbwgGJEiQIABIg1EJNHhKRM6FHl-NM3F-p2qdMKxtnqv5PtdGzPr3aWtEaQEcOS_eqKgGrOcmBUL0GqhW0ql2GUJBEqICahjTNjPK0ImmlGndLZdELrJNp0BMHCwAYeSUZao5oAQhHPxHPjwMa8gEKHBgFIggKBggPEgIYDTIOCgwKAggbEgYIBBICGAASJAgAEiA2w-1j74YQhUlm1PBCB414_evHBaUCrSuQ8_xk9767lxpAkBsq9NrPM0WNLZGsSEtgutlI6NEPqpaVsJYFTVtG6DKpd7YLF0ZMrPVFrQgB9UnqRUZ18KyIxBNAaSXir4P_CCJoCkCo38e8sEEVD7PJ920Pcnb-nkG1CeS8bnK0FsUPQmnxQlTgNlgGvDOHLpFWySqY3abg0da-TzpPpdQGgrUa-4MGEiQIABIgrN1tW1O_7keL9on44BL-eYi_dV49fFFSlHq8FJvCAYkoASIiCiATasTkjxkF1pf4Gd9PoqQSAn5ZoO_oT7cwWkDn_p0rVw==", false, []string{}},
	{"test035_ffi.bc", "EsUBClkKBHRlc3QKAWEKDWVxdWFsIHN0cmluZ3MYBjI9CjsKAggbGg8KBAoCMAEKBxIFCAQQgAgaJAoFCgMYgQgKBQoDGIEICgcaBQgcEIAICgUKAxiCCAoEGgIIFRIkCAASIBBVx1CxoVBZN68VN8YmujJjmVwzpkdYqq-xJ1sDEuKEGkDRcZ_RAcJpXS2sTfZ1aZGDY_aRthZ2cOHbv4Am9jmnqh7C4TcH9NNMrbsq3OXG6KgWV33Qaahxfg9ctOo87FsEKAEiIgogmeh7DpFYUx7utQP_FSZuKyPColB7E4ydGx8qtFjfLWE=", true, []string{"d1719fd101c2695d2dac4df67569918363f691b6167670e1dbbf8026f639a7aa1ec2e13707f4d34cadbb2adce5c6e8a816577dd069a8717e0f5cb4ea3cec5b04"}},
	{"test036_secp256r1.bc", "EqoBCj0KBWZpbGUxCgVmaWxlMhgDIg0KCwgEEgMYgAgSAhgAIg0KCwgEEgMYgQgSAhgAIg0KCwgEEgMYgAgSAhgBEiUIARIhAl6Rj9RGODKuooI9_ZcWo2tNmxN3vVPdgt30wLx17Wu_GkBii5ptdMyAs-zlC-_R9fDwJcCjXVFwiy53wRrtX5aLk7QJbIftgWlgVxbek04VVEPxQDNNcXCPzEJH5aClGLMNKAEaoAEKKwoBMBgDMiQKIgoCCBsSBwgCEgMIgggSBggDEgIYABILCAQSAwiCCBICGAASJQgBEiECeinoORyx61y3ivjAJBoGxxPifjTXblt2UEPC6fKpkO4aSDBGAiEAtgZ0hUoSgUzDbIqrlgDB2fnTFg4jNLcsD-7eWlYhPqUCIQCk9Lvy3DOzCSZ685_OdmEgF922Fx6c0qOqioU_RfFnXygBIiIKIMpB2rCFkO2kQjG2_PS7EQyFKyTwML-ZaonwLMzFfrXx", false, []string{}},
}

// Tokens built with the official Go library, github.com/biscuit-auth/
// biscuit-go/v2 v2.2.0 (signature payload v0, an empty context in every
// block): NewBuilder(root).AddAuthorityFact(grant_block(<root JSON>)), then
// Append of a block with grant_block({"via":"svc:x"}), then Seal. The root
// key is the Ed25519 key with seed 00 01 … 1f.
var libTokens = []string{
	"EuMBCnkKWnsiY2FuIjpbInJlYWQiXSwiZXhwIjoiMjAzMC0wMS0wMVQwMDowMDowMFoiLCJraWQiOiJrMSIsIm5zIjpbIm1hdGNoZXMiXSwic3ViIjoidXNlcjpib2IifQoLZ3JhbnRfYmxvY2sSABgDIgoKCAiBCBIDGIAIEiQIABIgZixDJgykgOF4WHSqDvxzWMemS8Xu9yXnGqeDzKPKwBcaQP1oqrrcA4HHpPRoSDF-ofk-h7iiYkWg_Eqa35WVh3cBAkrBh3TP_8zGm_LWlB64Tzs0DGLoApwQnVZfCTh93wIiIgogCaVF0lIswZQcu5ua8m69V9HPTXWVTU9kUEaF93fvbSM=",
	"EuMBCnkKWnsiY2FuIjpbInJlYWQiXSwiZXhwIjoiMjAzMC0wMS0wMVQwMDowMDowMFoiLCJraWQiOiJrMSIsIm5zIjpbIm1hdGNoZXMiXSwic3ViIjoidXNlcjpib2IifQoLZ3JhbnRfYmxvY2sSABgDIgoKCAiBCBIDGIAIEiQIABIgZixDJgykgOF4WHSqDvxzWMemS8Xu9yXnGqeDzKPKwBcaQP1oqrrcA4HHpPRoSDF-ofk-h7iiYkWg_Eqa35WVh3cBAkrBh3TP_8zGm_LWlB64Tzs0DGLoApwQnVZfCTh93wIaiwEKIQoPeyJ2aWEiOiJzdmM6eCJ9EgAYAyIKCggIgQgSAxiCCBIkCAASILix6QrAfOQgh6sJW1YTlTYmxazKLTq826D5DPq3XGlNGkAegIahbZ2b4tiIac4K6Q6u40VlBOs3waccV7qpwnzHle_PaVkyYkTIm52Y8NIAXrw3Qgv6L985MKPFoC4fC04KIiIKIIRGXIo23Tbv9MsR6L0MCfSsLz4G785c8Xz_Gm29DvJI",
	"EuMBCnkKWnsiY2FuIjpbInJlYWQiXSwiZXhwIjoiMjAzMC0wMS0wMVQwMDowMDowMFoiLCJraWQiOiJrMSIsIm5zIjpbIm1hdGNoZXMiXSwic3ViIjoidXNlcjpib2IifQoLZ3JhbnRfYmxvY2sSABgDIgoKCAiBCBIDGIAIEiQIABIgZixDJgykgOF4WHSqDvxzWMemS8Xu9yXnGqeDzKPKwBcaQP1oqrrcA4HHpPRoSDF-ofk-h7iiYkWg_Eqa35WVh3cBAkrBh3TP_8zGm_LWlB64Tzs0DGLoApwQnVZfCTh93wIaiwEKIQoPeyJ2aWEiOiJzdmM6eCJ9EgAYAyIKCggIgQgSAxiCCBIkCAASILix6QrAfOQgh6sJW1YTlTYmxazKLTq826D5DPq3XGlNGkAegIahbZ2b4tiIac4K6Q6u40VlBOs3waccV7qpwnzHle_PaVkyYkTIm52Y8NIAXrw3Qgv6L985MKPFoC4fC04KIkISQEPm3G5mg3oVYIwn1GI9uuj2YQdVVta_lJ7obpKCRfK0QUbAhAxXDzDkzZ6gqAtqvR8FgNnCSUNKTxfoYuEukwM=",
}

const libRootPub = "A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg"

var libSigs = []string{"fd68aabadc0381c7a4f46848317ea1f93e87b8a26245a0fc4a9adf9595877701024ac18774cfffccc69bf2d6941eb84f3b340c62e8029c109d565f09387ddf02", "1e8086a16d9d9be2d88869ce0ae90eaee3456504eb37c1a71c57baa9c27cc795efcf6959326244c89b9d98f0d2005ebc37420bfa2fdf3930a3c5a02e1f0b4e0a"}

func TestSpecSamples(t *testing.T) {
	root, _ := hex.DecodeString(sampleRootPub)
	seed, _ := hex.DecodeString(sampleRootPriv)
	priv := ed25519.NewKeyFromSeed(seed)
	if !priv.Public().(ed25519.PublicKey).Equal(ed25519.PublicKey(root)) {
		t.Fatal("sample key pair")
	}
	for _, s := range specSamples {
		t.Run(s.name, func(t *testing.T) {
			data, err := base64.URLEncoding.DecodeString(s.token)
			if err != nil {
				t.Fatal(err)
			}
			c, err := parseContainer(data, true)
			if err == nil {
				err = c.verify(root)
			}
			if s.ok != (err == nil) {
				t.Fatalf("ok %v, got %v", s.ok, err)
			}
			if s.ok {
				for i, sb := range c.blocks {
					if hex.EncodeToString(sb.sig) != s.sigs[i] {
						t.Fatalf("block %d signature (revocation id) differs", i)
					}
				}
				// Ed25519 is deterministic: re-signing our payload with the
				// sample root key reproduces the reference signature, so the
				// payload bytes (v0 or v1) are exactly the reference's.
				if sig := ed25519.Sign(priv, c.blocks[0].payload(nil)); hex.EncodeToString(sig) != s.sigs[0] {
					t.Fatalf("authority payload v%d differs from the reference", c.blocks[0].version)
				}
			}
			// None of them is a grant: their blocks hold other Datalog.
			_, err = Decode(s.token, 0)
			wantStatus(t, err, 401)
		})
	}
	// test035 uses signature payload v1, the others v0.
	c, _ := parseContainer(must64(t, specSamples[4].token), true)
	if !strings.HasPrefix(specSamples[4].name, "test035") || c.blocks[0].version != 1 {
		t.Fatal("expected a v1 sample")
	}
}

func must64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.URLEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Tokens built by biscuit-go decode and verify through our parser, can be
// narrowed by us, and keep the library's signatures as revocation ids.
func TestBiscuitGoTokens(t *testing.T) {
	pub, err := base64.RawURLEncoding.DecodeString(libRootPub)
	if err != nil {
		t.Fatal(err)
	}
	env := Env{Now: now, NS: "matches", Revoked: map[string]bool{},
		Keys: []Key{{Kid: "k1", Alg: "Ed25519", Pub: ed25519.PublicKey(pub), Can: []string{"*"}}}}
	for i, tok := range libTokens {
		g, err := Decode(tok, 8192)
		if err != nil {
			t.Fatalf("token %d: %v", i, err)
		}
		v, err := Verify(g, env)
		if err != nil {
			t.Fatalf("token %d: %v", i, err)
		}
		if v.Principal.ID != "user:bob" || !v.Can["read"] || g.Sealed() != (i == 2) {
			t.Fatalf("token %d: %+v", i, v.Principal)
		}
		if i > 0 && (len(g.Blocks) != 2 || strings.Join(v.Principal.Via, ",") != "svc:x") {
			t.Fatalf("token %d: blocks", i)
		}
		for j, sb := range g.c.blocks {
			if hex.EncodeToString(sb.sig) != libSigs[j] {
				t.Fatalf("token %d block %d: signature", i, j)
			}
		}
		if i < 2 {
			n, err := g.Narrow(map[string]any{"via": "svc:y", "ns": []string{"matches"}})
			if err != nil {
				t.Fatal(err)
			}
			d, err := Decode(n.Encode(), 0)
			if err != nil {
				t.Fatal(err)
			}
			if v, err := Verify(d, env); err != nil || v.Principal.Via[len(v.Principal.Via)-1] != "svc:y" {
				t.Fatalf("narrowed library token: %v", err)
			}
		}
	}
}
