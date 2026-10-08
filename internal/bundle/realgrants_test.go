package bundle_test

import (
	"bytes"
	"testing"

	"github.com/middle-management/patchlog/internal/bundle"
	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/keystore"
	"github.com/middle-management/patchlog/internal/seal"
)

// Against a real authenticated server (no simulated grants endpoint): a
// plain and a sealed namespace each export their grants, the sealed one's
// fetched sealed and opened by the exporter (§C.3.1, §G.4.1), and the
// signatures verify against the source.
func TestRealServerGrantExport(t *testing.T) {
	t.Parallel()
	ks, err := keystore.New(keystore.Generate())
	if err != nil {
		t.Fatal(err)
	}
	s := clienttest.New(t, clienttest.Options{Auth: true, KeyStore: ks})
	admin := clienttest.NewKey("admin")
	bot := signerKey(t, "bot-1", 7)
	for _, tc := range []struct {
		ns  string
		doc map[string]any
	}{
		{"plain", map[string]any{}},
		{"sealed", map[string]any{"encryption": map[string]any{"level": "sealed"}}},
	} {
		t.Run(tc.ns, func(t *testing.T) {
			oper := s.Client(t, client.WithBearer(s.OperatorGrant(t, tc.ns)))
			doc := map[string]any{"keys": []any{admin.Entry("*")}}
			for k, v := range tc.doc {
				doc[k] = v
			}
			must(oper.CreateNamespace(ctx, tc.ns, doc))
			writer := s.Client(t, client.WithBearer(admin.Grant(t, s.Now(), "user:alice", []string{tc.ns},
				[]string{"read", "create", "append"}, map[string]any{"signers": []any{bot.Entry()}})),
				client.WithKeys(client.NewKeys(nil))).With(client.WithSigner(bot))
			p1, p2 := client.GenesisPatches(map[string]any{"n": 1}), ops(op("replace", "/n", 2))
			if tc.ns == "sealed" {
				p1, p2 = append(p1, op("add", "/$nonce", seal.NewNonce())), nonce(op("replace", "/n", 2))
			}
			w := must(writer.Create(ctx, tc.ns, "d", p1))
			w2 := must(writer.Append(ctx, tc.ns, "d", w.ID, p2))

			bearer := admin.Grant(t, s.Now(), "user:root", []string{tc.ns}, []string{"read", "export"})
			reader := s.Client(t, client.WithBearer(bearer), client.WithKeys(client.NewKeys(nil)))
			var buf bytes.Buffer
			plan, _, err := bundle.Export(ctx, reader, &buf, bundle.ExportOptions{Select: []string{tc.ns}, Authors: true,
				Plaintext: true, Bearer: bearer})
			if err != nil {
				t.Fatal(err)
			}
			if len(plan.Notes) != 0 {
				t.Fatalf("notes %v", plan.Notes)
			}
			grants := 0
			for _, m := range lineMaps(t, buf.Bytes())[1:] {
				if m["stored"] != nil {
					grants++
					if m["ns"] != tc.ns || m["key"] == nil {
						t.Fatalf("grant line %v", m)
					}
				}
			}
			if grants != 1 {
				t.Fatalf("%d grant lines:\n%s", grants, buf.Bytes())
			}
			st, _ := sigStatuses(t, buf.Bytes(), bundle.VerifyOptions{Keys: bundle.SourceKeyChecker(reader)})
			if st[w.ID] != bundle.SigVerified || st[w2.ID] != bundle.SigVerified {
				t.Fatalf("statuses %v", st)
			}
		})
	}
}
