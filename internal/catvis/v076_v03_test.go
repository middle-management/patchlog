package catvis_test

import (
	"crypto/ed25519"
	"encoding/base64"
	"testing"

	"github.com/middle-management/patchlog/internal/grantcheck"
)

// v076V03Matches is matches's document with the catalog's key catalog-01
// and a second key ed-01, without requireAt, whose scope rules are
// edRules.
func v076V03Matches(t *testing.T, edRules string) *grantcheck.Config {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	doc := parse(`{"read":"grant","roles":{"reader":{"can":["read"]}},
		"keys":[{"kid":"catalog-01","alg":"Ed25519","pub":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
			"can":["read","create","append","restore"],"maxTtl":"PT15M","readScope":"resource","requireAt":"cat",
			"roles":{"allow":["reader"]}},
			{"kid":"ed-01","alg":"Ed25519","pub":"` + base64.RawURLEncoding.EncodeToString(pub) + `",
			"can":["read"],"rules":` + edRules + `}],
		"catalogs":{"cat":{"place":["group:match-desk"]}}}`)
	cfg, err := grantcheck.ParseConfig("matches", "", doc)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}
