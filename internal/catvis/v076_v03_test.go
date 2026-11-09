package catvis_test

import (
	"crypto/ed25519"
	"encoding/base64"
	"reflect"
	"testing"

	"github.com/middle-management/patchlog/internal/catvis"
	"github.com/middle-management/patchlog/internal/grant"
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

// §B.11.5 deciding subjects: "a rule of any role or key of a content
// namespace it trusts", not only the catalog's keys (v0.76).
func TestV076V03ProfileEveryKey(t *testing.T) {
	t.Parallel()
	docs := map[string]any{
		"root":          map[string]any{"parents": []any{}, "$access": acc("group:editors", "reader")},
		"matches.derby": map[string]any{"parents": parents("root")},
	}
	li := grant.Principal{ID: "user:li", Groups: []string{"editors", "staff"}}

	pos := `[{"op":"test","path":"/principal/groups","schema":{"contains":{"const":"staff"}}}]`
	p := seedCatalog(t, v076V03Matches(t, pos), docs).Profile()
	if !p.Groups["staff"] || p.KeepAll || p.SubScoped {
		t.Fatalf("positive key rule: %+v", p)
	}
	if got := catvis.ListingSubjects(p, li); !reflect.DeepEqual(got, []string{"group:editors", "group:staff"}) {
		t.Errorf("ListingSubjects %v", got)
	}

	// A negated test of the other key keeps every group.
	neg := `[{"not":{"op":"test","path":"/principal/groups","schema":{"contains":{"const":"staff"}}}}]`
	p = seedCatalog(t, v076V03Matches(t, neg), docs).Profile()
	if !p.KeepAll {
		t.Fatalf("negated key rule: %+v", p)
	}
	bo := grant.Principal{ID: "user:bo", Groups: []string{"editors", "interns"}}
	if got := catvis.ListingSubjects(p, bo); !reflect.DeepEqual(got, []string{"group:editors", "group:interns"}) {
		t.Errorf("KeepAll ListingSubjects %v", got)
	}

	// A sub scope decides only on the catalog's own key.
	sub := `[],"sub":"user:.*"`
	if p := seedCatalog(t, v076V03Matches(t, sub), docs).Profile(); p.SubScoped {
		t.Errorf("another key's sub scope: %+v", p)
	}
}
