package core

import (
	"context"
	"testing"
)

// W3X (CIS-17, §6.1, F-S1): a schema revision read in the clear carries
// the marker its row was stored with (Rev.SchemaRules, served as
// schema.RulesHeader): v0.73 for one written now, legacy for a row stored
// before markers, and none for a document that isn't a schema. The read
// cache serves the same.
func TestW3XRevSchemaRules(t *testing.T) {
	t.Parallel()
	s := newSchemaEnv(t)
	ctx := context.Background()
	s.mkNS("sch")
	now := s.put("sch", "now", "", idnSchema())
	old := s.put("sch", "old", "", idnSchema())
	s.storedBefore("sch", "old", old)
	doc := s.put("sch", "doc", "", map[string]any{"$schema": "/r/sch/now/rev/" + now, "e": "a@b.example"})
	for _, c := range []struct{ name, id, want string }{{"now", now, "v0.73"}, {"old", old, "legacy"}, {"doc", doc, ""}} {
		for i := 0; i < 2; i++ { // the second read is the read cache's
			r, err := s.e.ResourceRev(ctx, "sch", c.name, c.id, Credentials{})
			if err != nil || r.Status != 200 {
				t.Fatalf("%s: %+v %v", c.name, r, err)
			}
			if r.SchemaRules != c.want {
				t.Errorf("%s (read %d): SchemaRules %q, want %q", c.name, i, r.SchemaRules, c.want)
			}
		}
	}
}
