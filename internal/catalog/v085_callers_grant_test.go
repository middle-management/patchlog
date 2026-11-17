package catalog_test

import (
	"testing"
)

// Scenario 136 (SERVICES §B.11.4 The caller's grant, v0.85: "where the
// grant allows read (§C.2 item 2, counting only roles item 5 lets count)
// in no namespace the service follows that it verifies in"; §B.11.6). A
// base grant carrying the role reader names the catalog and matches: the
// catalog's reader lists no verb, so the grant allows read nowhere in the
// catalog namespace, and matches' reader lists read. It is judged as
// usual at POST /read-grants and for a read want, and reads its subject
// set's listings; before v0.85, which judged the catalog namespace alone,
// it got the caller's-grant 403. The same grant naming the catalog alone
// reads in no namespace the service follows, and so does one whose role
// lists read in neither: 403, at the listings and the exchange too
// (scenario 140).
func TestV085CallersGrantReadsInAContentNamespace(t *testing.T) {
	t.Parallel()
	w := setup(t)
	w.seed()
	w.startEdge()
	w.caughtUp()
	base := func(nss []string, role string) string {
		return w.opsKey.Grant(t, w.s.Now(), "user:fred", nss, []string{"read"}, map[string]any{"groups": toAny("fan-club"), "roles": toAny(role)})
	}
	items := map[string]any{"items": toAny("/r/matches/derby")}
	read := map[string]any{"item": "/r/matches/derby", "want": toAny("read")}

	in := base([]string{"cat", "matches"}, "reader")
	if r := w.do("POST", "/read-grants", in, items); r.status != 200 || entry(r, 0)["grant"] == nil {
		t.Errorf("read in matches alone, POST /read-grants: %d %v, want it judged as usual", r.status, r.body)
	}
	if r := w.do("POST", "/grants", in, read); r.status != 200 || r.body["grant"] == nil {
		t.Errorf("read in matches alone, a read want: %d %v, want it judged as usual", r.status, r.body)
	}
	if r, _ := w.follow("/cat/children?of=season", in); r.status != 200 {
		t.Errorf("read in matches alone, its listing: %d %v", r.status, r.body)
	}
	if r, cks := w.exchange(in, nil, ""); r.status != 200 || len(cks) != 1 {
		t.Errorf("read in matches alone, the exchange: %d %v", r.status, r.body)
	}
	for what, tok := range map[string]string{
		"the same grant naming the catalog alone": base([]string{"cat"}, "reader"),
		"a role that lists read in neither":       base([]string{"cat", "matches"}, "deleter"),
	} {
		v82Refused(t, what+": POST /read-grants", w.do("POST", "/read-grants", tok, items))
		v82Refused(t, what+": a read want", w.do("POST", "/grants", tok, read))
		if r := w.do("GET", "/cat/children?of=season", tok, nil); r.status != 403 {
			t.Errorf("%s: its listing: %d %v, want 403", what, r.status, r.body)
		}
		if r, cks := w.exchange(tok, nil, ""); r.status != 403 || len(cks) != 0 {
			t.Errorf("%s: the exchange: %d %v, want 403", what, r.status, r.body)
		}
	}
}
