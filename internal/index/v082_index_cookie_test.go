package index_test

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

// V82-05 (v0.82), SVC-10 (SERVICES §A.4 gs: "A cookie is 403 until the
// reader exchanges again ... where a marker's key, rules or roles would
// end a gs cookie, its key being the one that verified the grant in
// {ns}, reads:{ns} markers included"; §B.11.9 gs): a cookie carries its
// prefix and exp alone, so an exchange whose keys or entries differ from
// those its marker's cookie of that exp came from mints one with another
// exp. No exchange vouches again for a cookie that ended, and none is
// held back by one.

// The answers at v82Paths and at an at URL already answered.
const v82Reads3, v82Refuse3 = v82Reads + ",OK", v82Refuse + ",Forbidden"

// TestV082CookieRevivedByAnotherReader: al and bo read docs whole
// through k1 with grants that expire at the same second (the grant's exp
// bounds the cookie's). docs narrows k1's sub scope to bo alone: al's
// grant no longer verifies (403 at the exchange) and her cookie is 403.
// bo exchanges again, as he must. al, who has not exchanged and can't,
// must stay 403 under the cookie she holds.
func TestV082CookieRevivedByAnotherReader(t *testing.T) {
	t.Parallel()
	d := newV82Whole(t)
	exp := d.s.Now().Add(10 * time.Minute)
	al := v82Grant(d, d.k1, "user:al", exp)
	bo := v82Grant(d, d.k1, "user:bo", exp)
	prefixes, alC := d.exchange(al)
	d.exchange(bo)
	paths := v82Paths(prefixes)
	_, at := p37Follow(t, d.x, paths[0], alC, "")
	paths = append(paths, at)
	if got := v82Status(t, d.x, paths, alC); got != v82Reads3 {
		t.Fatalf("al under her cookie: %s", got)
	}
	d.patch(map[string]any{"op": "add", "path": "/keys/1/sub", "value": "user:bo"})
	if got := v82Status(t, d.x, paths, alC); got != v82Refuse3 {
		t.Fatalf("al under her cookie once k1 no longer allows her sub: %s", got)
	}
	if r := p37Do(t, d.x, "POST", "/edge-grants", al, "", nil, ""); r.status != 403 {
		t.Fatalf("al exchanging again: %d %v, want 403", r.status, r.body)
	}
	// bo reads under his new cookie first: what it is answered, kept or
	// not, is never al's.
	_, boC := d.exchange(bo)
	if got := v82Status(t, d.x, paths, boC); got != v82Reads3 {
		t.Errorf("bo under his new cookie: %s", got)
	}
	if alC[0].Value == boC[0].Value {
		t.Errorf("bo's new cookie is the one al holds: %v", boC[0])
	}
	if got := v82Status(t, d.x, paths, alC); got != v82Refuse3 {
		t.Errorf("al, whose grant k1 refuses and who never exchanged again, under her old cookie after bo's exchange: %s, want 403", got)
	}
}

// TestV082CookieNeverCured: al reads through k1, di through k2, with
// grants that expire at the same second. docs removes k1. di's cookie is
// 403 (it is al's too); di exchanges her own, still valid grant again and
// must read: "403 until the reader exchanges again".
func TestV082CookieNeverCured(t *testing.T) {
	t.Parallel()
	d := newV82Whole(t)
	exp := d.s.Now().Add(10 * time.Minute)
	al := v82Grant(d, d.k1, "user:al", exp)
	di := v82Grant(d, d.k2, "user:di", exp)
	d.exchange(al)
	prefixes, diC := d.exchange(di)
	paths := v82Paths(prefixes)
	if got := v82Status(t, d.x, paths, diC); got != v82Reads {
		t.Fatalf("di under her cookie: %s", got)
	}
	d.patch(map[string]any{"op": "remove", "path": "/keys/1"})
	t.Logf("di under her cookie once k1, not her key, is removed: %s", v82Status(t, d.x, paths, diC))
	_, diC = d.exchange(di)
	if got := v82Status(t, d.x, paths, diC); got != v82Reads {
		t.Errorf("di, through k2 which never changed, having exchanged again: %s, want 200", got)
	}
}

// TestV082CookieNeverCuredOneReader: one reader, one key. li's grant
// names the roles reader and extra, and its exp bounds her cookie's. docs
// changes extra; her cookie is 403; she exchanges the same grant again,
// which k1 still verifies, and must read.
func TestV082CookieNeverCuredOneReader(t *testing.T) {
	t.Parallel()
	d := newV82Whole(t)
	d.patch(map[string]any{"op": "add", "path": "/roles/extra", "value": map[string]any{"can": []any{"read"}}})
	li := d.k1.Grant(t, d.s.Now(), "user:li", []string{"docs"}, []string{"read"},
		map[string]any{"roles": []any{"reader", "extra"}, "exp": d.s.Now().Add(10 * time.Minute).Format(time.RFC3339)})
	prefixes, c := d.exchange(li)
	paths := v82Paths(prefixes)
	if got := v82Status(t, d.x, paths, c); got != v82Reads {
		t.Fatalf("li under her cookie: %s", got)
	}
	// extra no longer lists read: the roles her grant reads through are
	// now reader alone.
	d.patch(map[string]any{"op": "replace", "path": "/roles/extra/can", "value": []any{"append"}})
	if got := v82Status(t, d.x, paths, c); got != v82Refuse {
		t.Fatalf("li under her cookie once extra changed: %s", got)
	}
	_, c = d.exchange(li)
	if got := v82Status(t, d.x, paths, c); got != v82Reads {
		t.Errorf("li, having exchanged the same grant again: %s, want 200", got)
	}
}

// TestV082ScopeCookieRevivedByAnotherReader: the same for a scope
// marker (newV77Docs: k1's grants read docs in part, under
// reads:docs:scope:{digest}): readers with the same rules and key share
// the marker and, with the same exp, the edge_gs_keys row.
func TestV082ScopeCookieRevivedByAnotherReader(t *testing.T) {
	t.Parallel()
	d := newV77Docs(t)
	exp := d.s.Now().Add(10 * time.Minute)
	al := v82Grant(d, d.k1, "user:al", exp)
	bo := v82Grant(d, d.k1, "user:bo", exp)
	prefixes, alC := d.exchange(al)
	boP, _ := d.exchange(bo)
	if boP["docs"] != prefixes["docs"] {
		t.Fatalf("al and bo don't share a scope marker: %v %v", prefixes, boP)
	}
	paths := v82Paths(prefixes)
	_, at := p37Follow(t, d.x, paths[0], alC, "")
	paths = append(paths, at)
	if got := v82Status(t, d.x, paths, alC); got != v82Reads3 {
		t.Fatalf("al under her cookie: %s", got)
	}
	d.patch(map[string]any{"op": "add", "path": "/keys/1/sub", "value": "user:bo"})
	if got := v82Status(t, d.x, paths, alC); got != v82Refuse3 {
		t.Fatalf("al under her cookie once k1 no longer allows her sub: %s", got)
	}
	if r := p37Do(t, d.x, "POST", "/edge-grants", al, "", nil, ""); r.status != 403 {
		t.Fatalf("al exchanging again: %d %v, want 403", r.status, r.body)
	}
	_, boC := d.exchange(bo)
	if got := v82Status(t, d.x, paths, boC); got != v82Reads3 {
		t.Errorf("bo under his new cookie: %s", got)
	}
	if got := v82Status(t, d.x, paths, alC); got != v82Refuse3 {
		t.Errorf("al under her old scope cookie after bo's exchange: %s, want 403", got)
	}
}

// TestV082GCookieNotRevivedByAnotherReader: the same for a g: marker
// (§B.11.9 gs). al and bo, in the same groups through catalog-01, share
// reads:matches:g:{gs} and, their grants expiring together, a cookie.
// matches changes catalog-01's maxTtl, which neither the gs nor the
// scope digest reads: the cookie is 403, bo's exchange gives him another
// for the same prefix, and the one al holds stays 403 until she
// exchanges, for another of her own.
func TestV082GCookieNotRevivedByAnotherReader(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	w := newV75X(t, false)
	exchange := func(token string) (string, []*http.Cookie) {
		t.Helper()
		r := p37Do(t, w.x, "POST", "/edge-grants", token, "", nil, "")
		if r.status != 200 {
			t.Fatalf("exchange: %d %v", r.status, r.body)
		}
		for _, p := range r.body["prefixes"].([]any) {
			if strings.HasPrefix(p.(string), "/matches/g/") {
				return p.(string) + "?q=derby", r.cookies
			}
		}
		t.Fatalf("no /matches/g/ prefix: %v", r.body)
		return "", nil
	}
	status := func(path string, c []*http.Cookie) int {
		t.Helper()
		got, _ := p37Follow(t, w.x, path, c, "")
		return got.status
	}
	value := func(path string, cs []*http.Cookie) string {
		t.Helper()
		for _, c := range cs {
			if c.Path == strings.TrimSuffix(path, "?q=derby") {
				return c.Value
			}
		}
		t.Fatalf("no cookie for %s", path)
		return ""
	}
	al, bo := w.reader("user:al", []any{"fans"}), w.reader("user:bo", []any{"fans"})
	path, alC := exchange(al)
	boPath, boC := exchange(bo)
	if boPath != path || value(path, boC) != value(path, alC) {
		t.Fatalf("al and bo don't share a cookie: %s %s", path, boPath)
	}
	if got := status(path, alC); got != 200 {
		t.Fatalf("al under her cookie: %d", got)
	}
	must(w.admin.PatchConfig(ctx, "matches", must(w.admin.NSHead(ctx, "matches")).Config, []any{map[string]any{"op": "replace", "path": "/keys/1/maxTtl", "value": "PT14M"}}))
	w.x.caughtUp("matches")
	w.x.ix.ExpireGrantChecks()
	if got := status(path, alC); got != 403 {
		t.Fatalf("al under her cookie once catalog-01's maxTtl changed: %d", got)
	}
	boPath, boC = exchange(bo)
	if boPath != path || value(path, boC) == value(path, alC) {
		t.Fatalf("bo's new cookie at %s, al's at %s: the same cookie, or another prefix", boPath, path)
	}
	if got := status(path, boC); got != 200 {
		t.Errorf("bo under his new cookie: %d", got)
	}
	if got := status(path, alC); got != 403 {
		t.Errorf("al under her old g: cookie after bo's exchange: %d, want 403", got)
	}
	alPath, alC2 := exchange(al)
	if alPath != path || status(path, alC2) != 200 {
		t.Errorf("al, exchanged again, at %s: %d", alPath, status(alPath, alC2))
	}
	if got := status(path, alC); got != 403 {
		t.Errorf("al under her old g: cookie after her own exchange: %d, want 403", got)
	}
}

// TestV082ExchangeSameCookieAgain: an exchange through the same key with
// the same entry, for a grant with the same exp, vouches for exactly
// what the cookie minted before stands for, and gives that cookie; it
// uses up no second. A grant with two seconds left gives two cookies of
// reads:docs, one per key; a third set of keys, both in one exchange,
// has no second left after now to be told from them by, and is 503 with
// Retry-After, recording nothing: the two still read.
func TestV082ExchangeSameCookieAgain(t *testing.T) {
	t.Parallel()
	d := newV82Whole(t)
	exp := d.s.Now().Truncate(time.Second).Add(2 * time.Second)
	al := v82Grant(d, d.k1, "user:al", exp)
	cy := v82Grant(d, d.k2, "user:cy", exp)
	prefixes, alC := d.exchange(al)
	value := func(cs []*http.Cookie) string {
		t.Helper()
		for _, c := range cs {
			if c.Path == prefixes["docs"] {
				return c.Value
			}
		}
		t.Fatalf("no cookie for %s", prefixes["docs"])
		return ""
	}
	for range 3 {
		if _, again := d.exchange(al); value(again) != value(alC) {
			t.Fatalf("al's cookie, exchanged again with nothing changed: %v, was %v", again, alC)
		}
		if _, other := d.exchange(v82Grant(d, d.k1, "user:bo", exp)); value(other) != value(alC) {
			t.Fatalf("bo's cookie through the same key: %v, al's is %v", other, alC)
		}
	}
	_, cyC := d.exchange(cy)
	if value(cyC) == value(alC) {
		t.Fatalf("cy's cookie, through k2, is al's")
	}
	body := must(json.Marshal(map[string]any{"grants": []any{al, cy}}))
	r := p37Do(t, d.x, "POST", "/edge-grants", "", string(body), nil, "")
	if r.status != 503 || r.body["code"] != "behind" || r.header.Get("Retry-After") == "" || len(r.cookies) != 0 {
		t.Errorf("an exchange with no second left for its cookie: %d %v %v, %d cookies", r.status, r.body, r.header, len(r.cookies))
	}
	paths := v82Paths(prefixes)
	for name, c := range map[string][]*http.Cookie{"al": alC, "cy": cyC} {
		if got := v82Status(t, d.x, paths, c); got != v82Reads {
			t.Errorf("%s under its cookie: %s", name, got)
		}
	}
}
