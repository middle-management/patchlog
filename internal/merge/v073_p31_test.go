package merge_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/merge"
)

// bobBearer is a non-admin approver's grant for the catalog: match-desk,
// whose desk role has move and place in cat-season.
func (w *relWorld) bobBearer() string {
	return w.idp.Grant(w.t, w.s.Now(), "user:bob", relNS, []string{"read"},
		map[string]any{"groups": sAny("match-desk"), "exp": w.s.Now().Add(24 * time.Hour).Format(time.RFC3339)})
}

// catalogKeyInMatches lists the catalog's key in matches, through which a
// non-admin's roles count for read, so the catalog's nodes are visible to
// them (§B.11.3, §B.11.5).
func (w *relWorld) catalogKeyInMatches() {
	w.t.Helper()
	e := w.catKey.Entry("read", "create", "append", "restore")
	e["roles"] = map[string]any{"allow": sAny("desk", "reader")}
	must(w.ops.PatchConfig(ctx, "matches", must(w.ops.NSHead(ctx, "matches")).Config, ops(op("add", "/keys/-", e))))
}

// adminHeaders records the Admin-Authorization headers a client sends.
type adminHeaders struct {
	mu  sync.Mutex
	got []string
}

func (a *adminHeaders) RoundTrip(req *http.Request) (*http.Response, error) {
	if h := req.Header.Get("Admin-Authorization"); h != "" {
		a.mu.Lock()
		a.got = append(a.got, h)
		a.mu.Unlock()
	}
	return httpClient.Transport.RoundTrip(req)
}

// TestV073ReleaseAdminDryRunAsAdmin (TC-47, F-T4, scenario 44): a catalog
// batch that needs catalog-admins (step 2 creates locked with its $access)
// is answered as an admin dry run to an approver in catalog-admins, and
// the merge service asks again with its AdminGrant in Admin-Authorization,
// so the dry run is judged as the admin the batch then goes under (§F.8).
// The rest of the release goes under the merge key. An approver who isn't
// in catalog-admins stops the merge, whatever AdminGrant says, and so does
// a missing AdminGrant.
func TestV073ReleaseAdminDryRunAsAdmin(t *testing.T) {
	t.Parallel()
	w := newRelWorld(t)
	w.startCatalog()
	w.release7()
	o := w.opts("release-7")
	rec := &adminHeaders{}
	o.Granter = &merge.HTTPGranter{URLs: map[string]string{"cat-season": w.svcURL}, Bearer: w.mergeBearer(), Approver: w.annaBearer(),
		HTTP: &http.Client{Transport: rec}}
	dora := w.idp.Grant(t, w.s.Now(), "user:dora", relNS, []string{"read", "create", "append", "delete", "restore"},
		map[string]any{"groups": sAny("match-desk", "catalog-admins"), "exp": w.s.Now().Add(24 * time.Hour).Format(time.RFC3339)})
	o.AdminGrant = dora
	noErr(t, merge.SaveReleasePlan(ctx, w.anna, o, must(merge.PlanRelease(ctx, w.anna, o))))
	must(merge.ApproveRelease(ctx, w.anna, o))
	rp, err := merge.ApplyRelease(ctx, w.anna, o)
	if err != nil {
		t.Fatalf("apply with another admin's grant: %v", err)
	}
	if len(rec.got) == 0 || rec.got[0] != "Bearer "+dora {
		t.Fatalf("Admin-Authorization sent: %q", rec.got)
	}
	for _, st := range rp.Steps {
		if st.Key != "cat-season" {
			continue
		}
		e := entryOf(t, w.anna, "cat-season", st.Done)
		switch st.Step {
		case 2:
			if e.Grant == nil || e.Grant.Sub != "user:dora" || e.Grant.Kid != "idp" {
				t.Errorf("the $access batch went under %+v, want dora's", e.Grant)
			}
		case 4:
			if e.Grant == nil || e.Grant.Sub != "svc:merge" || e.Grant.Kid != "catalog-merge" {
				t.Errorf("the step-4 batch went under %+v, want the merge key's", e.Grant)
			}
		}
	}

	// An approver who isn't in catalog-admins, whatever AdminGrant says,
	// and an admin approver without an AdminGrant, stop the merge.
	for _, c := range []struct {
		name            string
		bob, adminGrant bool
	}{{"approved by bob", true, true}, {"without an admin's grant", false, false}} {
		w2 := newRelWorld(t)
		w2.catalogKeyInMatches()
		w2.startCatalog()
		w2.release7()
		o2 := w2.opts("release-7")
		if c.bob {
			o2.Granter = &merge.HTTPGranter{URLs: map[string]string{"cat-season": w2.svcURL}, Bearer: w2.mergeBearer(), Approver: w2.bobBearer(), HTTP: httpClient}
		}
		if !c.adminGrant {
			o2.AdminGrant = ""
		}
		noErr(t, merge.SaveReleasePlan(ctx, w2.anna, o2, must(merge.PlanRelease(ctx, w2.anna, o2))))
		must(merge.ApproveRelease(ctx, w2.anna, o2))
		_, err := merge.ApplyRelease(ctx, w2.anna, o2)
		switch {
		case c.bob && (err == nil || !strings.Contains(err.Error(), "403 forbidden locked: changing $access needs catalog-admins")):
			t.Errorf("%s: %v", c.name, err)
		case !c.bob && !errors.Is(err, merge.ErrAdminNeeded):
			t.Errorf("%s: %v", c.name, err)
		}
	}
}

// TestV073HTTPGranterAdmin (TC-47, TC-45): the granter sends the admin's
// grant in Admin-Authorization when asked to, reads the dry run's
// checkedAs, and tells a catalog without merge grants (404 not_offered)
// apart from other refusals.
func TestV073HTTPGranterAdmin(t *testing.T) {
	t.Parallel()
	var gotAdmin string
	answer := func(status int, body map[string]any) http.HandlerFunc {
		return func(rw http.ResponseWriter, r *http.Request) {
			gotAdmin = r.Header.Get("Admin-Authorization")
			rw.Header().Set("Content-Type", "application/json")
			rw.WriteHeader(status)
			_ = json.NewEncoder(rw).Encode(body)
		}
	}
	ask := func(h http.HandlerFunc, admin string) (*merge.MergeGrantResult, error) {
		srv := httptest.NewServer(h)
		defer srv.Close()
		g := &merge.HTTPGranter{URLs: map[string]string{"cat": srv.URL}, Bearer: "m", Approver: "a", HTTP: httpClient}
		return g.MergeGrant(ctx, "cat", map[string]any{"items": []any{}}, admin)
	}
	res, err := ask(answer(200, map[string]any{"admin": true, "approvedBy": "user:bob", "checkedAs": "user:ada"}), "ADMIN")
	if err != nil || !res.Admin || res.CheckedAs != "user:ada" || gotAdmin != "Bearer ADMIN" {
		t.Fatalf("admin dry run: %+v %v (Admin-Authorization %q)", res, err, gotAdmin)
	}
	if _, err := ask(answer(200, map[string]any{"grant": "g"}), ""); err != nil || gotAdmin != "" {
		t.Fatalf("a merge grant: %v (Admin-Authorization %q)", err, gotAdmin)
	}
	if _, err := ask(answer(403, map[string]any{"code": "forbidden", "message": "no power"}), ""); err == nil || errors.Is(err, merge.ErrNotOffered) {
		t.Fatalf("a 403: %v", err)
	}
	if _, err := ask(answer(404, map[string]any{"code": "not_offered", "message": "e2e"}), ""); !errors.Is(err, merge.ErrNotOffered) {
		t.Fatalf("not_offered: %v", err)
	}
}
