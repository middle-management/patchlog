package merge_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
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

// TestV073ReleaseAdminDryRunAsAdmin (TC-47, F-T4): a catalog batch that
// needs catalog-admins (step 2 creates locked with its $access) is refused
// to an approver who isn't one, with "admin": true, and the merge service
// asks again with its AdminGrant in Admin-Authorization, so the dry run
// is judged as the admin the batch then goes under (§F.8). The rest of the
// release goes under the merge key, from the approver's checks.
func TestV073ReleaseAdminDryRunAsAdmin(t *testing.T) {
	t.Parallel()
	w := newRelWorld(t)
	w.catalogKeyInMatches()
	w.startCatalog()
	w.release7()
	o := w.opts("release-7")
	o.Granter = &merge.HTTPGranter{URLs: map[string]string{"cat-season": w.svcURL}, Bearer: w.mergeBearer(), Approver: w.bobBearer(), HTTP: httpClient}
	noErr(t, merge.SaveReleasePlan(ctx, w.anna, o, must(merge.PlanRelease(ctx, w.anna, o))))
	must(merge.ApproveRelease(ctx, w.anna, o))
	rp, err := merge.ApplyRelease(ctx, w.anna, o)
	if err != nil {
		t.Fatalf("apply with a non-admin approver and an admin's grant: %v", err)
	}
	for _, st := range rp.Steps {
		if st.Key != "cat-season" {
			continue
		}
		e := entryOf(t, w.anna, "cat-season", st.Done)
		switch st.Step {
		case 2:
			if e.Grant == nil || e.Grant.Sub != "user:anna" || e.Grant.Kid != "idp" {
				t.Errorf("the $access batch went under %+v, want the admin's", e.Grant)
			}
		case 4:
			if e.Grant == nil || e.Grant.Sub != "svc:merge" || e.Grant.Kid != "catalog-merge" {
				t.Errorf("the step-4 batch went under %+v, want the merge key's", e.Grant)
			}
		}
	}

	// Without an admin's grant, the batch that needs one stops the merge.
	w2 := newRelWorld(t)
	w2.catalogKeyInMatches()
	w2.startCatalog()
	w2.release7()
	o2 := w2.opts("release-7")
	o2.Granter = &merge.HTTPGranter{URLs: map[string]string{"cat-season": w2.svcURL}, Bearer: w2.mergeBearer(), Approver: w2.bobBearer(), HTTP: httpClient}
	o2.AdminGrant = ""
	noErr(t, merge.SaveReleasePlan(ctx, w2.anna, o2, must(merge.PlanRelease(ctx, w2.anna, o2))))
	must(merge.ApproveRelease(ctx, w2.anna, o2))
	if _, err := merge.ApplyRelease(ctx, w2.anna, o2); !errors.Is(err, merge.ErrAdminNeeded) {
		t.Fatalf("apply without an admin's grant: %v", err)
	}
}

// TestV073HTTPGranterAdmin (TC-47, TC-45): the granter sends the admin's
// grant in Admin-Authorization when asked to, reads the dry run's
// checkedAs, and tells a batch that needs catalog-admins (a 403 with
// "admin": true) and a catalog without merge grants (404 not_offered)
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
	if _, err := ask(answer(403, map[string]any{"code": "forbidden", "message": "needs catalog-admins", "admin": true}), ""); !errors.Is(err, merge.ErrAdminNeeded) {
		t.Fatalf("a 403 marked admin: %v", err)
	}
	if _, err := ask(answer(403, map[string]any{"code": "forbidden", "message": "no power"}), ""); err == nil || errors.Is(err, merge.ErrAdminNeeded) {
		t.Fatalf("a plain 403: %v", err)
	}
	if _, err := ask(answer(404, map[string]any{"code": "not_offered", "message": "e2e"}), ""); !errors.Is(err, merge.ErrNotOffered) {
		t.Fatalf("not_offered: %v", err)
	}
}
