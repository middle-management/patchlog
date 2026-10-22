package index

import (
	"bytes"
	"context"
	"fmt"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/middle-management/patchlog/internal/derived"
	"github.com/middle-management/patchlog/internal/ids"
)

// TestV073StrictMins (IX-12, §A.5, F-I1): until F-I1 is answered, a min
// naming another namespace on a query of one keeps the v0.51 behaviour
// (strictMins off); the strict reading refuses it, listing it, before any
// read check, as a min naming a namespace the current checkpoint doesn't
// cover. A bare min, or one naming the queried namespace, is never refused.
func TestV073StrictMins(t *testing.T) {
	if strictMins {
		t.Fatal("strictMins is on before F-I1 is answered")
	}
	id := ids.FromBytes(bytes.Repeat([]byte{7}, ids.Size)).String()
	ix := &Index{roots: map[string]bool{"pa": true, "pb": true}}
	mins := []MinRef{{ID: id}, {NS: "pa", ID: id}, {NS: "pb", ID: id}, {NS: "zz", ID: id}}
	refused, behind, err := ix.judgeMins(context.Background(), httptest.NewRequest("GET", "/pa", nil), "pa", mins, true)
	if err != nil || behind || fmt.Sprint(refused) != fmt.Sprint([]string{"pb:" + id, "zz:" + id}) {
		t.Fatalf("strict: refused %v, behind %v, err %v", refused, behind, err)
	}
	if mins[0].NS != "pa" {
		t.Errorf("a bare min names the queried namespace: %+v", mins[0])
	}
}

// TestV073DropWholePublic (ENC-33, §E.2.6): opening the index drops the
// stored results sealed whole at a public URL, as before v0.73, with their
// tags, and keeps every other: a whole JWE at a private one (/g/{gs}, a
// namespace named g included), a public URL's JSON, /_refs answers.
func TestV073DropWholePublic(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.db")
	ix := openBare(t, path)
	ctx := context.Background()
	id := ids.FromBytes(bytes.Repeat([]byte{7}, ids.Size)).String()
	rows := []struct {
		view, scope string
		json, kept  bool
	}{
		{"/ps/at/" + id + "?q=x", "ps", false, false},
		{"/g/at/" + id + "?q=x", "g", false, false},
		{"/ps/at/" + id + "?q=y", "ps", true, true},
		{"/ps/g/" + id + "/at/" + id + "?q=x", "ps", false, true},
		{"/g/g/" + id + "/at/" + id + "?q=x", "g", false, true},
		{"/_refs/g/" + id + "/at/" + id + "?to=x", "/_refs/g/" + id, true, true},
	}
	for _, r := range rows {
		if _, err := ix.sealed.Put(ctx, r.view, r.scope, id, derived.Stored{Body: []byte("b"), JSON: r.json, Tags: "idx:" + r.scope}); err != nil {
			t.Fatal(err)
		}
	}
	ix.db.Close()
	ix = openBare(t, path)
	for _, r := range rows {
		var views, tags int
		if err := ix.db.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM sealed_views WHERE view = ?1), (SELECT count(*) FROM sealed_view_tags WHERE view = ?1)`, r.view).Scan(&views, &tags); err != nil {
			t.Fatal(err)
		}
		if want := map[bool]int{true: 1, false: 0}[r.kept]; views != want || tags != want {
			t.Errorf("%s (json %v): %d views, %d tags, want %d", r.view, r.json, views, tags, want)
		}
	}
}
