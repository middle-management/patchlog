package index

import (
	"bytes"
	"context"
	"fmt"
	"net/http/httptest"
	"testing"

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
