package client

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/seal"
)

// E2E-1 (§E.2.2; scenario 69): a namespace event's JWE served as a
// one-entry log range is rejected by the range reader, whose pl is
// compared in full and carries no event; with the range's own plaintext,
// [entry], too. The control, the range's pl, opens.
func TestV082EventJWEAsRangeRefused(t *testing.T) {
	t.Parallel()
	ke := seal.NewKey()
	kn, err := seal.NamespaceKey(ke, "s")
	if err != nil {
		t.Fatal(err)
	}
	cid := ids.Revision(nil, []byte(`[{"op":"add","path":"","value":{}}]`))
	nsID := ids.Hash(nil, []byte(`{"kind":"config"}`)).String()
	entry := map[string]any{"id": nsID, "prev": "", "kind": "config", "target": cid.String(), "author": "a", "created": "2026-10-04T12:00:00.000Z", "grant": nil}
	one, arr := jsonv.Canonical(jsonv.FromGo(entry)), jsonv.Canonical(jsonv.FromGo([]any{entry}))
	var body string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/ns/s/rev/"+nsID+"/log" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", seal.ContentType)
		w.Write([]byte(body))
	}))
	defer srv.Close()
	keys := StaticKeys()
	keys.Add("s#1", ke)
	c, err := New(srv.URL, WithKeys(keys))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for what, pt := range map[string][]byte{"the event": one, "an event's pl over the range's plaintext": arr} {
		body, err = seal.Seal(kn, "s#1", seal.NamespaceEventPL("s", nsID), pt)
		if err != nil {
			t.Fatal(err)
		}
		if lg, err := c.NSLog(ctx, "s", nsID, ""); !errors.Is(err, seal.ErrMismatch) {
			t.Fatalf("%s served as a range: %v %v", what, lg, err)
		}
	}
	body, _ = seal.Seal(kn, "s#1", seal.RangePL("s", "", nsID), arr)
	if lg, err := c.NSLog(ctx, "s", nsID, ""); err != nil || len(lg) != 1 || lg[0].ID != nsID {
		t.Fatalf("the range: %v %v", lg, err)
	}
}
