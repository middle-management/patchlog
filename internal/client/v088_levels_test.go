package client_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/seal"
)

// v0.88 §7.1 End-to-end namespaces ("A document its grant may not read
// (403, 404) teaches nothing, one served sealed teaches sealed, and any
// other failure fails the read"): a client that holds sealed reads a
// namespace's current document before its first plaintext 200. A 403 or
// 404 lets the plaintext through; a 401 or a 410 is no such answer, and
// the plaintext read fails, naming the document that wasn't read. Until
// v0.88 every refusal of the document taught nothing.
func TestV088OnlyAnUnreadableDocumentTeachesNothing(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	id := ids.Revision(nil, []byte("x")).String()
	for status, passes := range map[int]bool{403: true, 404: true, 401: false, 410: false} {
		st := newE3Stub(t)
		st.set("/ns/q", st.json(status, map[string]any{"code": "refused"}))
		st.set("/r/q/derby/rev/"+id, st.json(200, map[string]any{"title": "in the clear"}))
		c, _ := client.New(st.server().URL, client.WithExpectedLevel("n", "sealed"))
		_, err := c.Doc(ctx, "q", "derby", id)
		switch {
		case passes && err != nil:
			t.Errorf("q's document %d: the plaintext 200 refused: %v", status, err)
		case !passes && (err == nil || !strings.Contains(err.Error(), "reading the current namespace document of q")):
			t.Errorf("q's document %d: %v, want the plaintext read to fail naming the document", status, err)
		}
	}
}

// v0.88 §7.1 ("A document read by id is no claim: it teaches no level and
// isn't refused for its level. It takes base … from any document of the
// namespace, one it refuses or reads by id included"): NSDoc of z, a
// by-id read of a document claiming at-rest where sealed is held for n,
// isn't refused and teaches no level, but its base link holds z at n's
// level from then on.
func TestV088DocumentByIDTeachesOnlyItsBase(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	st := newE3Stub(t)
	v86NS(st, "z", map[string]any{"base": v86Base("n"), "encryption": map[string]any{"level": "at-rest"}})
	c, _ := client.New(st.server().URL, client.WithExpectedLevel("n", "sealed"))
	nsID := ids.Revision(nil, []byte("ns z")).String()
	if _, err := c.NSDoc(ctx, "z", nsID); err != nil {
		t.Fatalf("a by-id document claiming at-rest: %v, want it read", err)
	}
	if got := c.HeldLevel("z"); got != "sealed" {
		t.Fatalf("z held at %q after its by-id document, want sealed through its base", got)
	}
}

// v0.88 §E.2.2 ("In a chain of branches, each base's ns is accepted only
// up to the foreign parent of the nearest branch below it with entries of
// its own for the resource. Where they can't place such a parent, as
// where a document or /heads page that places it is unreadable to them,
// the ops it bounds fail the check and the read goes on"; Encryption
// scenario 67): ec is a branch of eb, a branch of e, and the reader may
// not read eb's namespace document. ec's fork from eb is placed from eb's
// /heads, so what eb sealed is accepted; what e sealed lies behind a fork
// that document would place, and is flagged and folded as [], the read
// going on. Until v0.88 the read failed with eb's 403.
func TestV088UnreadableBaseDocumentFlagsWhatLiesBehind(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	v := newP29Env(t, nil)
	grant := v.k.Grant(t, v.s.Now(), "user:a", []string{"e", "eb", "ec"}, p29Verbs, map[string]any{"enc": seal.RecipientJWK(v.priv.PublicKey())})
	c := v.s.Client(t, client.WithBearer(grant))
	x := c.E2E(v.priv)
	w1 := must(x.CreateDocSealed(ctx, "e", "d", map[string]any{"n": 1.0}))
	must(c.CreateBranch(ctx, "e", client.BranchRequest{Name: "eb"}))
	must(x.InitKeyring(ctx, "eb"))
	w2 := must(x.AppendSealed(ctx, "eb", "d", w1.ID, ops(op("replace", "", map[string]any{"n": 5.0}))))
	must(c.CreateBranch(ctx, "eb", client.BranchRequest{Name: "ec"}))

	// eb's head and its namespace documents are closed to this reader;
	// its /heads stays open.
	deny := regexp.MustCompile(`^/ns/eb(/rev/[^/]+)?$`)
	denied := 0
	rt := roundTrip(func(req *http.Request) (*http.Response, error) {
		if req.Method == "GET" && deny.MatchString(req.URL.Path) {
			denied++
			h := http.Header{}
			h.Set("Content-Type", "application/json")
			body := `{"error":"forbidden","code":"forbidden"}`
			return &http.Response{StatusCode: 403, Header: h, Body: io.NopCloser(strings.NewReader(body)), ContentLength: int64(len(body)), Request: req}, nil
		}
		return http.DefaultTransport.RoundTrip(req)
	})
	x2 := v.s.Client(t, client.WithBearer(grant), client.WithHTTPClient(&http.Client{Transport: rt})).E2E(v.priv)
	d, err := x2.DocE2E(ctx, "ec", "d", w2.ID)
	if err != nil {
		t.Fatalf("eb's document unreadable: %v, want the read to go on", err)
	}
	if len(d.Flagged) != 1 || d.Flagged[0].ID != w1.ID {
		t.Fatalf("e's entry behind eb's unreadable document: %+v, want it alone flagged", d)
	}
	if d.Value.(map[string]any)["n"] != 5.0 {
		t.Fatalf("eb's entry, up to the fork placed from its /heads: %+v", d)
	}
	if denied == 0 {
		t.Fatal("eb's document was never asked for")
	}
	if errors.Is(err, client.ErrLevelLowered) {
		t.Fatal(err)
	}
}
