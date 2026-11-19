package client_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/seal"
)

// v86NoHeads is a transport that answers 403 to every GET of a /heads
// listing whose path deny matches, as to a reader whose grant doesn't
// reach it, and counts them.
func v86NoHeads(next http.RoundTripper, deny *regexp.Regexp) (http.RoundTripper, func() int) {
	if next == nil {
		next = http.DefaultTransport.(*http.Transport).Clone()
	}
	var mu sync.Mutex
	n := 0
	return roundTrip(func(req *http.Request) (*http.Response, error) {
			if req.Method == "GET" && strings.HasSuffix(req.URL.Path, "/heads") && deny.MatchString(req.URL.Path) {
				mu.Lock()
				n++
				mu.Unlock()
				h := http.Header{}
				h.Set("Content-Type", "application/json")
				body := `{"error":"forbidden","code":"forbidden"}`
				return &http.Response{StatusCode: 403, Header: h, Body: io.NopCloser(strings.NewReader(body)), ContentLength: int64(len(body)), Request: req}, nil
			}
			return next.RoundTrip(req)
		}), func() int {
			mu.Lock()
			defer mu.Unlock()
			return n
		}
}

var (
	v86HeadsOfE    = regexp.MustCompile(`^/ns/e/`)
	v86HeadsOfBoth = regexp.MustCompile(`^/ns/(e|eb)/`)
)

// v0.86 §E.2.2 Protected header ("Where they can't place that parent, the
// op fails the check (§E.3.2)"; ENC-14; Encryption levels scenario 87): E3
// branch eb of e, read by a reader that can read neither e's /heads nor
// any /heads of eb that places d's foreign parent. The sealed ops in eb's
// log of d whose pl.ns names e fail the pl check: each is flagged and
// folded as [], never opened unchecked, wherever in the log it stands.
// Until v0.86 the client didn't check a fork it couldn't place, and so
// accepted the base's ns anywhere in the branch's log.
func TestV086UnplaceableForeignParentFailsClosed(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	v, fork, forgedID, forged := v85Branch(t)
	rt, denied := v86NoHeads(v85Splice(fork, forgedID, forged, nil), v86HeadsOfBoth)
	// A write of eb's own on the fork, of the whole document: it applies
	// whatever came before it.
	must(v.x.InitKeyring(ctx, "eb"))
	own := must(v.x.AppendSealed(ctx, "eb", "d", fork, ops(op("replace", "", map[string]any{"n": 9.0})))).ID
	if d := must(v.x.DocE2E(ctx, "eb", "d", own)); len(d.Flagged) != 0 || d.Value.(map[string]any)["n"] != 9.0 {
		t.Fatalf("with every /heads readable: %+v", d)
	}
	x := v.s.Client(t, client.WithBearer(v.grant), client.WithHTTPClient(&http.Client{Transport: rt})).E2E(v.priv)
	d := must(x.DocE2E(ctx, "eb", "d", own))
	if len(d.Flagged) != 2 || d.Value.(map[string]any)["n"] != 9.0 {
		t.Fatalf("read through with no /heads to place the fork: %+v, want both of e's entries flagged and folded as []", d)
	}
	for _, f := range d.Flagged {
		if !strings.Contains(f.Message, "foreign parent") {
			t.Fatalf("flag %q doesn't say why", f.Message)
		}
	}
	if denied() == 0 {
		t.Fatal("the reader never asked for a /heads")
	}
	// Nothing but e's entries: no document, rather than e's unchecked.
	if d, err := x.DocE2E(ctx, "eb", "d", fork); err == nil {
		t.Fatalf("e's entries alone, the fork unplaced: %+v, want no valid revision", d)
	}
	// The spliced entry, past the fork, is refused like the others.
	if d, err := x.DocE2E(ctx, "eb", "d", forgedID); err == nil {
		t.Fatalf("the spliced entry with no /heads to place the fork: %+v", d)
	}
	// So through the log: nothing sealed under e opens.
	es, flags := must2(x.OpenLog(ctx, "eb", "d", must(v.c.Log(ctx, "eb", "d", fork, ""))))
	if len(es) != 2 || flags[0] == "" || flags[1] == "" {
		t.Fatalf("OpenLog with no /heads to place the fork: flags %q", flags)
	}
}

// v0.86 §G.4.1 ("the foreign parent: the resource's head as the branch's
// /heads lists it at the branch's first ns_id"), §E.2.2 (scenario 87:
// "neither N's /heads nor any /heads of Z that places derby's foreign
// parent"): a reader that may not read the base's /heads places the fork
// from the branch's own, at its first namespace entry. What the branch
// reads through then folds as before, and an entry sealed under the
// base's key past the fork is flagged. Until v0.86 such a reader checked
// no fork.
func TestV086ForkPlacedFromBranchOwnHeads(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	v, fork, forgedID, forged := v85Branch(t)
	rt, denied := v86NoHeads(v85Splice(fork, forgedID, forged, nil), v86HeadsOfE)
	x := v.s.Client(t, client.WithBearer(v.grant), client.WithHTTPClient(&http.Client{Transport: rt})).E2E(v.priv)
	if d := must(x.DocE2E(ctx, "eb", "d", fork)); len(d.Flagged) != 0 || d.Value.(map[string]any)["n"] != 2.0 {
		t.Fatalf("read-through fold, the fork placed by eb's own /heads: %+v", d)
	}
	if denied() == 0 {
		t.Fatal("the base's /heads was never asked for")
	}
	d := must(x.DocE2E(ctx, "eb", "d", forgedID))
	if len(d.Flagged) != 1 || d.Flagged[0].ID != forgedID || d.Value.(map[string]any)["n"] != 2.0 {
		t.Fatalf("an entry sealed under the base past the fork: %+v", d)
	}
}

// v0.86 §E.2.2, §G.3 (scenario 87, for a remote base): a remote branch's
// fork is placed only by the branch's own /heads at its first entry. A
// reader that may not read it accepts no namespace of the remote chain.
func TestV086RemoteForkUnplaceableFailsClosed(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	v, fork, forgedID, forged := v85Branch(t)
	rt, _ := v86NoHeads(v85Splice(fork, forgedID, forged, func(ns string, doc map[string]any) {
		if b, ok := doc["base"].(map[string]any); ok && ns == "eb" {
			b["origin"], b["chain"] = "https://a.example", []any{"e"}
		}
	}), regexp.MustCompile(`^/ns/eb/`))
	x := v.s.Client(t, client.WithBearer(v.grant), client.WithHTTPClient(&http.Client{Transport: rt})).E2E(v.priv)
	if d, err := x.DocE2E(ctx, "eb", "d", fork); err == nil {
		t.Fatalf("a remote branch whose own /heads the reader may not read: %+v, want no valid revision", d)
	}
	es, flags := must2(x.OpenLog(ctx, "eb", "d", must(v.c.Log(ctx, "eb", "d", fork, ""))))
	if len(es) != 2 || !strings.Contains(flags[0], "foreign parent") || !strings.Contains(flags[1], "foreign parent") {
		t.Fatalf("OpenLog of a remote branch whose fork can't be placed: flags %q", flags)
	}
}

// v0.86 §E.2.2 (the fail-closed reading for a chain of branches): ec is a
// branch of eb, a branch of e. The reader places ec's fork from eb, but
// not eb's fork from e. What eb sealed is accepted up to the fork it can
// place, and what e sealed, which lies behind the fork it can't place, is
// flagged and folded as [].
func TestV086PartlyPlacedChain(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	v := newP29Env(t, nil)
	grant := v.k.Grant(t, v.s.Now(), "user:a", []string{"e", "eb", "ec"}, p29Verbs, map[string]any{"enc": seal.RecipientJWK(v.priv.PublicKey())})
	c := v.s.Client(t, client.WithBearer(grant))
	x := c.E2E(v.priv)
	w1 := must(x.CreateDocSealed(ctx, "e", "d", map[string]any{"n": 1.0}))
	must(c.CreateBranch(ctx, "e", client.BranchRequest{Name: "eb"}))
	ebFirst, _ := must2(c.NSLogPage(ctx, "eb", must(c.NSHead(ctx, "eb")).ID, ""))
	must(x.InitKeyring(ctx, "eb"))
	// A whole-document write, which applies whatever came before it.
	w2 := must(x.AppendSealed(ctx, "eb", "d", w1.ID, ops(op("replace", "", map[string]any{"n": 5.0}))))
	must(c.CreateBranch(ctx, "eb", client.BranchRequest{Name: "ec"}))

	// Every /heads placed: the whole chain folds.
	if d := must(x.DocE2E(ctx, "ec", "d", w2.ID)); len(d.Flagged) != 0 || d.Value.(map[string]any)["n"] != 5.0 {
		t.Fatalf("the chain with every fork placed: %+v", d)
	}
	// e's /heads, and eb's at its first entry, are closed to this reader;
	// eb's /heads at ec's at stays open.
	deny := regexp.MustCompile(`^/ns/e/|^/ns/eb/rev/` + ebFirst[0].ID + `/heads$`)
	rt, denied := v86NoHeads(nil, deny)
	x2 := v.s.Client(t, client.WithBearer(grant), client.WithHTTPClient(&http.Client{Transport: rt})).E2E(v.priv)
	d := must(x2.DocE2E(ctx, "ec", "d", w2.ID))
	if len(d.Flagged) != 1 || d.Flagged[0].ID != w1.ID || !strings.Contains(d.Flagged[0].Message, "foreign parent") {
		t.Fatalf("e's entry behind the fork that can't be placed: %+v", d)
	}
	if d.Value.(map[string]any)["n"] != 5.0 {
		t.Fatalf("eb's entry, up to the fork that is placed: %+v", d)
	}
	if denied() < 2 {
		t.Fatalf("%d /heads refused, want e's and eb's own", denied())
	}
}

// v0.86 §E.2.2, §E.3.1 (a prune's snapshot "is one such op"; scenario
// 87): a snapshot a branch reads through, sealed under its base, is
// refused where the reader can't place the foreign parent. It can't be
// folded as [], so the read fails with a mismatch.
func TestV086SnapshotUnplaceableForeignParent(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	v := newP29Env(t, nil)
	w1 := must(v.x.CreateDocSealed(ctx, "e", "d", map[string]any{"n": 1.0}))
	w2 := must(v.x.AppendSealed(ctx, "e", "d", w1.ID, ops(op("replace", "/n", 2))))
	v.s.Clock.Advance(10 * time.Minute)
	must(v.x.PruneE2E(ctx, "e", "d", w2.ID))
	must(v.c.CreateBranch(ctx, "e", client.BranchRequest{Name: "eb"}))
	if d := must(v.x.DocE2E(ctx, "eb", "d", w2.ID)); d.Value.(map[string]any)["n"] != 2.0 {
		t.Fatalf("the base's snapshot read through: %+v", d)
	}
	rt, _ := v86NoHeads(nil, v86HeadsOfBoth)
	x := v.s.Client(t, client.WithBearer(v.grant), client.WithHTTPClient(&http.Client{Transport: rt})).E2E(v.priv)
	if _, err := x.DocE2E(ctx, "eb", "d", w2.ID); !errors.Is(err, seal.ErrMismatch) || !strings.Contains(err.Error(), "foreign parent") {
		t.Fatalf("the base's snapshot with no /heads to place the fork: %v, want a mismatch", err)
	}
	// Placed from the branch's own /heads, it opens.
	rt, _ = v86NoHeads(nil, v86HeadsOfE)
	x = v.s.Client(t, client.WithBearer(v.grant), client.WithHTTPClient(&http.Client{Transport: rt})).E2E(v.priv)
	if d := must(x.DocE2E(ctx, "eb", "d", w2.ID)); d.Value.(map[string]any)["n"] != 2.0 {
		t.Fatalf("the base's snapshot, the fork placed by eb's own /heads: %+v", d)
	}
}

// v0.86 §E.2.2, §B.11.9: a partial reader's /heads is a redirect to its
// filtered listing, which doesn't place a fork. It counts as a /heads the
// reader can't read: the fork is placed from the branch's own, and where
// that redirects too, nothing sealed under the base is accepted. Until
// v0.86 the redirect ended the fold with an error.
func TestV086FilteredHeadsDoNotPlaceAFork(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	v, fork, _, _ := v85Branch(t)
	redirect := func(deny *regexp.Regexp) http.RoundTripper {
		next := http.DefaultTransport.(*http.Transport).Clone()
		return roundTrip(func(req *http.Request) (*http.Response, error) {
			if req.Method == "GET" && strings.HasSuffix(req.URL.Path, "/heads") && deny.MatchString(req.URL.Path) {
				h := http.Header{}
				h.Set("Location", strings.Replace(req.URL.Path, "/rev/", "/g/1"+strings.Repeat("a", 32)+"/rev/", 1))
				return &http.Response{StatusCode: 302, Header: h, Body: io.NopCloser(strings.NewReader("")), Request: req}, nil
			}
			return next.RoundTrip(req)
		})
	}
	x := v.s.Client(t, client.WithBearer(v.grant), client.WithHTTPClient(&http.Client{Transport: redirect(v86HeadsOfE)})).E2E(v.priv)
	if d := must(x.DocE2E(ctx, "eb", "d", fork)); len(d.Flagged) != 0 || d.Value.(map[string]any)["n"] != 2.0 {
		t.Fatalf("the base's /heads filtered, the fork placed by eb's own: %+v", d)
	}
	x = v.s.Client(t, client.WithBearer(v.grant), client.WithHTTPClient(&http.Client{Transport: redirect(v86HeadsOfBoth)})).E2E(v.priv)
	_, flags := must2(x.OpenLog(ctx, "eb", "d", must(v.c.Log(ctx, "eb", "d", fork, ""))))
	if !strings.Contains(flags[0], "foreign parent") || !strings.Contains(flags[1], "foreign parent") {
		t.Fatalf("both /heads filtered: flags %q", flags)
	}
}
