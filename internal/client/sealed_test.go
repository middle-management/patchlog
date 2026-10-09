package client_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/keystore"
	"github.com/middle-management/patchlog/internal/seal"
)

func keyStore(t *testing.T) *keystore.Local {
	ks, err := keystore.New(keystore.Generate())
	if err != nil {
		t.Fatal(err)
	}
	return ks
}

func nonced(patches []any) []any {
	return append(append([]any{}, patches...), op("add", "/$nonce", seal.NewNonce()))
}

// The client decrypts every sealed read transparently, and returns what
// an unsealed namespace serves.
func TestSealedTransparent(t *testing.T) { t.Parallel(); testSealedTransparent(t) }

func testSealedTransparent(t *testing.T) {
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{KeyStore: keyStore(t), LongPoll: 150 * time.Millisecond})
	plain := s.Client(t, client.WithAuthor("alice"))
	c := plain.With(client.WithKeys(client.NewKeys(nil)))
	for _, ns := range []string{"p", "s"} {
		doc := map[string]any{"read": "public", "encryption": map[string]any{"level": "at-rest"}}
		if ns == "s" {
			doc["encryption"] = map[string]any{"level": "sealed"}
		}
		must(c.CreateNamespace(ctx, ns, doc))
	}
	sets := [][]any{nonced(client.GenesisPatches(map[string]any{"n": 0})), nonced(ops(op("replace", "/n", 1))), nonced(ops(op("add", "/m", "x")))}
	var ids []string
	for _, ns := range []string{"p", "s"} {
		parent := ""
		for i, ps := range sets {
			var w *client.WriteResult
			if parent == "" {
				w = must(c.Create(ctx, ns, "a", ps))
			} else {
				w = must(c.Append(ctx, ns, "a", parent, ps))
			}
			parent = w.ID
			if ns == "p" {
				ids = append(ids, w.ID)
			} else if ids[i] != w.ID {
				t.Fatal("ids differ")
			}
		}
	}
	if sealed := must(c.Sealed(ctx, "s")); !sealed {
		t.Fatal("s not reported sealed")
	}
	if sealed := must(c.Sealed(ctx, "p")); sealed {
		t.Fatal("p reported sealed")
	}
	// Without keys: ErrNoKeys.
	if _, err := plain.Doc(ctx, "s", "a", ids[0]); !errors.Is(err, client.ErrNoKeys) {
		t.Fatalf("no keys: %v", err)
	}
	// Documents and logs.
	for _, id := range ids {
		sd, pd := must(c.Doc(ctx, "s", "a", id)), must(c.Doc(ctx, "p", "a", id))
		if string(sd.Raw) != string(pd.Raw) {
			t.Fatalf("doc %s: %s != %s", id, sd.Raw, pd.Raw)
		}
	}
	sl, pl := must(c.Log(ctx, "s", "a", "", ids[0])), must(c.Log(ctx, "p", "a", "", ids[0]))
	if len(sl) != 2 || fmt.Sprint(sl[1].Raw) != fmt.Sprint(pl[1].Raw) || sl[1].Patches == nil {
		t.Fatalf("log %+v", sl)
	}
	// Namespace documents, logs and long-polls.
	h := must(c.NSHead(ctx, "s"))
	nd := must(c.NSDoc(ctx, "s", h.ID))
	if enc, _ := nd.Value["encryption"].(map[string]any); enc["level"] != "sealed" {
		t.Fatalf("ns doc %s", nd.Raw)
	}
	nl := must(c.NSLog(ctx, "s", h.ID, ""))
	if len(nl) != 4 || nl[3].Target != ids[2] {
		t.Fatalf("ns log %+v", nl)
	}
	part := must(c.NSLog(ctx, "s", h.ID, nl[1].ID))
	if len(part) != 2 || part[0].ID != nl[2].ID {
		t.Fatalf("ns log range %+v", part)
	}
	lp := must(c.LongPoll(ctx, "s", nl[1].ID, ""))
	if len(lp.Entries) != 2 || lp.Since != h.ID {
		t.Fatalf("long-poll %+v", lp)
	}
	rl := must(c.ResourceLongPoll(ctx, "s", "a", ids[0], ""))
	if len(rl.Entries) != 2 || rl.Since != ids[2] {
		t.Fatalf("resource long-poll %+v", rl)
	}
	// Events.
	ectx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var got []string
	stop := errors.New("stop")
	err := c.NSEvents(ectx, "s", "", func(e client.NSEntry) error {
		got = append(got, e.Kind+":"+e.Target)
		if len(got) == 4 {
			return stop
		}
		return nil
	})
	if !errors.Is(err, stop) || got[3] != "head:"+ids[2] {
		t.Fatalf("ns events %v %v", got, err)
	}
	var revs []string
	err = c.ResourceEvents(ectx, "s", "a", ids[0], func(ev client.Event) error {
		m, _ := ev.Data.(map[string]any)
		if ev.JWE == "" || m["id"] != ev.ID {
			return fmt.Errorf("event %+v", ev)
		}
		revs = append(revs, ev.ID)
		if len(revs) == 2 {
			return stop
		}
		return nil
	})
	if !errors.Is(err, stop) || revs[1] != ids[2] {
		t.Fatalf("resource events %v %v", revs, err)
	}

	// A JWE served under the wrong binding is refused: a static key ring
	// with the right key still checks pl (here: another revision's bytes).
	fk := must(c.FetchKeys(ctx, "s", nil, nil))
	st := client.StaticKeys()
	st.Add(fk[0].Kid, fk[0].Key)
	sc := plain.With(client.WithKeys(st))
	if d := must(sc.Doc(ctx, "s", "a", ids[1])); string(d.Raw) == "" {
		t.Fatal("static keys")
	}
	swap := &swapper{c: s, from: ids[1], to: ids[0]}
	bad := must(client.New(s.URL, client.WithHTTPClient(swap.client()), client.WithKeys(st)))
	if _, err := bad.Doc(ctx, "s", "a", ids[1]); !errors.Is(err, seal.ErrMismatch) {
		t.Fatalf("replayed JWE accepted: %v", err)
	}
}

// Keys wrapped to the grant's enc are unwrapped with the recipient key, and
// per-resource grants get only their resources' keys.
func TestSealedWrappedAndPerResource(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := clienttest.New(t, clienttest.Options{Auth: true, KeyStore: keyStore(t)})
	k := clienttest.NewKey("k")
	op := s.Client(t, client.WithBearer(s.OperatorGrant(t, "s")))
	must(op.CreateNamespace(ctx, "s", map[string]any{"read": "grant", "keys": []any{k.Entry("*")}, "encryption": map[string]any{"level": "sealed"}}))
	w := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:w", []string{"s"}, []string{"create", "read"})))
	a := must(w.Create(ctx, "s", "a", nonced(client.GenesisPatches(map[string]any{"v": "a"}))))
	b := must(w.Create(ctx, "s", "b", nonced(client.GenesisPatches(map[string]any{"v": "b"}))))

	jwk, priv, err := seal.GenerateRecipient()
	if err != nil {
		t.Fatal(err)
	}
	g := k.Grant(t, s.Now(), "user:r", []string{"s"}, []string{"read"}, map[string]any{"enc": jwk})
	noPriv := s.Client(t, client.WithBearer(g), client.WithKeys(client.NewKeys(nil)))
	if _, err := noPriv.Doc(ctx, "s", "a", a.ID); err == nil {
		t.Fatal("wrapped keys used without the recipient key")
	}
	r := s.Client(t, client.WithBearer(g), client.WithKeys(client.NewKeys(priv)))
	if d := must(r.Doc(ctx, "s", "a", a.ID)); d.Value.(map[string]any)["v"] != "a" {
		t.Fatalf("doc %s", d.Raw)
	}
	if nl := must(r.NSLog(ctx, "s", must(r.NSHead(ctx, "s")).ID, "")); len(nl) != 3 {
		t.Fatalf("ns log %+v", nl)
	}

	// Per-resource: a grant fixed to /resource "a" opens a, not b.
	fixed := k.Grant(t, s.Now(), "user:li", []string{"s"}, []string{"read"}, map[string]any{"rules": []any{map[string]any{"op": "test", "path": "/resource", "value": "a"}}})
	pr := s.Client(t, client.WithBearer(fixed), client.WithKeys(client.NewKeys(nil)))
	if d := must(pr.Doc(ctx, "s", "a", a.ID)); d.Value.(map[string]any)["v"] != "a" {
		t.Fatalf("per-resource doc %s", d.Raw)
	}
	if l := must(pr.Log(ctx, "s", "a", a.ID, "")); len(l) != 1 {
		t.Fatalf("per-resource log %+v", l)
	}
	// b isn't readable at all with it, so there's nothing to decrypt.
	if _, err := pr.Doc(ctx, "s", "b", b.ID); !client.IsNotFound(err) {
		t.Fatalf("b: %v", err)
	}
	fk := must(pr.FetchKeys(ctx, "s", nil, []string{"a", "b"}))
	if len(fk) != 1 || fk[0].Resource != "a" {
		t.Fatalf("per-resource keys %+v", fk)
	}
	full := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:w", []string{"s"}, []string{"read"})))
	st := client.StaticKeys()
	st.AddResource(fk[0].Kid, "a", fk[0].Key)
	sb := full.With(client.WithKeys(st))
	if _, err := sb.Doc(ctx, "s", "b", b.ID); !errors.Is(err, client.ErrNoKeys) {
		t.Fatalf("K_a used for b: %v", err)
	}
}

// swapper serves another revision's bytes for one revision (a replayed
// ciphertext, as a hostile cache could).
type swapper struct {
	c        *clienttest.Server
	from, to string
}

func (s *swapper) client() *http.Client { return &http.Client{Transport: s} }

func (s *swapper) RoundTrip(r *http.Request) (*http.Response, error) {
	r2 := r.Clone(r.Context())
	r2.URL.Path = strings.Replace(r.URL.Path, "/rev/"+s.from, "/rev/"+s.to, 1)
	return s.c.HTTP.Client().Transport.RoundTrip(r2)
}
