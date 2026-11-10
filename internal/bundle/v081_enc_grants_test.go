package bundle_test

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/bundle"
	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/grant"
	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/seal"
)

// kn reseals the grant answers of sealedGrantsHandler, which seals under
// K_e as servers before v0.81 did, under K_n (§E.2.1, §E.2.2).
func kn(t *testing.T, inner func(http.Handler, *client.Client) http.Handler) func(http.Handler, *client.Client) http.Handler {
	return func(next http.Handler, c *client.Client) http.Handler {
		h := inner(next, c)
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !strings.Contains(r.URL.Path, "/grants/") {
				h.ServeHTTP(w, r)
				return
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, r)
			body := rec.Body.Bytes()
			if rec.Code == 200 && rec.Header().Get("Content-Type") == seal.ContentType {
				jwe, err := resealKn(c, string(body))
				if err != nil {
					// Not t.Fatal, off the test's goroutine: the exporter
					// would retry the grant for ever.
					t.Errorf("resealing a grant under K_n: %v", err)
					w.WriteHeader(500)
					return
				}
				body = []byte(jwe)
			}
			for k, v := range rec.Header() {
				if k != "Content-Length" {
					w.Header()[k] = v
				}
			}
			w.WriteHeader(rec.Code)
			w.Write(body)
		})
	}
}

// resealKn opens jwe, sealed under K_e of epoch 1 of its kid's namespace,
// and seals its plaintext again under that epoch's K_n.
func resealKn(c *client.Client, jwe string) (string, error) {
	hd, err := seal.ParseHeader(jwe)
	if err != nil {
		return "", err
	}
	ns, _, _ := seal.ParseKid(hd.Kid)
	es, err := c.FetchKeys(ctx, ns, []int{1}, nil)
	if err != nil || len(es) == 0 {
		return "", fmt.Errorf("keys %v %v", es, err)
	}
	_, pt, err := seal.Open(jwe, es[0].Key)
	if err != nil {
		return "", err
	}
	k, err := seal.NamespaceKey(es[0].Key, ns)
	if err != nil {
		return "", err
	}
	return seal.Seal(k, hd.Kid, hd.PL, pt)
}

// KEYS-4 (§E.2.2, TOOLS §G.4.2): a sealed namespace's grants are sealed
// under K_n since v0.81; the exporter derives it from the K_e /keys gives
// and the bundle carries the grant line, so the signatures verify.
func TestV081ExportOpensGrantUnderKn(t *testing.T) {
	t.Parallel()
	nsKey := clienttest.NewKey("ns-key")
	bot := signerKey(t, "bot-1", 1)
	g := mintFor(t, nsKey.Priv, nsKey.Kid, "alice", "s", bot)
	served := map[string]*grant.Grant{g.ID().String(): g}
	src := newWrappedEncDeployment(t, stagingOrigin, kn(t, sealedGrantsHandler(t, served, func(a string) *grant.Grant {
		if a == "alice" {
			return g
		}
		return nil
	}, []map[string]any{})))
	src.ns("s", map[string]any{"read": "grant", "encryption": map[string]any{"level": "sealed"},
		"keys": []any{nsKey.Entry("create", "append", "delete", "read")}})
	canon := func(p any) []byte { return jsonv.Canonical(must(client.ToValue(p))) }
	p1 := append(client.GenesisPatches(map[string]any{"v": marker}), op("add", "/$nonce", seal.NewNonce()))
	r1 := must(src.c.Create(ctx, "s", "a", p1, client.WithSignature(bot.SignPatches(stagingOrigin, "s", "a", nil, canon(p1))))).ID
	par := must(ids.Parse(r1))
	p2 := nonce(op("add", "/w", 2.0))
	must(src.c.Append(ctx, "s", "a", r1, p2, client.WithSignature(bot.SignPatches(stagingOrigin, "s", "a", &par, canon(p2)))))
	var buf bytes.Buffer
	plan, _, err := bundle.Export(ctx, src.c, &buf, bundle.ExportOptions{Select: []string{"s"}, Authors: true, Plaintext: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Notes) != 0 {
		t.Fatalf("notes %v", plan.Notes)
	}
	n := 0
	for _, m := range lineMaps(t, buf.Bytes())[1:] {
		if m["stored"] != nil {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("%d grant lines", n)
	}
}
