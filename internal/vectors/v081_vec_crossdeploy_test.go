package vectors_test

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/keystore"
	"github.com/middle-management/patchlog/internal/seal"
)

// asV0261 reseals every sealed answer under /ns/{ns}/ from K_n to K_e, kid
// and pl unchanged, as a v0.26.1 sealed source serves its namespace
// documents, ranges and grants.
type asV0261 struct {
	rt     http.RoundTripper
	ns     string
	ke, kn []byte
}

func (a asV0261) RoundTrip(r *http.Request) (*http.Response, error) {
	resp, err := a.rt.RoundTrip(r)
	if err != nil || !strings.HasPrefix(r.URL.Path, "/ns/"+a.ns+"/") || !strings.HasPrefix(resp.Header.Get("Content-Type"), seal.ContentType) {
		return resp, err
	}
	b, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return nil, err
	}
	h, pt, err := seal.Open(strings.TrimSpace(string(b)), a.kn)
	if err != nil {
		return nil, err
	}
	jwe, err := seal.SealUncompressed(a.ke, h.Kid, h.PL, pt)
	if err != nil {
		return nil, err
	}
	resp.Body = io.NopCloser(bytes.NewReader([]byte(jwe)))
	resp.ContentLength = int64(len(jwe))
	resp.Header.Set("Content-Length", strconv.Itoa(len(jwe)))
	return resp, nil
}

// Release notes, "Cross-deployment": a v0.81 client reading a v0.26.1
// sealed source's namespace document and namespace log range, sealed
// under K_e, fails closed with the decryption error (seal.ErrDecrypt):
// namespace content opens under K_n only (§E.2.1), and drafts promise no
// compatibility with data written under an earlier draft ("Reading this
// spec"). The same answers resealed under K_n open.
func TestV081CrossDeploymentKeSealedFailsClosed(t *testing.T) {
	t.Parallel()
	ks, err := keystore.New(keystore.Generate())
	if err != nil {
		t.Fatal(err)
	}
	s := clienttest.New(t, clienttest.Options{KeyStore: ks})
	c := s.Client(t, client.WithAuthor("admin"))
	if _, err := c.CreateNamespace(ctx, "demo", map[string]any{"encryption": map[string]any{"level": "sealed"}}); err != nil {
		t.Fatal(err)
	}
	got, err := c.FetchKeys(ctx, "demo", []int{1}, nil)
	if err != nil || len(got) != 1 || got[0].Key == nil {
		t.Fatalf("keys: %+v %v", got, err)
	}
	kn, err := seal.NamespaceKey(got[0].Key, "demo")
	if err != nil {
		t.Fatal(err)
	}
	h, err := c.NSHead(ctx, "demo")
	if err != nil {
		t.Fatal(err)
	}
	for _, old := range []bool{false, true} {
		key := kn
		if old {
			key = got[0].Key
		}
		rc := s.Client(t, client.WithAuthor("admin"), client.WithKeys(client.NewKeys(nil)), client.WithTransport(func(rt http.RoundTripper) http.RoundTripper {
			return asV0261{rt, "demo", key, kn}
		}))
		doc, derr := rc.NSDoc(ctx, "demo", h.ID)
		log, lerr := rc.NSLog(ctx, "demo", h.ID, "")
		if !old {
			if derr != nil || doc == nil || lerr != nil || len(log) != 1 {
				t.Fatalf("resealed under K_n: doc %v %v, log %v %v", doc, derr, log, lerr)
			}
			continue
		}
		if !errors.Is(derr, seal.ErrDecrypt) || doc != nil {
			t.Errorf("a K_e-sealed namespace document: %v %v, want seal.ErrDecrypt", doc, derr)
		}
		if !errors.Is(lerr, seal.ErrDecrypt) || log != nil {
			t.Errorf("a K_e-sealed namespace log range: %v %v, want seal.ErrDecrypt", log, lerr)
		}
	}
}
