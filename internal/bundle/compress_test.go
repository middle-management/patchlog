package bundle_test

import (
	"database/sql"
	"fmt"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/core"
	"github.com/middle-management/patchlog/internal/keystore"
	"github.com/middle-management/patchlog/internal/pgtest"
	"github.com/middle-management/patchlog/internal/seal"
	"github.com/middle-management/patchlog/internal/server"
)

// Store compression (core.Options.StoreCompression) applies only to
// namespaces without encryption: at-rest, sealed and e2e namespaces,
// padded ones included, store every patch set, head and snapshot
// encrypted (0x01), never compressed (0x02). The plaintext of those rows,
// canonical JSON, is checked in core (TestStoreCompressionRows); here, the
// writes of the clients that seal.
func TestStoreCompressionLevels(t *testing.T) {
	t.Parallel()
	if pgtest.Enabled() {
		t.Skip("store compression is SQLite only")
	}
	path := filepath.Join(t.TempDir(), "levels.db")
	ks, err := keystore.New(keystore.Generate())
	noErr(t, err)
	e, err := core.Open(core.Options{Path: path, BlobDir: t.TempDir(), Origin: cmsOrigin, AuthDisabled: true, Purger: nopPurger{}, KeyStore: ks,
		RetentionInterval: -1, StoreCompression: "zstd", StoreCompressMin: 64})
	noErr(t, err)
	hs := httptest.NewServer(clienttest.CountPages(server.New(e)))
	t.Cleanup(func() {
		hs.CloseClientConnections()
		hs.Close()
		e.Close()
	})
	c := must(client.New(hs.URL, client.WithAuthor("alice"), client.WithKeys(client.NewKeys(nil))))
	d := &deployment{t: t, origin: cmsOrigin, url: hs.URL, c: c}
	d.ns("p", map[string]any{"read": "public"})
	d.ns("a", map[string]any{"read": "public", "encryption": map[string]any{"level": "at-rest"}})
	d.ns("s", map[string]any{"read": "grant", "encryption": map[string]any{"level": "sealed", "pad": true}})
	d.ns("e", map[string]any{"read": "grant", "encryption": map[string]any{"level": "e2e", "pad": true}})
	_, priv, err := seal.GenerateRecipient()
	noErr(t, err)
	x := c.E2E(priv)
	must(x.InitKeyring(ctx, "e"))

	body := func(i int) string { return strings.Repeat(fmt.Sprintf("lorem ipsum %d dolor sit amet ", i), 80) }
	for _, ns := range []string{"p", "a", "s"} {
		id := must(c.Create(ctx, ns, "d", nonce(op("add", "", map[string]any{"title": marker, "body": body(0)})))).ID
		for i := 1; i <= 3; i++ {
			id = must(c.Append(ctx, ns, "d", id, nonce(op("add", fmt.Sprint("/p", i), body(i))))).ID
		}
	}
	id := must(x.CreateDocSealed(ctx, "e", "d", map[string]any{"title": marker, "body": body(0)})).ID
	for i := 1; i <= 3; i++ {
		id = must(x.AppendSealed(ctx, "e", "d", id, ops(op("add", fmt.Sprint("/p", i), body(i))))).ID
	}
	if doc := d.doc("s", "d"); doc["p3"] != body(3) {
		t.Fatalf("sealed doc %v", doc)
	}

	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(10000)")
	noErr(t, err)
	defer db.Close()
	forms := map[string]map[string]int{}
	for _, q := range []string{
		`SELECT n.name, substr(CAST(r.patches AS BLOB), 1, 1) FROM revisions r JOIN resources s ON s.res = r.res JOIN namespaces n ON n.ns = s.ns WHERE r.patches IS NOT NULL`,
		`SELECT n.name, substr(CAST(h.doc AS BLOB), 1, 1) FROM heads h JOIN resources s ON s.res = h.res JOIN namespaces n ON n.ns = s.ns`,
		`SELECT n.name, substr(CAST(h.doc AS BLOB), 1, 1) FROM snapshots h JOIN resources s ON s.res = h.res JOIN namespaces n ON n.ns = s.ns`,
	} {
		rows, err := db.Query(q)
		noErr(t, err)
		for rows.Next() {
			var ns string
			var first []byte
			noErr(t, rows.Scan(&ns, &first))
			form := "canonical"
			switch first[0] {
			case 1:
				form = "encrypted"
			case 2:
				form = "compressed"
			}
			if forms[ns] == nil {
				forms[ns] = map[string]int{}
			}
			forms[ns][form]++
		}
		noErr(t, rows.Err())
		rows.Close()
	}
	t.Logf("stored forms %v", forms)
	if forms["p"]["compressed"] < 4 {
		t.Fatalf("plain namespace: %v", forms["p"])
	}
	for _, ns := range []string{"a", "s", "e"} {
		if f := forms[ns]; f["compressed"] > 0 || f["canonical"] > 0 || f["encrypted"] < 4 {
			t.Fatalf("namespace %s: %v", ns, f)
		}
	}
}
