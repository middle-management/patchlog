package server

import (
	"context"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	plclient "github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/core"
	"github.com/middle-management/patchlog/internal/edge"
	"github.com/middle-management/patchlog/internal/grant"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/seal"
)

// keyEntries returns the entries of a 200 POST /ns/{ns}/keys answer.
func keyEntries(t *testing.T, r *resp) []map[string]any {
	t.Helper()
	expect(t, r, 200)
	var out []map[string]any
	for _, x := range r.Obj()["keys"].([]any) {
		out = append(out, x.(map[string]any))
	}
	return out
}

// P18, ENC-8 (§E.2.3): /keys entries are { kid, name?, from?, wrapped },
// or at E2 { kid, name?, key } for a grant without enc: name for a K_r,
// and no suite or resource member.
func TestV073KeysEntryShape(t *testing.T) {
	t.Parallel()
	e := newSealedAuthEnv(t)
	k := newKey("k")
	e.mkNS("s", map[string]any{"read": "grant", "keys": []any{k.entry("*")}, "encryption": map[string]any{"level": "sealed"}})
	jwk, _, _ := seal.GenerateRecipient()
	fixA := []any{map[string]any{"op": "test", "path": "/resource", "value": "a"}}
	for name, c := range map[string]struct {
		extra   map[string]any
		members []string
	}{
		"K_r raw":     {map[string]any{"rules": fixA}, []string{"key", "kid", "name"}},
		"K_r wrapped": {map[string]any{"rules": fixA, "enc": jwk}, []string{"kid", "name", "wrapped"}},
		"K_e raw":     {nil, []string{"key", "kid"}},
		"K_e wrapped": {map[string]any{"enc": jwk}, []string{"kid", "wrapped"}},
	} {
		var extra []map[string]any
		if c.extra != nil {
			extra = append(extra, c.extra)
		}
		g := e.grant(k, "user:r", []string{"s"}, []string{"read"}, extra...)
		_, r := e.keysOf("s", map[string]any{"resources": []any{"a"}}, g)
		entries := keyEntries(t, r)
		if len(entries) != 1 {
			t.Fatalf("%s: %s", name, r.Body)
		}
		var got []string
		for m := range entries[0] {
			got = append(got, m)
		}
		sort.Strings(got)
		if strings.Join(got, ",") != strings.Join(c.members, ",") {
			t.Errorf("%s: members %v, want %v (%s)", name, got, c.members, r.Body)
		}
		if n, ok := entries[0]["name"]; ok && n != "a" {
			t.Errorf("%s: name %v", name, n)
		}
	}
}

// P18, ENC-11 (§E.3.2): the keyring document is { "keys": [{ kid, to,
// from, wrapped }] } with nothing else but a $nonce, entries of exactly
// those members, no two for one kid and to, kids of this namespace and
// epochs not after encryption.epoch; written in plaintext, checked as
// outside E3. A keyring in the format before v0.63 is refused.
func TestV073KeyringDocument(t *testing.T) {
	t.Parallel()
	f := newE2E(t)
	e := f.tenv
	_, admin, _ := seal.GenerateRecipient()
	readerPub, _ := seal.ParseRecipientJWK(f.readerJWK)
	k1 := seal.NewKey()
	kr, err := seal.BuildKeyringV2(admin, "e", 1, k1, []*ecdh.PublicKey{admin.PublicKey(), readerPub})
	if err != nil {
		t.Fatal(err)
	}
	good := kr.Value()
	entry := func(i int) map[string]any {
		m := map[string]any{}
		for k, v := range good["keys"].([]any)[i].(map[string]any) {
			m[k] = v
		}
		return m
	}
	legacy, _ := seal.BuildKeyring("e", 1, k1, []*ecdh.PublicKey{readerPub})
	other, _ := seal.BuildKeyringV2(admin, "x", 1, k1, []*ecdh.PublicKey{readerPub})
	ahead, _ := seal.BuildKeyringV2(admin, "e", 2, k1, []*ecdh.PublicKey{readerPub})
	withSuite := entry(0)
	withSuite["suite"] = seal.Suite
	noFrom := entry(0)
	delete(noFrom, "from")
	badTo := entry(0)
	badTo["to"] = seal.RecipientID(readerPub)
	for name, doc := range map[string]any{
		"format before v0.63": legacy.Value(),
		"another member":      map[string]any{"keys": good["keys"], "ns": "e"},
		"entry with a suite":  map[string]any{"keys": []any{withSuite}},
		"entry without from":  map[string]any{"keys": []any{noFrom}},
		"to a recipient id":   map[string]any{"keys": []any{badTo}},
		"two for one kid, to": map[string]any{"keys": []any{entry(0), entry(0)}},
		"kid of another ns":   other.Value(),
		"epoch after epoch":   ahead.Value(),
		"keys not an array":   map[string]any{"keys": map[string]any{}},
		"no keys":             map[string]any{"$nonce": seal.NewNonce()},
		"$nonce not a string": map[string]any{"keys": good["keys"], "$nonce": 1.0},
		"wrapped not a key":   map[string]any{"keys": []any{map[string]any{"kid": "e#1", "to": entry(0)["to"], "from": entry(0)["from"], "wrapped": "AAAA"}}},
	} {
		r := e.write("PATCH", "e", "keyring", "", addRoot(doc), f.adminG)
		if r.Code != 422 || r.Str("code") != "invalid" {
			t.Errorf("%s: %d %s", name, r.Code, r.Body)
		}
		if name == "format before v0.63" && !strings.Contains(r.Str("message"), "before v0.63") {
			t.Errorf("legacy: %s", r.Body)
		}
	}
	// Two entries for one kid and different recipients, with a $nonce.
	withNonce := map[string]any{"keys": good["keys"], "$nonce": seal.NewNonce()}
	krID := e.create("e", "keyring", withNonce, f.adminG)
	// Plaintext: read as a document, not folded.
	if r := e.get("/r/e/keyring/rev/"+krID, f.readerG); r.Code != 200 || r.H.Get("X-E2E") != "" || r.Obj()["$nonce"] == nil {
		t.Fatalf("keyring read %d %v %s", r.Code, r.H, r.Body)
	}
	// Appending an old-format keyring onto it is refused too.
	expectCode(t, e.write("PATCH", "e", "keyring", krID, ops(op("replace", "", legacy.Value())), f.adminG), 422, "invalid")
}

// P18, ENC-9 and ENC-11 (§E.2.3, §E.3.2): /keys relays the keyring
// entries whose to is the RFC 7638 thumbprint of the grant's enc, with
// their from; a grant whose enc no entry names gets none.
func TestV073KeysRelayByThumbprint(t *testing.T) {
	t.Parallel()
	f := newE2E(t)
	e := f.tenv
	_, admin, _ := seal.GenerateRecipient()
	otherJWK, other, _ := seal.GenerateRecipient()
	strangerJWK, _, _ := seal.GenerateRecipient()
	k1 := seal.NewKey()
	kr, err := seal.BuildKeyringV2(admin, "e", 1, k1, []*ecdh.PublicKey{f.readerPriv.PublicKey(), other.PublicKey()})
	if err != nil {
		t.Fatal(err)
	}
	e.create("e", "keyring", kr.Value(), f.adminG)
	for _, c := range []struct {
		jwk  map[string]any
		priv *ecdh.PrivateKey
	}{{f.readerJWK, f.readerPriv}, {otherJWK, other}} {
		g := e.grant(f.writer, "user:r", []string{"e"}, []string{"read"}, map[string]any{"enc": c.jwk})
		_, r := e.keysOf("e", nil, g)
		entries := keyEntries(t, r)
		if len(entries) != 1 {
			t.Fatalf("relayed %s", r.Body)
		}
		w, err := seal.ParseWrappedKey(entries[0])
		if err != nil {
			t.Fatal(err)
		}
		want, _ := kr.Entry("e#1", seal.Thumbprint(c.priv.PublicKey()))
		if w.From != seal.Thumbprint(admin.PublicKey()) || string(w.Wrapped) != string(want.Wrapped) || len(entries[0]) != 3 {
			t.Fatalf("relayed entry %v", entries[0])
		}
		if k, err := seal.UnwrapKeyAuth(c.priv, admin.PublicKey(), w); err != nil || string(k) != string(k1) {
			t.Fatalf("unwrap: %v", err)
		}
	}
	g := e.grant(f.writer, "user:s", []string{"e"}, []string{"read"}, map[string]any{"enc": strangerJWK})
	_, r := e.keysOf("e", nil, g)
	if entries := keyEntries(t, r); len(entries) != 0 {
		t.Fatalf("a stranger got %s", r.Body)
	}
}

// kidsOf returns the kids ("kid name" for a K_r) of a 200 /keys answer,
// in order.
func kidsOf(t *testing.T, r *resp) string {
	t.Helper()
	var out []string
	for _, e := range keyEntries(t, r) {
		k := e["kid"].(string)
		if n, ok := e["name"].(string); ok {
			k += " " + n
		}
		out = append(out, k)
	}
	return strings.Join(out, ",")
}

// P18, ENC-13, ENC-14 and ENC-15 (§E.2.3): the epochs run from the one in
// force at the last namespace entry at or before the latest nbf among all
// the grant's blocks, a batch's config change included, or the first
// where there is none; the current one alone with no nbf in any block;
// with historyEpochs h, at most the current one and the h before it; and
// an epoch that began after the grant's exp isn't left out.
func TestV073KeysEpochWindow(t *testing.T) {
	t.Parallel()
	e := newSealedAuthEnv(t)
	k := newKey("k")
	e.mkNS("s", sealedDoc(map[string]any{"read": "grant", "keys": []any{k.entry("*")}}))
	long := map[string]any{"exp": t0.Add(10 * time.Hour).Format(time.RFC3339)}
	star := e.grant(k, "user:admin", []string{"s"}, []string{"create", "read", "config"}, long)
	e.clock.Advance(time.Hour)
	expect(t, e.patchNS("s", ops(op("add", "/encryption/epoch", 2.0)), star), 201)
	e.clock.Advance(time.Hour)
	// Epoch 3 begins with a batch's config change.
	r := e.do(req{method: "POST", path: "/ns/s/batch", bearer: star, body: map[string]any{
		"config": map[string]any{"ifMatch": e.configID("s", star), "patches": ops(op("add", "/encryption/epoch", 3.0))},
		"items":  []any{map[string]any{"resource": "x", "ifNoneMatch": "*", "steps": []any{withNonce(addRoot(map[string]any{}))}}}}})
	expect(t, r, 201)
	e.clock.Advance(10 * time.Minute) // t0+2h10m; epochs began at t0, t0+1h, t0+2h
	at := func(d time.Duration) string { return t0.Add(d).Format(time.RFC3339) }
	keys := func(root map[string]any, narrow ...map[string]any) string {
		t.Helper()
		root = mapsMerge(map[string]any{"kid": k.kid, "sub": "user:r", "ns": []any{"s"}, "can": []any{"read"}, "exp": at(3 * time.Hour)}, root)
		g, err := grant.Mint(root, k.priv)
		if err != nil {
			t.Fatal(err)
		}
		for _, b := range narrow {
			if g, err = g.Narrow(b); err != nil {
				t.Fatal(err)
			}
		}
		_, r := e.keysOf("s", nil, g.Encode())
		return kidsOf(t, r)
	}
	for name, c := range map[string]struct {
		root   map[string]any
		narrow []map[string]any
		want   string
	}{
		"no nbf":                         {nil, nil, "s#3"},
		"nbf before the first epoch":     {map[string]any{"nbf": at(-time.Hour)}, nil, "s#1,s#2,s#3"},
		"nbf in epoch 2":                 {map[string]any{"nbf": at(90 * time.Minute)}, nil, "s#2,s#3"},
		"a narrowing block's nbf counts": {map[string]any{"nbf": at(-time.Hour)}, []map[string]any{{"nbf": at(90 * time.Minute)}}, "s#2,s#3"},
		"only a narrowing block has nbf": {nil, []map[string]any{{"nbf": at(30 * time.Minute)}}, "s#1,s#2,s#3"},
		"the batch began epoch 3":        {map[string]any{"nbf": at(-time.Hour)}, []map[string]any{{"nbf": at(125 * time.Minute)}}, "s#3"},
	} {
		if got := keys(c.root, c.narrow...); got != c.want {
			t.Errorf("%s: %s, want %s", name, got, c.want)
		}
	}
	// historyEpochs 1: the current epoch and the one before it.
	expect(t, e.patchNS("s", ops(op("add", "/encryption/historyEpochs", 1.0)), star), 201)
	if got := keys(map[string]any{"nbf": at(-time.Hour)}); got != "s#2,s#3" {
		t.Errorf("historyEpochs 1: %s", got)
	}
	expect(t, e.patchNS("s", ops(op("remove", "/encryption/historyEpochs")), star), 201)
	// Epoch 4 begins at t0+5h, after the grant's exp (t0+3h); the clock is
	// set back for the grant to verify.
	e.clock.set(t0.Add(5 * time.Hour))
	expect(t, e.patchNS("s", ops(op("add", "/encryption/epoch", 4.0)), star), 201)
	e.clock.set(t0.Add(150 * time.Minute))
	if got := keys(map[string]any{"nbf": at(-time.Hour)}); got != "s#1,s#2,s#3,s#4" {
		t.Errorf("an epoch after exp: %s", got)
	}
}

func mapsMerge(dst, src map[string]any) map[string]any {
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

// P18, ENC-16 (§E.2.3): at E2 a grant whose rules fix /resource (§2.1)
// gets K_r for the names in resources, by default every name it fixes; a
// name it doesn't fix, or may not read, is 403. Rules that refer to
// /resource without fixing it give no K_r and, the grant not reading
// unrestricted, no K_e either.
func TestV073KeysPerResourceNames(t *testing.T) {
	t.Parallel()
	e := newSealedAuthEnv(t)
	k := newKey("k")
	e.mkNS("s", sealedDoc(map[string]any{"read": "grant", "keys": []any{k.entry("*")}}))
	enum := func(names ...any) map[string]any {
		return map[string]any{"op": "test", "path": "/resource", "schema": map[string]any{"enum": names}}
	}
	notB := map[string]any{"not": map[string]any{"op": "test", "path": "/resource", "value": "b"}}
	g := func(rules ...any) string {
		return e.grant(k, "user:li", []string{"s"}, []string{"read"}, map[string]any{"rules": rules})
	}
	for name, c := range map[string]struct {
		grant     string
		resources any // nil: absent
		status    int
		want      string
	}{
		"default: every fixed name":  {g(enum("b", "a")), nil, 200, "s#1 a,s#1 b"},
		"asked":                      {g(enum("a", "b")), []any{"b"}, 200, "s#1 b"},
		"asked twice":                {g(enum("a", "b")), []any{"a", "a"}, 200, "s#1 a"},
		"none asked":                 {g(enum("a", "b")), []any{}, 200, ""},
		"not fixed":                  {g(enum("a", "b")), []any{"a", "c"}, 403, ""},
		"fixed, not readable":        {g(enum("a", "b"), notB), []any{"b"}, 403, ""},
		"default with an unreadable": {g(enum("a", "b"), notB), nil, 403, ""},
		"readable of those":          {g(enum("a", "b"), notB), []any{"a"}, 200, "s#1 a"},
		"inside all":                 {g(map[string]any{"all": []any{enum("a", "b")}}), nil, 200, "s#1 a,s#1 b"},
		"two fixing rules intersect": {g(enum("a", "b"), map[string]any{"op": "test", "path": "/resource", "value": "a"}), nil, 200, "s#1 a"},
		"refers without fixing":      {g(notB), nil, 403, ""},
		"an invalid literal":         {g(enum("a", "b/c")), []any{"a"}, 403, ""},
		"unrestricted: K_e, ignored": {e.grant(k, "user:r", []string{"s"}, []string{"read"}), []any{"zzz"}, 200, "s#1"},
	} {
		body := map[string]any{}
		if c.resources != nil {
			body["resources"] = c.resources
		}
		r := e.do(req{method: "POST", path: "/ns/s/keys", body: body, bearer: c.grant})
		if r.Code != c.status {
			t.Errorf("%s: %d %s", name, r.Code, r.Body)
			continue
		}
		if c.status == 403 {
			if r.Str("code") != "forbidden" {
				t.Errorf("%s: %s", name, r.Body)
			}
			continue
		}
		if got := kidsOf(t, r); got != c.want {
			t.Errorf("%s: %s, want %s", name, got, c.want)
		}
	}
}

// P18, ENC-17 (§E.2.3, §6.6): each /keys request draws one token from the
// principal's exchangeRate bucket, as /edge-grants does, at E2 and E3; a
// refused request draws nothing.
func TestV073KeysExchangeRate(t *testing.T) {
	t.Parallel()
	f := newE2E(t, withExchangeRate(core.Rate{Rate: 0.001, Burst: 2}))
	e := f.tenv
	e.mkNS("s", sealedDoc(map[string]any{"read": "grant", "keys": []any{f.admin.entry("*")}}))
	sg := e.grant(f.admin, "user:r", []string{"s"}, []string{"read"})
	refused := e.grant(f.admin, "user:r", []string{"s"}, []string{"read"}, map[string]any{"rules": []any{map[string]any{"op": "test", "path": "/resource", "value": "a"}}})
	for i := 0; i < 3; i++ {
		_, r := e.keysOf("s", map[string]any{"resources": []any{"b"}}, refused)
		expectCode(t, r, 403, "forbidden")
	}
	for i := 0; i < 2; i++ {
		_, r := e.keysOf("s", nil, sg)
		expect(t, r, 200)
	}
	_, r := e.keysOf("s", nil, sg)
	if r.Code != 429 || r.Str("limit") != "exchangeRate" || r.H.Get("Retry-After") == "" {
		t.Fatalf("third /keys: %d %s", r.Code, r.Body)
	}
	// At E3 too, per principal.
	for i := 0; i < 2; i++ {
		_, r := e.keysOf("e", nil, f.readerG)
		expect(t, r, 200)
	}
	_, r = e.keysOf("e", nil, f.readerG)
	if r.Code != 429 || r.Str("limit") != "exchangeRate" {
		t.Fatalf("third e2e /keys: %d %s", r.Code, r.Body)
	}
}

// P18, ENC-18 (§E.2.3, §F.8.1): an e2e branch's /keys relays its own
// keyring's entries and each local base's keyring's as of at, even after
// the branch has written its own: for the base's epochs up to the one in
// force at at, from the one in force at the latest nbf or at at if that
// is earlier; with no nbf, the epoch the base has in force now, so none
// once it has moved past its epoch at at. The request's epochs don't
// select among the base's.
func TestV073KeysBranchBases(t *testing.T) {
	t.Parallel()
	f := newE2E(t)
	e := f.tenv
	admin := f.readerPriv // wraps the keyrings; the reader is a recipient too
	readerPub := f.readerPriv.PublicKey()
	k1, k2, k3, kb := seal.NewKey(), seal.NewKey(), seal.NewKey(), seal.NewKey()
	kr, err := seal.BuildKeyringV2(admin, "e", 1, k1, []*ecdh.PublicKey{readerPub})
	if err != nil {
		t.Fatal(err)
	}
	adm := func() string { return e.grant(f.admin, "user:admin", []string{"e", "eb"}, allVerbs) }
	head := e.create("e", "keyring", kr.Value(), adm())
	rotate := func(epoch float64, key []byte) {
		t.Helper()
		if err := kr.Add(admin, readerPub, seal.Kid("e", int(epoch)), key); err != nil {
			t.Fatal(err)
		}
		g := adm()
		r := e.do(req{method: "POST", path: "/ns/e/batch", bearer: g, body: map[string]any{
			"config": map[string]any{"ifMatch": e.configID("e", g), "patches": ops(op("add", "/encryption/epoch", epoch))},
			"items":  []any{map[string]any{"resource": "keyring", "ifMatch": head, "steps": []any{ops(op("replace", "", kr.Value()))}}}}})
		expect(t, r, 201)
		head = r.Obj()["items"].([]any)[0].(map[string]any)["ids"].([]any)[0].(string)
	}
	e.clock.Advance(time.Hour)
	rotate(2, k2) // epoch 2 from t0+1h
	e.clock.Advance(time.Hour)
	expect(t, e.branch("e", map[string]any{"name": "eb"}, adm()), 201) // at: t0+2h, epoch 2
	e.clock.Advance(10 * time.Minute)
	at := func(d time.Duration) map[string]any { return map[string]any{"nbf": t0.Add(d).Format(time.RFC3339)} }
	reader := func(extra ...map[string]any) string {
		return e.grant(f.writer, "user:reader", []string{"eb"}, []string{"read"}, append(extra, map[string]any{"enc": f.readerJWK})...)
	}
	kids := func(body map[string]any, g string) string {
		t.Helper()
		_, r := e.keysOf("eb", body, g)
		return kidsOf(t, r)
	}
	for name, c := range map[string]struct {
		grant string
		want  string
	}{
		"no nbf, base still at its epoch at at": {reader(), "e#2"},
		"nbf before the base's first epoch":     {reader(at(-time.Hour)), "e#1,e#2"},
		"nbf in epoch 1":                        {reader(at(30 * time.Minute)), "e#1,e#2"},
		"nbf after at":                          {reader(at(125 * time.Minute)), "e#2"},
	} {
		if got := kids(nil, c.grant); got != c.want {
			t.Errorf("%s: %s, want %s", name, got, c.want)
		}
	}
	// The request's epochs don't select among the base's.
	if got := kids(map[string]any{"epochs": []any{}}, reader(at(-time.Hour))); got != "e#1,e#2" {
		t.Errorf("epochs [] narrowed the base's: %s", got)
	}

	// The branch writes its own keyring, of the epoch its document copied:
	// both are relayed.
	bk, err := seal.BuildKeyringV2(admin, "eb", 2, kb, []*ecdh.PublicKey{readerPub})
	if err != nil {
		t.Fatal(err)
	}
	e.appendRev("eb", "keyring", head, ops(op("replace", "", bk.Value())), adm())
	if got := kids(nil, reader(at(-time.Hour))); got != "eb#2,e#1,e#2" {
		t.Errorf("after the branch's own keyring: %s", got)
	}
	if got := kids(map[string]any{"epochs": []any{}}, reader(at(-time.Hour))); got != "e#1,e#2" {
		t.Errorf("epochs [] with the branch's own: %s", got)
	}

	// The base moves past its epoch at at: a grant without nbf gets none
	// of the base's, and none ever gets the base's epoch after at.
	e.clock.Advance(time.Hour)
	rotate(3, k3)
	if got := kids(nil, reader()); got != "eb#2" {
		t.Errorf("no nbf, base past its epoch at at: %s", got)
	}
	if got := kids(nil, reader(at(-time.Hour))); got != "eb#2,e#1,e#2" {
		t.Errorf("after the base's rotation: %s", got)
	}
}

// withZip returns jwe with "zip":"DEF" added to its protected header: the
// server checks the header without a key, so the rest needn't open.
func withZip(t *testing.T, jwe string) string {
	t.Helper()
	parts := strings.Split(jwe, ".")
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatal(err)
	}
	var h map[string]any
	if err := json.Unmarshal(raw, &h); err != nil {
		t.Fatal(err)
	}
	h["zip"] = "DEF"
	parts[0] = base64.RawURLEncoding.EncodeToString(jsonv.Canonical(jsonv.FromGo(h)))
	return strings.Join(parts, ".")
}

// zipOp returns the sealed patch set raw with its op's JWE given a zip
// header.
func zipOp(t *testing.T, raw string) string {
	t.Helper()
	ps := jsonv.MustParse([]byte(raw)).([]any)
	op := ps[0].(map[string]any)
	op["value"] = withZip(t, op["value"].(string))
	return string(jsonv.Canonical(ps))
}

// P18, ENC-3, ENC-20 and ENC-24 (§E.3.1, step 3 and 4): an E3 sealed op,
// or a prune's snapshot, whose protected header has zip is 422 invalid; a
// sealed op's kid must name the epoch in force, for a batch's items the
// one its config change produces (422 invalid); and a declared blob that
// has a nonce is 422 blob.
func TestV073E2ESealedOpChecks(t *testing.T) {
	t.Parallel()
	e := newEnv(t, withKeyStore(newKeyStore(t)), withEncTuning, withArchive(t, t.TempDir()), withoutRetentionLoop, withoutBlobSweep)
	e.mkNS("e", e2eDoc(map[string]any{}))
	k := seal.NewKey()
	sealedUnder := func(epoch int, name, parent string, patches []any) string {
		return sealed(t, k, seal.Kid("e", epoch), "e", name, parent, patches)
	}

	// ENC-3: no zip, in a write or a snapshot.
	expectCode(t, e.writeAs("e", "z", "", zipOp(t, sealedUnder(1, "z", "", addRoot(map[string]any{"n": 0.0}))), "alice"), 422, "invalid")
	p0 := etagOf(e.writeAs("e", "p", "", sealedUnder(1, "p", "", addRoot(map[string]any{"n": 0.0})), "alice"))
	p1 := etagOf(e.writeAs("e", "p", p0, sealedUnder(1, "p", p0, ops(op("replace", "/n", 1.0))), "alice"))
	e.clock.Advance(10 * time.Minute)
	snap, err := seal.SealSnapshot(k, "e#1", "e", "p", p1, map[string]any{"n": 1.0})
	if err != nil {
		t.Fatal(err)
	}
	expectCode(t, e.prune("e", "p", map[string]any{"horizon": p1, "snapshot": withZip(t, snap)}, "admin"), 422, "invalid")
	expect(t, e.prune("e", "p", map[string]any{"horizon": p1, "snapshot": snap}, "admin"), 200)

	// ENC-20: the epoch in force only, once the namespace is at epoch 2.
	expect(t, e.patchNS("e", ops(op("add", "/encryption/epoch", 2.0)), ""), 201)
	expectCode(t, e.writeAs("e", "p", p1, sealedUnder(1, "p", p1, ops(op("replace", "/n", 2.0))), "alice"), 422, "invalid")
	p2 := etagOf(e.writeAs("e", "p", p1, sealedUnder(2, "p", p1, ops(op("replace", "/n", 2.0))), "alice"))
	// A batch that moves to epoch 3: its items seal under 3, not 2.
	batch := func(epoch int) *resp {
		return e.do(req{method: "POST", path: "/ns/e/batch", author: "admin", body: map[string]any{
			"config": map[string]any{"ifMatch": e.configID("e", ""), "patches": ops(op("add", "/encryption/epoch", 3.0))},
			"items":  []any{map[string]any{"resource": "p", "ifMatch": p2, "steps": []any{jsonv.MustParse([]byte(sealedUnder(epoch, "p", p2, ops(op("replace", "/n", 3.0)))))}}}}})
	}
	if r := batch(2); r.Code != 422 || !strings.Contains(string(r.Body), "invalid") {
		t.Fatalf("batch item under the epoch before its config change: %d %s", r.Code, r.Body)
	}
	expect(t, batch(3), 201)

	// ENC-24: a declared blob with a nonce.
	data, _, err := plclient.EncryptBlob("image/png", []byte("nonced "+encMarker), false)
	if err != nil {
		t.Fatal(err)
	}
	nonce := seal.NewNonce()
	bid := blobID(core.SealedBlobType, nonce, data)
	expect(t, e.putBlobAs("e", "b", bid, core.SealedBlobType, nonce, data, "alice"), 201)
	ps, err := seal.WithBlobs([]byte(sealedUnder(3, "b", "", addRoot(map[string]any{"pic": bid}))), []string{bid})
	if err != nil {
		t.Fatal(err)
	}
	r := e.writeAs("e", "b", "", string(ps), "alice")
	expectCode(t, r, 422, "blob")
	if !strings.Contains(r.Str("message"), "nonce") {
		t.Fatalf("blob refusal %s", r.Body)
	}
}

// P18, ENC-4 (§E.2.2): a namespace log range is sealed under K_e of the
// current epoch, not that of its last entry; a stored range keeps its
// bytes.
func TestV073RangeCurrentEpoch(t *testing.T) {
	t.Parallel()
	e := newSealedEnv(t)
	e.mkNS("s", sealedDoc(map[string]any{"read": "public"}))
	a0 := e.wr("s", "a", "", withNonce(addRoot(map[string]any{"v": 1.0})))
	h1 := e.nsHead("s")
	e.wr("s", "a", a0, withNonce(ops(op("replace", "/v", 2.0))))
	h2 := e.nsHead("s")
	kidOf := func(path string) string {
		t.Helper()
		r := e.get(path)
		expect(t, r, 200)
		h, err := seal.ParseHeader(string(r.Body))
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		return h.Kid
	}
	stored := "/ns/s/rev/" + h2 + "/log?since=" + h1
	before := string(e.get(stored).Body)
	if k := kidOf(stored); k != "s#1" {
		t.Fatalf("before the rotation: %s", k)
	}
	expect(t, e.patchNS("s", ops(op("add", "/encryption/epoch", 2.0)), ""), 201)
	// A range ending before the rotation, not stored yet: the current epoch.
	if k := kidOf("/ns/s/rev/" + h1 + "/log"); k != "s#2" {
		t.Fatalf("an unstored range of epoch 1's entries is sealed under %s, want s#2", k)
	}
	if after := string(e.get(stored).Body); after != before {
		t.Fatal("a stored range was sealed again")
	}
}

// P18, RH-44 (ENC-30, §E.2.5, §9): sealed and e2e namespaces are cached by
// read mode: a public one publicly; one with read "grant" privately, with
// edge lifetimes only on a read the verifying edge verified.
func TestV073SealedCacheByReadMode(t *testing.T) {
	t.Parallel()
	e := newEdgeEnv(t, withKeyStore(newKeyStore(t)), withEncTuning)
	e.mkNS("pub", sealedDoc(map[string]any{"read": "public"}))
	e.mkNS("priv", sealedDoc(map[string]any{"read": "grant"}))
	e.mkNS("e2", e2eDoc(map[string]any{"read": "grant"}))
	pid := e.wr("pub", "a", "", withNonce(addRoot(map[string]any{"v": 1.0})))
	qid := e.wr("priv", "a", "", withNonce(addRoot(map[string]any{"v": 1.0})))
	k := seal.NewKey()
	eid := etagOf(e.writeAs("e2", "a", "", sealed(t, k, "e2#1", "e2", "a", "", addRoot(map[string]any{"v": 1.0})), "alice"))
	get := func(path string, verified bool) *resp {
		t.Helper()
		hr, err := http.NewRequest("GET", e.srv.URL+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		hr.Header.Set("X-Author", "reader")
		if verified {
			hr.Header.Set(edge.DefaultHeader, edgeSecret)
			hr.Header.Set(edge.DefaultPrefixHeader, path[:strings.Index(path, "/rev/")])
		}
		res, err := http.DefaultClient.Do(hr)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		b, _ := io.ReadAll(res.Body)
		return &resp{Code: res.StatusCode, H: res.Header, Body: b}
	}
	if r := get("/r/pub/a/rev/"+pid, false); r.Code != 200 || r.H.Get("Cache-Control") != ccImmutable {
		t.Fatalf("public sealed: %d %v", r.Code, r.H)
	}
	for _, path := range []string{"/r/priv/a/rev/" + qid, "/r/e2/a/rev/" + eid} {
		r := get(path, false)
		if r.Code >= 400 || !strings.HasPrefix(r.H.Get("Cache-Control"), "private") || r.H.Get("CDN-Cache-Control") != "no-store" {
			t.Errorf("%s unverified: %d %v", path, r.Code, r.H)
		}
		r = get(path, true)
		if r.Code >= 400 || !strings.HasPrefix(r.H.Get("Cache-Control"), "private") || r.H.Get("CDN-Cache-Control") == "" || r.H.Get("CDN-Cache-Control") == "no-store" {
			t.Errorf("%s verified: %d %v", path, r.Code, r.H)
		}
	}
}

// flakyKeyStore fails Wrap while failing is set.
type flakyKeyStore struct {
	core.KeyStore
	failing atomic.Bool
}

func (k *flakyKeyStore) Wrap(ctx context.Context, key, aad []byte) ([]byte, error) {
	if k.failing.Load() {
		return nil, errors.New("key store unavailable")
	}
	return k.KeyStore.Wrap(ctx, key, aad)
}

// P18 carry-over (§E.2.4): with -rotate-on-revoke, a rotation that fails
// after a revocation committed is recorded as due and retried until one
// succeeds, rather than only logged.
func TestV073RotationAfterRevokeRetried(t *testing.T) {
	t.Parallel()
	ks := &flakyKeyStore{KeyStore: newKeyStore(t)}
	e := newAuthEnv(t, withKeyStore(ks), withEncTuning, func(o *core.Options) { o.RotateOnRevoke = true })
	k := newKey("k")
	e.mkNS("s", sealedDoc(map[string]any{"read": "grant", "keys": []any{k.entry("*")}}))
	star := e.grant(k, "user:admin", []string{"s"}, []string{"config", "read"})
	epoch := func() float64 {
		t.Helper()
		r := e.get("/ns/s/rev/"+e.nsHead("s", star), star)
		h, err := seal.ParseHeader(string(r.Body))
		if err != nil {
			t.Fatal(err)
		}
		_, n, _ := seal.ParseKid(h.Kid)
		return float64(n)
	}
	ctx := context.Background()
	ks.failing.Store(true)
	expect(t, e.patchNS("s", ops(op("add", "/revoked", []any{"1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"})), star), 201)
	if due, err := e.e.RotationsDue(ctx); err != nil || len(due) != 1 || due[0] != "s" {
		t.Fatalf("due after a failed rotation: %v %v", due, err)
	}
	ks.failing.Store(false)
	if epoch() != 1 {
		t.Fatal("rotated while the key store failed")
	}
	// Still failing: kept due.
	ks.failing.Store(true)
	if done, err := e.e.RetryRotations(ctx); err != nil || len(done) != 0 {
		t.Fatalf("retry while failing: %v %v", done, err)
	}
	ks.failing.Store(false)
	if done, err := e.e.RetryRotations(ctx); err != nil || len(done) != 1 {
		t.Fatalf("retry: %v %v", done, err)
	}
	if epoch() != 2 {
		t.Fatalf("epoch after the retry: %v", epoch())
	}
	if due, _ := e.e.RotationsDue(ctx); len(due) != 0 {
		t.Fatalf("still due: %v", due)
	}
}

// P18 review (ENC-17, §E.2.3 "as /edge-grants does", §C.5.2): an e2e
// /keys request that is refused (422, the grant has no enc) draws no
// exchangeRate token; the principal's next, valid request gets its keys.
func TestV073E2EKeysRefusalDrawsNoToken(t *testing.T) {
	t.Parallel()
	f := newE2E(t, withExchangeRate(core.Rate{Rate: 0.001, Burst: 1}))
	e := f.tenv
	noEnc := e.grant(f.writer, "user:reader", []string{"e"}, []string{"read"})
	if _, r := e.keysOf("e", nil, noEnc); r.Code != 422 {
		t.Fatalf("e2e /keys without enc: %d %s", r.Code, r.Body)
	}
	if _, r := e.keysOf("e", nil, f.readerG); r.Code != 200 {
		t.Fatalf("after a refused request: %d %s", r.Code, r.Body)
	}
	if _, r := e.keysOf("e", nil, f.readerG); r.Code != 429 {
		t.Fatalf("a second valid request within the burst of 1: %d %s", r.Code, r.Body)
	}
}

// P18 review (§E.2.4): with -rotate-on-revoke the rotation is recorded as
// due with the revocation, and any new epoch clears it: one an operator's
// config write begins counts as the rotation, so the retry doesn't rotate
// again; and a revocation whose rotation succeeds leaves nothing due.
func TestV073RotationDueClearedByNewEpoch(t *testing.T) {
	t.Parallel()
	ks := &flakyKeyStore{KeyStore: newKeyStore(t)}
	e := newAuthEnv(t, withKeyStore(ks), withEncTuning, func(o *core.Options) { o.RotateOnRevoke = true })
	k := newKey("k")
	e.mkNS("s", sealedDoc(map[string]any{"read": "grant", "keys": []any{k.entry("*")}}))
	star := e.grant(k, "user:admin", []string{"s"}, []string{"config", "read"})
	ctx := context.Background()
	ks.failing.Store(true)
	expect(t, e.patchNS("s", ops(op("add", "/revoked", []any{"1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"})), star), 201)
	ks.failing.Store(false)
	if due, _ := e.e.RotationsDue(ctx); len(due) != 1 {
		t.Fatalf("due: %v", due)
	}
	expect(t, e.patchNS("s", ops(op("add", "/encryption/epoch", 2.0)), star), 201)
	if due, _ := e.e.RotationsDue(ctx); len(due) != 0 {
		t.Errorf("still due after a new epoch begun by a config write: %v", due)
	}
	if done, err := e.e.RetryRotations(ctx); err != nil || len(done) != 0 {
		t.Errorf("retried a rotation a config write made: rotated %v again (%v)", done, err)
	}
	// A revocation whose rotation succeeds: epoch 3, nothing due.
	expect(t, e.patchNS("s", ops(op("add", "/revoked/-", "1bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")), star), 201)
	if due, _ := e.e.RotationsDue(ctx); len(due) != 0 {
		t.Errorf("due after a rotation that succeeded: %v", due)
	}
	h, err := seal.ParseHeader(string(e.get("/ns/s/rev/"+e.nsHead("s", star), star).Body))
	if err != nil || h.Kid != "s#3" {
		t.Errorf("namespace document after the second revocation: %v %v", h, err)
	}
}

// P18 review (ENC-14, §7.4: historyEpochs "an integer ≥ 0", §E.2.3): with
// historyEpochs 0, a grant gets keys for the current epoch alone, whatever
// its nbf; 0 isn't read as "no cap".
func TestV073HistoryEpochsZero(t *testing.T) {
	t.Parallel()
	e := newSealedAuthEnv(t)
	k := newKey("k")
	e.mkNS("s", sealedDoc(map[string]any{"read": "grant", "keys": []any{k.entry("*")}}))
	long := map[string]any{"exp": t0.Add(10 * time.Hour).Format(time.RFC3339)}
	star := e.grant(k, "user:admin", []string{"s"}, []string{"read", "config"}, long)
	e.clock.Advance(time.Hour)
	expect(t, e.patchNS("s", ops(op("add", "/encryption/epoch", 2.0)), star), 201)
	early := e.grant(k, "user:r", []string{"s"}, []string{"read"}, map[string]any{"nbf": t0.Add(-time.Hour).Format(time.RFC3339)})
	if _, r := e.keysOf("s", nil, early); kidsOf(t, r) != "s#1,s#2" {
		t.Fatalf("without historyEpochs: %s", kidsOf(t, r))
	}
	expect(t, e.patchNS("s", ops(op("add", "/encryption/historyEpochs", 0.0)), star), 201)
	if _, r := e.keysOf("s", nil, early); kidsOf(t, r) != "s#2" {
		t.Errorf("historyEpochs 0: %s", kidsOf(t, r))
	}
	expect(t, e.patchNS("s", ops(op("replace", "/encryption/historyEpochs", -1.0)), star), 422)
}
