package core

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/seal"
)

// Blobs of remote branches (§G.3, §7.8).
//
// A remote branch reads through shadows that mirror the base's chains up
// front (remote_branch.go), and its base's blobs are mirrored with them:
// every blob a mirrored document references is fetched from the base's
// immutable /r/{ns}/{name}/blob/{bid}, verified against its id (§3.7) with
// the reference that names it, and attached to the shadow's resource at
// the revisions that reference it, as a write would (blob_refs and
// blobs). Branch availability and reads (historyBlob) then work as for a
// local branch, and the branch keeps the blobs whatever the base prunes or
// loses access to later ("mirror up front to be independent").
//
// Encrypted bases (§G.5.2):
//
//   - E2. A sealed base never serves a blob's plaintext: its /blob/{bid}
//     answers 302 to the blob sealed under an epoch (§E.2.2). The client
//     follows it and opens the blob with the keys it opens the base's
//     sealed revisions with (the endpoint's grant gets K_e, or K_r for a
//     per-resource grant, from the base's POST /ns/{ns}/keys), then checks
//     it against the reference. The shadows hold the plaintext, as they
//     hold the documents', and the branch seals it under its own epoch
//     keys when it serves it.
//   - E3. The documents are ciphertext, so the blobs are those the sealed
//     ops declare in plaintext (§E.3.1): each revision's list, or for a
//     restore with [] the last live document's. The bytes are the writer's
//     ciphertext, mirrored verbatim, of SealedBlobType and without a nonce,
//     and verified against the id; their keys travel in the sealed
//     references, which only readers open. Each revision's list is
//     recorded in blob_refs and attached, as a sealed write does.

// remoteBlob is a blob fetched from the base and verified.
type remoteBlob struct {
	typ, nonce string
	data       []byte
}

// fetchBlobs fetches and verifies every blob that a document of ch
// references, from resource name of base namespace ns, whose view (as
// the base serves it, read-through included) has every document of ch.
// They are kept in ch.blobs, which prefixes share.
func fetchBlobs(ctx context.Context, c *client.Client, ns, name string, ch *remoteChain, mapErr func(string, error) *Error) *Error {
	if ch.blobs == nil {
		ch.blobs = map[ids.ID]*remoteBlob{}
	}
	if ch.opaque && ch.plain == 0 {
		return fetchDeclared(ctx, c, ns, name, ch, mapErr)
	}
	refs := map[ids.ID]blobRef{}
	var order []ids.ID
	err := ch.fold(func(i int, e client.LogEntry, doc any) error {
		// An opaque chain's documents are those from before its raise to
		// e2e (plainPrefix), whose blobs keep their references.
		if e.Kind != "rev" || ch.opaque && i >= ch.plain {
			return nil
		}
		for _, r := range blobRefsOf(doc) {
			if _, ok := refs[r.bid]; !ok {
				refs[r.bid] = r
				order = append(order, r.bid)
			}
		}
		return nil
	})
	if err != nil {
		return unverified("/r/%s/%s: %v", ns, name, err)
	}
	for _, bid := range order {
		if ch.blobs[bid] != nil {
			continue
		}
		r := refs[bid]
		what := "/r/" + ns + "/" + name + "/blob/" + bid.String()
		// GetBlobRef follows a sealed base's 302 and opens the blob with
		// the endpoint's keys (§E.2.2); a plaintext base serves it as is.
		// Either way the bytes are checked against the reference.
		b, err := c.GetBlobRef(ctx, ns, name, client.BlobRef(bid.String(), r.typ, int(r.size), r.nonce))
		if err != nil {
			return blobFetchErr(what, err, mapErr)
		}
		typ, _ := parseBlobType(b.Type)
		if typ != r.typ || int64(len(b.Data)) != r.size {
			return unverified("%s doesn't match the reference's type or size", what)
		}
		ch.blobs[bid] = &remoteBlob{typ: typ, nonce: r.nonce, data: b.Data}
	}
	if ch.opaque {
		return fetchDeclared(ctx, c, ns, name, ch, mapErr)
	}
	return nil
}

// fetchDeclared fetches and verifies the blobs an e2e chain's sealed ops
// declare (§E.3.1): the writer's ciphertext, of SealedBlobType and without
// a nonce, as the base serves it.
func fetchDeclared(ctx context.Context, c *client.Client, ns, name string, ch *remoteChain, mapErr func(string, error) *Error) *Error {
	lists, err := ch.declaredLists()
	if err != nil {
		return unverified("/r/%s/%s: %v", ns, name, err)
	}
	for _, list := range lists {
		for _, bid := range list {
			if ch.blobs[bid] != nil {
				continue
			}
			what := "/r/" + ns + "/" + name + "/blob/" + bid.String()
			b, err := c.GetBlob(ctx, ns, name, bid.String(), "")
			if err != nil {
				return blobFetchErr(what, err, mapErr)
			}
			if typ, _ := parseBlobType(b.Type); typ != SealedBlobType {
				return unverified("%s is of type %q; an e2e blob is a sealed blob (§E.3.1)", what, b.Type)
			}
			ch.blobs[bid] = &remoteBlob{typ: SealedBlobType, data: b.Data}
		}
	}
	return nil
}

// blobFetchErr maps a failed blob fetch: an answer from the base, or keys
// this deployment can't get, as mapErr does; anything else (bytes that
// don't match the reference, a sealing that doesn't open) is unverified.
func blobFetchErr(what string, err error, mapErr func(string, error) *Error) *Error {
	if _, api := client.AsAPIError(err); api || errors.Is(err, client.ErrNoKeys) {
		return mapErr(what, err)
	}
	return unverified("%s: %v", what, err)
}

// declaredLists lists, for each entry of an e2e chain, the blobs its
// resulting document references as the server knows them (§E.3.1): a
// revision's declared list, for a restore with [] the last live
// document's, and nil for a tombstone.
//
// Entries from before a raise to e2e (remoteChain.plain) are in the clear:
// their lists are the references their documents hold.
func (c *remoteChain) declaredLists() ([][]ids.ID, error) {
	out := make([][]ids.ID, len(c.entries))
	var last []ids.ID
	err := c.fold(func(i int, e client.LogEntry, doc any) error {
		if e.Kind != "rev" {
			return nil
		}
		if !e.HasPatches {
			return fmt.Errorf("revision %s has no patch set", e.ID)
		}
		switch {
		case i < c.plain:
			last = nil
			for _, r := range blobRefsOf(doc) {
				last = append(last, r.bid)
			}
		case string(jsonv.Canonical(e.Patches)) != "[]":
			_, list, ok := seal.SealedOp(e.Patches)
			if !ok {
				return fmt.Errorf("revision %s is not one sealed op (§E.3.1)", e.ID)
			}
			ds, derr := parseDeclared(list)
			if derr != nil {
				return fmt.Errorf("revision %s: malformed declared blob list (§E.3.1)", e.ID)
			}
			last = ds
		}
		out[i] = last
		return nil
	})
	return out, err
}

// attachMirrored records the blobs that doc, the document of mirrored
// revision seq of res, references, and attaches them (attachFetched).
func (t *tx) attachMirrored(res int64, ch *remoteChain, doc any, seq int64) {
	refs := blobRefsOf(doc)
	bids := make([]ids.ID, len(refs))
	for i, r := range refs {
		bids[i] = r.bid
	}
	t.attachFetched(res, ch, bids, seq)
}

// attachFetched records bids as the blobs the document of mirrored
// revision seq of res references, and attaches them (attachStep), storing
// the bytes fetched from the base; at E3 bids is the revision's declared
// list (declaredLists). A blob that wasn't fetched (a mirrored schema has
// none) is neither recorded nor attached.
func (t *tx) attachFetched(res int64, ch *remoteChain, bids []ids.ID, seq int64) {
	step := &stepState{blobs: map[ids.ID]*blobRow{}}
	owner := t.bytesOwner(res)
	for _, bid := range bids {
		b := ch.blobs[bid]
		if b == nil || step.blobs[bid] != nil {
			continue
		}
		h := sha256.Sum256(b.data)
		t.putBytes(owner, h[:], b.data)
		step.blobs[bid] = &blobRow{res: res, bid: bid, typ: b.typ, nonce: b.nonce, size: int64(len(b.data)), hash: h[:], owner: owner}
	}
	t.attachStep(res, step, seq)
}

// --- A's sealings from before its raise ---------------------------------------

// E3 sources raised from sealed (§G.5.2, Addendum E Levels). B mirrors
// A's sealings of content from before the raise byte for byte: the JWEs A
// serves for those revisions' documents and log entries, and the sealed
// blobs at their epoch URLs, those A names by redirecting …/blob/{bid}
// included, so A fixes an epoch it hadn't yet. They are fetched as A
// serves them and stored under the shadow where B would store its own
// sealing of them (the sealed table, blob_epochs), so B serves A's bytes.
// Each is checked to open, under the key of the epoch its kid names (the
// source's, which B holds for its own /keys, fetchPreRaiseKeys), to the
// content the chain verified; where B lacks that key it is stored after a
// structural check alone: a compact JWE, or a sealed blob, whose kid names
// the epoch A serves the revision under and whose pl names the content.
// B never seals that content itself (preRaiseResJob, openSealedBlob):
// what A didn't serve it (a 403, 404 or other answer that isn't a 5xx) is
// left out, and B answers for it as for a failed fetch (502 upstream,
// §G.3, preRaiseUnfetched).

// preSealings are the sealings of an opaque chain's entries from before
// its raise, as the base served them: by entry id, the log entry's and the
// document's JWE, and by blob, the sealed bytes of each epoch URL.
type preSealings struct {
	entries map[string]string
	docs    map[string]string
	blobs   map[ids.ID]map[int][]byte
}

// rawGet fetches path from the base as served, with the endpoint's grant.
// A status other than 200 is returned with no error.
func rawGet(ctx context.Context, ep RemoteEndpoint, baseURL, path string, q url.Values) (int, http.Header, []byte, error) {
	u := baseURL + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	hr, err := http.NewRequestWithContext(ctx, "GET", u, nil)
	if err != nil {
		return 0, nil, nil, err
	}
	if ep.Bearer != "" {
		hr.Header.Set("Authorization", "Bearer "+ep.Bearer)
	}
	res, err := ep.HTTPClient.Do(hr)
	if err != nil {
		return 0, nil, nil, err
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, maxPreSealing))
	if err != nil {
		return 0, nil, nil, err
	}
	return res.StatusCode, res.Header, body, nil
}

// maxPreSealing bounds one fetched answer: a log page or a document's
// JWE, or a sealed blob, which the deployment's blob size bounds anyway.
const maxPreSealing = 1 << 30

// fetchPreSealings fetches the base's sealings of ch's entries from before
// its raise from sealed (ch.plain, those served with a kid) from resource
// name of base namespace ns, checks them, and keeps them in ch.sealings,
// which prefixes share. keys are the source's epoch keys from before each
// raise, by namespace (remoteLevel.preKeys). Only no answer, or a 5xx,
// fails creation; a sealing that opens to other content than the chain
// verified, or, where B lacks its epoch's key, isn't shaped as one of that
// content under the kid A serves it with, is unverified. Any other answer
// leaves that sealing out, to be answered 502 upstream (preRaiseUnfetched).
func fetchPreSealings(ctx context.Context, ep RemoteEndpoint, baseURL, ns, name string, ch *remoteChain, keys map[string]map[int][]byte) *Error {
	last := -1
	for i := 0; i < ch.plain; i++ {
		if ch.entries[i].Kid != "" {
			last = i
		}
	}
	if last < 0 {
		return nil
	}
	what := "/r/" + ns + "/" + name
	fail := func(err error) *Error {
		if noAnswer(err) {
			return upstreamErr("%s: %v", what, err)
		}
		return nil
	}
	ps := &preSealings{entries: map[string]string{}, docs: map[string]string{}, blobs: map[ids.ID]map[int][]byte{}}
	// The log entries, from pages entirely from before the raise (§7.1
	// Paging): each a JWE.
	path := what + "/rev/" + ch.entries[last].ID + "/log"
	for since := ""; ; {
		var q url.Values
		if since != "" {
			q = url.Values{"since": {since}}
		}
		st, hdr, body, err := rawGet(ctx, ep, baseURL, path, q)
		if err != nil || st >= 500 {
			if err == nil {
				err = fmt.Errorf("%d", st)
			}
			return fail(&url.Error{Op: "GET", URL: path, Err: err})
		}
		if st != 200 {
			// None of these entries is had: B answers them 502 upstream,
			// never its own sealing (preRaiseUnfetched).
			log.Printf("remote base %s: its sealed log entries from before its raise: %d; the branch answers them 502 upstream", what, st)
			break
		}
		var page []any
		if json.Unmarshal(body, &page) != nil {
			return unverified("%s: a log page that isn't an array", path)
		}
		for _, v := range page {
			s, ok := v.(string)
			if !ok {
				continue
			}
			if h, err := seal.ParseHeader(s); err == nil {
				if id, ok := h.PL["id"].(string); ok {
					ps.entries[id] = s
				}
			}
		}
		next := hdr.Get("X-Log-Next")
		if next == "" || next == since {
			break
		}
		since = next
	}
	docs := map[int]any{}
	if err := ch.fold(func(i int, e client.LogEntry, doc any) error {
		if i < ch.plain {
			docs[i] = doc
		}
		return nil
	}); err != nil {
		return unverified("%s: %v", what, err)
	}
	blobEpochs := map[ids.ID]map[int]bool{}
	for i := 0; i <= last; i++ {
		e := ch.entries[i]
		if e.Kid == "" {
			continue
		}
		kns, epoch, err := seal.ParseKid(e.Kid)
		if err != nil {
			delete(ps.entries, e.ID)
			continue
		}
		// Without the epoch's key, A's bytes are kept unchecked but for
		// their shape (preSealingShape).
		var kr []byte
		if key := keys[kns][epoch]; key != nil {
			if kr, err = seal.ResourceKey(key, kns, name); err != nil {
				kr = nil
			}
		}
		if jwe, ok := ps.entries[e.ID]; ok {
			kind := seal.KindRev
			if e.Kind == "tombstone" {
				kind = seal.KindTombstone
			}
			pl := seal.ResourcePL(kns, name, e.ID, kind)
			if kr == nil {
				if !preSealingShape(jwe, e.Kid, pl) {
					return unverified("%s: its sealing of the log entry %s isn't a JWE under %s for it", what, e.ID, e.Kid)
				}
			} else {
				pt, err := seal.OpenExpect(jwe, kr, e.Kid, pl)
				v, perr := jsonv.Parse(pt)
				if err != nil || perr != nil || !bytes.Equal(jsonv.Canonical(v), jsonv.Canonical(e.Raw)) {
					return unverified("%s: its sealing of the log entry %s doesn't open to the entry its log gives", what, e.ID)
				}
			}
		}
		if e.Kind != "rev" {
			continue
		}
		st, _, body, err := rawGet(ctx, ep, baseURL, what+"/rev/"+e.ID, nil)
		switch {
		case err != nil || st >= 500:
			if err == nil {
				err = fmt.Errorf("%d", st)
			}
			if ferr := fail(&url.Error{Op: "GET", URL: what + "/rev/" + e.ID, Err: err}); ferr != nil {
				return ferr
			}
		case st == 200:
			jwe := string(bytes.TrimSpace(body))
			pl := seal.ResourcePL(kns, name, e.ID, seal.KindDoc)
			if kr == nil {
				if !preSealingShape(jwe, e.Kid, pl) {
					return unverified("%s: its sealing of the document of %s isn't a JWE under %s for it", what, e.ID, e.Kid)
				}
			} else {
				pt, err := seal.OpenExpect(jwe, kr, e.Kid, pl)
				v, perr := jsonv.Parse(pt)
				if err != nil || perr != nil || !bytes.Equal(jsonv.Canonical(v), jsonv.Canonical(docs[i])) {
					return unverified("%s: its sealing of the document of %s doesn't open to the document its log gives", what, e.ID)
				}
			}
			ps.docs[e.ID] = string(body)
		default:
			// Not served to B (403, 404): left out, so B answers it 502
			// upstream (preRaiseUnfetched), never with its own sealing.
			log.Printf("remote base %s: its sealing of the document of %s from before its raise: %d; the branch answers it 502 upstream", what, e.ID, st)
		}
		for _, r := range blobRefsOf(docs[i]) {
			if blobEpochs[r.bid] == nil {
				blobEpochs[r.bid] = map[int]bool{}
			}
			blobEpochs[r.bid][epoch] = true
		}
	}
	// The sealed blobs at the epoch URLs of the revisions that reference
	// them (§E.2.2, Levels), and at the one A redirects …/blob/{bid} to,
	// which fixes an epoch where none of them had one at A yet.
	for bid, eps := range blobEpochs {
		b := ch.blobs[bid]
		if b == nil {
			continue
		}
		e, herr := blobHeadEpoch(ctx, ep, baseURL, what+"/blob/"+bid.String())
		if herr != nil {
			if ferr := fail(herr); ferr != nil {
				return ferr
			}
		}
		if e > 0 {
			eps[e] = true
		}
		for epoch := range eps {
			p := what + "/blob/" + bid.String() + "/e/" + strconv.Itoa(epoch)
			st, _, body, err := rawGet(ctx, ep, baseURL, p, nil)
			if err != nil || st >= 500 {
				if err == nil {
					err = fmt.Errorf("%d", st)
				}
				if ferr := fail(&url.Error{Op: "GET", URL: p, Err: err}); ferr != nil {
					return ferr
				}
				continue
			}
			if st != 200 {
				// Left out: B answers that epoch URL 502 upstream.
				continue
			}
			h, err := seal.ParseBlobHeader(body)
			if err != nil {
				return unverified("%s: %v", p, err)
			}
			kns, e, err := seal.ParseKid(h.Kid)
			if err != nil || e != epoch {
				return unverified("%s isn't sealed under that epoch", p)
			}
			want := seal.BlobPL(kns, name, bid.String())
			if !bytes.Equal(jsonv.Canonical(map[string]any(h.PL)), jsonv.Canonical(map[string]any(want))) {
				return unverified("%s doesn't name the blob its reference names", p)
			}
			// Without the epoch's key, A's bytes are kept on their shape.
			if key := keys[kns][e]; key != nil {
				kr, err := seal.ResourceKey(key, kns, name)
				if err != nil {
					continue
				}
				if _, pt, err := seal.OpenBlob(body, kr); err != nil || !bytes.Equal(pt, b.data) {
					return unverified("%s doesn't open to the blob its reference names", p)
				}
			}
			if ps.blobs[bid] == nil {
				ps.blobs[bid] = map[int][]byte{}
			}
			ps.blobs[bid][epoch] = body
		}
	}
	ch.sealings = ps
	return nil
}

// preSealingShape is the check of a sealing of A's B can't open (§G.5.2):
// a compact JWE whose protected header's kid is kid and whose pl is pl.
func preSealingShape(jwe, kid string, pl seal.PL) bool {
	h, err := seal.ParseHeader(jwe)
	return err == nil && h.Expect(kid, pl) == nil
}

// blobHeadEpoch asks the base for path, a blob's …/blob/{bid} URL, without
// following its redirect, and returns the epoch the 302 names (§E.2.2),
// fixed by A if none was: 0 for any other answer but no answer or a 5xx,
// which is an error.
func blobHeadEpoch(ctx context.Context, ep RemoteEndpoint, baseURL, path string) (int, error) {
	hr, err := http.NewRequestWithContext(ctx, "GET", baseURL+path, nil)
	if err != nil {
		return 0, err
	}
	if ep.Bearer != "" {
		hr.Header.Set("Authorization", "Bearer "+ep.Bearer)
	}
	nc := *ep.HTTPClient
	nc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	res, err := nc.Do(hr)
	if err != nil {
		return 0, &url.Error{Op: "GET", URL: path, Err: err}
	}
	defer res.Body.Close()
	io.Copy(io.Discard, io.LimitReader(res.Body, 1<<20))
	if res.StatusCode >= 500 {
		return 0, &url.Error{Op: "GET", URL: path, Err: fmt.Errorf("%d", res.StatusCode)}
	}
	if res.StatusCode != http.StatusFound {
		return 0, nil
	}
	loc := res.Header.Get("Location")
	if u, err := url.Parse(loc); err == nil {
		loc = u.Path
	}
	rest, ok := strings.CutPrefix(loc, path+"/e/")
	if !ok {
		return 0, nil
	}
	e, err := strconv.Atoi(rest)
	if err != nil || e < 1 {
		return 0, nil
	}
	return e, nil
}

// storePreSealings stores the base's sealings of mirrored entry e of
// resource row res, inserted as revision seq, under the shadow holding it
// (fetchPreSealings): keyed as preRaiseResJob and openSealedBlob key their
// own, so they are served as A serves them. kidNS is the namespace of the
// base's chain the shadow mirrors; a sealing whose kid names another isn't
// one the shadow serves. bids are the blobs the revision's document
// references.
func (t *tx) storePreSealings(res int64, kidNS string, ps *preSealings, e client.LogEntry, seq int64, bids []ids.ID) {
	if ps == nil || e.Kid == "" {
		return
	}
	kns, epoch, err := seal.ParseKid(e.Kid)
	if err != nil || kns != kidNS {
		return
	}
	var sh int64
	var name string
	t.must(t.QueryRow(`SELECT ns, name FROM resources WHERE res = ?`, res).Scan(&sh, &name))
	key := name + "/" + e.ID
	for kind, jwe := range map[string]string{sealEntry: ps.entries[e.ID], sealDoc: ps.docs[e.ID]} {
		if jwe == "" {
			continue
		}
		_, err := t.Exec(`INSERT INTO sealed (ns, kind, key, name, rev_seq, jwe, created) VALUES (?,?,?,?,?,?,?) ON CONFLICT DO NOTHING`,
			sh, kind, key, name, seq, jwe, t.now.UnixMilli())
		t.must(err)
	}
	for _, bid := range bids {
		data := ps.blobs[bid][epoch]
		if data == nil {
			continue
		}
		var exists bool
		t.must(t.QueryRow(`SELECT EXISTS (SELECT 1 FROM blob_epochs WHERE ns = ? AND name = ? AND bid = ? AND epoch = ?)`, sh, name, bid[:], epoch).Scan(&exists))
		if exists {
			continue
		}
		var stored, file any = data, nil
		if f := t.storeFile(epochFile(sh, bid[:], epoch), data); f != "" {
			stored, file = nil, f
		}
		_, err := t.Exec(`INSERT INTO blob_epochs (ns, name, bid, epoch, data, file, created) VALUES (?,?,?,?,?,?,?)`,
			sh, name, bid[:], epoch, stored, file, t.now.UnixMilli())
		t.must(err)
	}
}

// preRaiseUnfetched is the answer for content from before its source's
// raise from sealed that remote branch shadow sh mirrors without A's
// sealing of it (fetchPreSealings): as for a failed fetch, 502 upstream
// naming the source's deployment (§G.3, §12.1), since B never seals an E3
// source's content itself (§G.5.2). It is panicked by the sealing builders
// (preRaiseResJob, openSealedBlob), as encUnavailable is, so no caller can
// go on to serve that content another way.
func (t *tx) preRaiseUnfetched(sh *nsRow, what string) *Error {
	return apiErr(502, "upstream", "origin", t.shadowOrigin(sh), "message",
		what+" is from before its source's raise from sealed, and this deployment doesn't hold the source's own sealing of it, "+
			"which it serves byte for byte and never seals itself (§G.5.2, §G.3)")
}

// shadowOrigin is the origin of the remote base whose chain shadow sh
// mirrors, found from the first shadow up ("" if none).
func (t *tx) shadowOrigin(sh *nsRow) string {
	cur := sh.id
	for range 64 {
		var origin string
		err := t.QueryRow(`SELECT origin FROM remote_bases WHERE shadow = ?`, cur).Scan(&origin)
		if err == nil {
			return origin
		}
		if !errors.Is(err, sql.ErrNoRows) {
			t.must(err)
		}
		// The shadow above reads through this one (kidName).
		if t.QueryRow(`SELECT ns FROM namespaces WHERE base = ? AND name LIKE '~%'`, cur).Scan(&cur) != nil {
			return ""
		}
	}
	return ""
}
