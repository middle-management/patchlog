package core

import (
	"context"
	"crypto/sha256"
	"database/sql"
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
// B stores one only once it has opened it, under the key of the epoch its
// kid names (the source's, which B holds for its own /keys,
// fetchPreRaiseKeys), to the content the chain verified (§G.5.2: "B stores
// and serves a pre-raise sealing only once it has opened and verified
// it"). At creation, a sealing whose epoch key B's grant doesn't get, A's
// /keys refusing or omitting it, is 422 as for a base B can't read, and
// one that doesn't open to that content is 502 upstream (§G.3 Creating
// one). B never seals that content itself (preRaiseResJob,
// openSealedBlob): one A didn't serve it, refusing it (a 4xx), answering
// 410 or failing transiently, is recorded as pending
// (preraise_pending.go), fetched again at each sync, and answered 502
// upstream until then, or 410 pruned once A answered that (§G.3,
// preRaiseUnfetched).

// preSealings are the sealings of an opaque chain's entries from before
// its raise, as the base served them, each opened and verified: by entry
// id, the log entry's and the document's JWE, and by blob, the sealed
// bytes of each epoch URL. pending are, by entry id, those of the entry
// and its document A didn't serve; blobAnswers, by blob and epoch, A's
// answer where it didn't serve that blob sealing, and blobWant each
// fetched blob's digest, which its sealing must open to.
type preSealings struct {
	entries     map[string]string
	docs        map[string]string
	blobs       map[ids.ID]map[int][]byte
	pending     map[string][]pendingSealing
	blobAnswers map[ids.ID]map[int][2]string
	blobWant    map[ids.ID][32]byte
}

// rawGet fetches path from the base as served, with the endpoint's grant,
// reading at most limit bytes of a 200 and maxErrBody of any other answer.
// A status other than 200 is returned with no error. A redirect isn't
// followed: it is returned as A's answer, which pendingAnswer counts as a
// refusal, so A can't point B, with its grant, at any address it picks. A
// body over its bound is errTooLarge, with the status.
func rawGet(ctx context.Context, ep RemoteEndpoint, baseURL, path string, q url.Values, limit int64) (int, http.Header, []byte, error) {
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
	nc := *ep.HTTPClient
	nc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	res, err := nc.Do(hr)
	if err != nil {
		return 0, nil, nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		limit = maxErrBody
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, limit+1))
	if err != nil {
		return 0, nil, nil, err
	}
	if int64(len(body)) > limit {
		return res.StatusCode, res.Header, nil, errTooLarge
	}
	return res.StatusCode, res.Header, body, nil
}

// errTooLarge is an answer of the base's longer than B reads (rawGet): a
// refusal, never stored (pendingAnswer).
var errTooLarge = errors.New("the answer is longer than this deployment reads for it")

// maxErrBody bounds the body of an answer other than a 200 that B reads:
// an error, whose code and horizon are all B reads of it.
const maxErrBody = 64 << 10

// preCaps bound what B reads of the base's answers for its sealings from
// before its raise (rawGet): a log page, an entry's or a document's JWE,
// and a sealed blob of size bytes (blob). They follow this deployment's
// maximums, and the true size of a blob it mirrored: a sealing that can't
// fit isn't one of content it mirrored, but padding or junk.
type preCaps struct {
	page, jwe int64
}

// preCaps are this deployment's bounds on the base's sealings: a JWE as
// large as base64 of a padded document, or patch set, of its maximum size
// (§E.2.2, padmé adds at most 12%) with its header; a log page of its
// maximum page of such entries.
func (e *Engine) preCaps() preCaps {
	m := e.opt.Maximums
	jwe := 2*int64(max(m.DocumentSize, m.PatchSetSize)) + 64<<10
	page := 2*int64(m.LogPageBytes) + int64(m.LogPageSize)*(4<<10)
	return preCaps{page: max(page, jwe), jwe: jwe}
}

// jweFor bounds A's sealing of content whose canonical JSON is n bytes
// long, where B mirrored that content: base64 of it padded (§E.2.2, padmé
// adds at most an eighth) with its IV and tag, and a header of up to
// 8 KiB.
func jweFor(n int) int64 {
	return int64(seal.PadLen(n)+64)*4/3 + 8<<10
}

// blob bounds the sealed form of a blob of size bytes: the plaintext with
// its length, padded (at most an eighth more), the header (64 KiB at most,
// seal.ParseBlobHeader) and the IV and tag.
func (preCaps) blob(size int64) int64 {
	return size + size/8 + 128<<10
}

// fetchPreSealings fetches the base's sealings of ch's entries from before
// its raise from sealed (ch.plain, those served with a kid) from resource
// name of base namespace ns, opens and checks them, and keeps them in
// ch.sealings, which prefixes share. keys are the source's epoch keys from
// before each raise, by namespace (remoteLevel.preKeys). An entry whose
// epoch's key B's grant didn't get is 422, as for a base B can't read
// (§G.3 Creating one: "except what it can't open because §E.2.3 gives its
// grant no key for that epoch, which is 422"), whether or not A serves its
// sealing; a sealing that opens to other content than the chain verified,
// or doesn't open, is unverified (502). Any other answer than a 200,
// transient failures included, leaves that sealing pending (ps.pending,
// ps.blobAnswers), for B to fetch again at each sync.
//
// What A answers is bounded (caps, rawGet), and a 410 pruned is taken only
// with a horizon that is a revision of ch after the sealing's own, or one
// after ch's head that A's log verifies (prunedIn); any other is a
// refusal, which isn't final.
func fetchPreSealings(ctx context.Context, ep RemoteEndpoint, baseURL, ns, name string, ch *remoteChain, keys map[string]map[int][]byte, caps preCaps) *Error {
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
	// Every sealing needs its epoch's key, which B gets from A's /keys
	// with its grant (fetchPreRaiseKeys): without it, B could only store
	// it unopened.
	krs := map[int][]byte{}
	for i := 0; i <= last; i++ {
		e := ch.entries[i]
		if e.Kid == "" {
			continue
		}
		kns, epoch, err := seal.ParseKid(e.Kid)
		if err != nil {
			continue
		}
		var kr []byte
		if key := keys[kns][epoch]; key != nil {
			kr, err = seal.ResourceKey(key, kns, name)
		}
		if kr == nil || err != nil {
			return fetchErr(fmt.Sprintf("%s: its sealings under %s from before the base's raise to e2e", what, e.Kid), client.ErrNoKeys)
		}
		krs[i] = kr
	}
	ps := &preSealings{entries: map[string]string{}, docs: map[string]string{}, blobs: map[ids.ID]map[int][]byte{},
		pending: map[string][]pendingSealing{}, blobAnswers: map[ids.ID]map[int][2]string{}, blobWant: map[ids.ID][32]byte{}}
	// The log entries, from pages entirely from before the raise (§7.1
	// Paging): each a JWE. Where a page isn't served, the entries not had
	// stay pending with A's answer, pruned only where A answers an entry's
	// own range so (fetchPreEntries).
	var entries []preEntry
	chain := make([]string, last+1)
	pos := make(map[string]int, len(ch.entries))
	for i, e := range ch.entries {
		pos[e.ID] = i
		if i <= last {
			chain[i] = e.ID
		}
	}
	for i := 0; i <= last; i++ {
		if e := ch.entries[i]; e.Kid != "" {
			entries = append(entries, preEntry{id: e.ID, parent: e.Parent, parentKnown: true, max: jweFor(len(jsonv.Canonical(e.Raw)))})
		}
	}
	// A's 410 pruned for the sealing of entry i, or of a blob first
	// referenced there, names a horizon of the chain after it, or is a
	// refusal.
	// A horizon after the chain's head, which the chain doesn't hold (A
	// pruned past B's at, §8.6), is taken where A's log verifies it after
	// the head (verifyHorizonPast).
	checks := horizonChecks{}
	prunedIn := func(ans, hz string, i int) (string, string) {
		if ans != pendPruned {
			return ans, hz
		}
		if j, ok := pos[hz]; ok {
			// After the sealing's own revision: A keeps the horizon's
			// document and entry (§8.6).
			if j <= i {
				return pendRefused, ""
			}
			return ans, hz
		}
		if !checks.verify(ctx, ep, baseURL, what, ch.entries[len(ch.entries)-1].ID, hz, caps) {
			return pendRefused, ""
		}
		return pendPrunedPast, hz
	}
	got, answers := fetchPreEntries(ctx, ep, baseURL, what, chain, entries, caps)
	for _, a := range answers {
		if a[0] == pendUnverified {
			return unverified("%s: a log page that isn't an array", what+"/rev/"+ch.entries[last].ID+"/log")
		}
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
	// The first entry referencing each blob under each epoch: where
	// storePreSealings records its pending row, which A's horizon for it
	// must be after.
	firstRef := map[ids.ID]map[int]int{}
	for i := 0; i <= last; i++ {
		e := ch.entries[i]
		kr := krs[i]
		if kr == nil {
			continue
		}
		kns, epoch, _ := seal.ParseKid(e.Kid)
		kind := seal.KindRev
		if e.Kind == "tombstone" {
			kind = seal.KindTombstone
		}
		pl, want := seal.ResourcePL(kns, name, e.ID, kind), contentDigest(e.Raw)
		if jwe, ok := got[e.ID]; ok {
			if !openPreSealing(jwe, kr, e.Kid, pl, want) {
				return unverified("%s: its sealing of the log entry %s doesn't open to the entry its log gives", what, e.ID)
			}
			ps.entries[e.ID] = jwe
		} else {
			ans, hz := prunedIn(answers[e.ID][0], answers[e.ID][1], i)
			ps.pending[e.ID] = append(ps.pending[e.ID], pendingSealing{kind: sealEntry, ref: e.ID, epoch: epoch, kid: e.Kid, pl: pl, want: want,
				answer: ans, horizon: hz})
		}
		if e.Kind != "rev" {
			continue
		}
		pl, want = seal.ResourcePL(kns, name, e.ID, seal.KindDoc), contentDigest(docs[i])
		st, _, body, err := rawGet(ctx, ep, baseURL, what+"/rev/"+e.ID, nil, jweFor(len(jsonv.Canonical(docs[i]))))
		if err == nil && st == 200 {
			// Stored as A serves it, without whitespace around it, which
			// openPreSealing ignores and B would serve at any length.
			jwe := trimJWE(body)
			if !openPreSealing(jwe, kr, e.Kid, pl, want) {
				return unverified("%s: its sealing of the document of %s doesn't open to the document its log gives", what, e.ID)
			}
			ps.docs[e.ID] = jwe
		} else {
			ans, hz := pendingAnswer(st, body, err)
			ans, hz = prunedIn(ans, hz, i)
			ps.pending[e.ID] = append(ps.pending[e.ID], pendingSealing{kind: sealDoc, ref: e.ID, epoch: epoch, kid: e.Kid, pl: pl, want: want,
				answer: ans, horizon: hz})
		}
		for _, r := range blobRefsOf(docs[i]) {
			if blobEpochs[r.bid] == nil {
				blobEpochs[r.bid] = map[int]bool{}
				firstRef[r.bid] = map[int]int{}
			}
			if _, ok := firstRef[r.bid][epoch]; !ok {
				firstRef[r.bid][epoch] = i
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
		ps.blobWant[bid] = sha256.Sum256(b.data)
		e, herr := blobHeadEpoch(ctx, ep, baseURL, what+"/blob/"+bid.String())
		if herr != nil {
			// The epoch URLs of the revisions are still fetched.
			log.Printf("remote base %s: the epoch A serves %s under: %v", what, bid, herr)
		}
		if e > 0 {
			eps[e] = true
		}
		for epoch := range eps {
			p := what + "/blob/" + bid.String() + "/e/" + strconv.Itoa(epoch)
			st, _, body, err := rawGet(ctx, ep, baseURL, p, nil, caps.blob(int64(len(b.data))))
			if err != nil || st != 200 {
				ans, hz := pendingAnswer(st, body, err)
				first, ok := firstRef[bid][epoch]
				if !ok {
					first = len(ch.entries) // no entry's epoch: never recorded
				}
				ans, hz = prunedIn(ans, hz, first)
				if ps.blobAnswers[bid] == nil {
					ps.blobAnswers[bid] = map[int][2]string{}
				}
				ps.blobAnswers[bid][epoch] = [2]string{ans, hz}
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
			key := keys[kns][e]
			if key == nil {
				// An epoch no entry is sealed under, whose key B lacks: it
				// can't open it, so it doesn't store it (storePreSealings
				// stores only the entries' epochs).
				continue
			}
			kr, err := seal.ResourceKey(key, kns, name)
			if err != nil || !openPreBlob(body, kr, h.Kid, seal.BlobPL(kns, name, bid.String()), ps.blobWant[bid]) {
				return unverified("%s doesn't open to the blob its reference names", p)
			}
			if ps.blobs[bid] == nil {
				ps.blobs[bid] = map[int][]byte{}
			}
			ps.blobs[bid][epoch] = body
		}
	}
	logPending(what, ps)
	ch.sealings = ps
	return nil
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
// (fetchPreSealings), each opened and verified there: keyed as
// preRaiseResJob and openSealedBlob key their own, so they are served as A
// serves them. Those A didn't serve are recorded as pending
// (recordPending), for each sync to fetch again (retryPreSealings). kidNS
// is the namespace of the base's chain the shadow mirrors; a sealing whose
// kid names another isn't one the shadow serves. bids are the blobs the
// revision's document references.
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
	for _, p := range ps.pending[e.ID] {
		t.recordPending(sh, name, seq, p)
	}
	for _, bid := range bids {
		if data := ps.blobs[bid][epoch]; data != nil {
			t.storePreBlob(sh, name, bid, epoch, data)
			continue
		}
		ans, ok := ps.blobAnswers[bid][epoch]
		if !ok {
			continue
		}
		t.recordPending(sh, name, seq, pendingSealing{kind: pendBlob, ref: bid.String(), epoch: epoch, kid: e.Kid,
			pl: seal.BlobPL(kns, name, bid.String()), want: ps.blobWant[bid], answer: ans[0], horizon: ans[1]})
	}
}

// preRaiseUnfetched is the answer for content from before its source's
// raise from sealed that remote branch shadow sh mirrors without A's
// sealing of it (fetchPreSealings): kind (sealEntry, sealDoc or pendBlob)
// of ref (a revision or blob id) of resource name, "" for none. Where A
// answered 410 pruned for that sealing it is 410 pruned with A's horizon,
// for good; otherwise, as for a failed fetch, 502 upstream naming the
// source's deployment, until a sync stores it (§G.5.2: "its resource
// answering 502 (upstream) until then, or 410 where A has pruned it",
// §G.3, §12.1), since B never seals an E3 source's content itself. It is
// panicked by the sealing builders (preRaiseResJob), as encUnavailable
// is, so no caller can go on to serve that content another way. epoch is
// the epoch URL of a blob's sealing, A's answer for which is for that
// epoch alone; for an entry or a document, which have one sealing, -1.
func (t *tx) preRaiseUnfetched(sh *nsRow, kind, name, ref string, epoch int, what string) *Error {
	if name != "" {
		if hz, ok := t.pendingPruned(sh, kind, name, ref, epoch); ok {
			return apiErr(410, "pruned", "message", what+" is from before its source's raise from sealed, whose deployment has pruned it (§G.3, §8.6)",
				"horizon", hz)
		}
	}
	return apiErr(502, "upstream", "origin", t.shadowOrigin(sh), "message",
		what+" is from before its source's raise from sealed, and this deployment doesn't hold the source's own sealing of it, "+
			"which it serves byte for byte only once it has opened and verified it, and never seals itself (§G.5.2, §G.3)")
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
