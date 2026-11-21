package seal

import (
	"fmt"

	"github.com/middle-management/patchlog/internal/jsonv"
)

// Filtered answers at E2 (§E.2.2, §7.9, v0.89). A partial reader's only
// key is its view's K_view (FilterViewKey). Its filtered answers are each
// one JWE under K_view, with the unfiltered form's pl and view added, and
// the plaintext
//
//	{ "body": <the answer as §7.9 gives it>, "keys": [<view's keys JWE>, …] }
//
// where each view's keys JWE, sealed once under the K_view of the
// revision's epoch with pl ViewKeysPL, holds ViewKeys: that revision's
// K_rev, its K_log where its parent is visible, and the K_blob of each
// blob its document references.

// Kinds of the filtered forms (§E.2.2).
const (
	// KindKeys binds a view's keys for a revision (ViewKeysPL).
	KindKeys = "keys"
	// KindHidden is the kind of a filtered resource stream's hidden event.
	KindHidden = "hidden"
)

// ViewKeysPL binds a view's keys for revision id of resource name:
// { ns, view, name, id, kind: "keys" } (§E.2.2).
func ViewKeysPL(ns, view, name, id string) PL {
	return PL{"ns": ns, "view": view, "name": name, "id": id, "kind": KindKeys}
}

// WithView is pl, the unfiltered form's binding, with view added: what a
// filtered answer of view is bound to (§E.2.2). pl is not changed.
func WithView(pl PL, view string) PL {
	out := make(PL, len(pl)+1)
	for k, v := range pl {
		out[k] = v
	}
	out["view"] = view
	return out
}

// FilteredRangePL binds a filtered namespace log range or long-poll
// answer: { ns, view, range: [since, last] }.
func FilteredRangePL(ns, view, since, last string) PL {
	return WithView(RangePL(ns, since, last), view)
}

// FilteredResourceRangePL binds a filtered resource log range or
// long-poll answer: { ns, view, name, range: [since, last] }.
func FilteredResourceRangePL(ns, view, name, since, last string) PL {
	return PL{"ns": ns, "view": view, "name": name, "range": []any{since, last}}
}

// FilteredHeadsPL binds a filtered /heads page: { ns, view, at, after },
// after "" on the first page.
func FilteredHeadsPL(ns, view, at, after string) PL {
	return PL{"ns": ns, "view": view, "at": at, "after": after}
}

// ViewKeys is a view's keys for one revision (§E.2.2): Key its K_rev, Log
// its K_log or nil where §7.9 shows its entry without patches, and Blobs
// the K_blob of each blob its document references, by id.
type ViewKeys struct {
	Key   []byte
	Log   []byte
	Blobs map[string][]byte
}

// Plaintext is k's canonical JSON, { "key", "log"?, "blobs" }, each key
// in base64url.
func (k ViewKeys) Plaintext() []byte {
	blobs := map[string]any{}
	for bid, b := range k.Blobs {
		blobs[bid] = b64.EncodeToString(b)
	}
	m := map[string]any{"key": b64.EncodeToString(k.Key), "blobs": blobs}
	if k.Log != nil {
		m["log"] = b64.EncodeToString(k.Log)
	}
	return jsonv.Canonical(m)
}

// ParseViewKeys parses the plaintext of a view's keys: key and every
// blob's key 32 bytes in base64url, log absent or so too, blobs an object
// (absent read as none). Other members are ignored.
func ParseViewKeys(b []byte) (ViewKeys, error) {
	v, err := jsonv.Parse(b)
	if err != nil {
		return ViewKeys{}, fmt.Errorf("%w: view keys: %v", ErrFormat, err)
	}
	m, ok := v.(map[string]any)
	if !ok {
		return ViewKeys{}, fmt.Errorf("%w: view keys", ErrFormat)
	}
	key := func(x any) ([]byte, bool) {
		s, ok := x.(string)
		if !ok {
			return nil, false
		}
		k, err := b64.DecodeString(s)
		return k, err == nil && len(k) == KeySize
	}
	var out ViewKeys
	if out.Key, ok = key(m["key"]); !ok {
		return ViewKeys{}, fmt.Errorf("%w: view keys: key", ErrFormat)
	}
	if l, has := m["log"]; has {
		if out.Log, ok = key(l); !ok {
			return ViewKeys{}, fmt.Errorf("%w: view keys: log", ErrFormat)
		}
	}
	out.Blobs = map[string][]byte{}
	if bs, has := m["blobs"]; has {
		bm, ok := bs.(map[string]any)
		if !ok {
			return ViewKeys{}, fmt.Errorf("%w: view keys: blobs", ErrFormat)
		}
		for bid, x := range bm {
			k, ok := key(x)
			if !ok {
				return ViewKeys{}, fmt.Errorf("%w: view keys: blob %s", ErrFormat, bid)
			}
			out.Blobs[bid] = k
		}
	}
	return out, nil
}

// FilteredPlaintext is a filtered answer's plaintext at E2, canonical
// { "body": body, "keys": keys }, keys the view's keys JWEs in the order
// the body first names their revisions, [] if none.
func FilteredPlaintext(body any, keys []string) []byte {
	ks := make([]any, len(keys))
	for i, k := range keys {
		ks[i] = k
	}
	return jsonv.Canonical(map[string]any{"body": body, "keys": ks})
}

// ParseFiltered splits a filtered answer's plaintext into its body and
// its keys JWEs.
func ParseFiltered(b []byte) (body any, keys []string, err error) {
	v, err := jsonv.Parse(b)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: filtered answer: %v", ErrFormat, err)
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, nil, fmt.Errorf("%w: filtered answer", ErrFormat)
	}
	body, ok = m["body"]
	if !ok {
		return nil, nil, fmt.Errorf("%w: filtered answer without body", ErrFormat)
	}
	arr, ok := m["keys"].([]any)
	if !ok {
		return nil, nil, fmt.Errorf("%w: filtered answer without keys", ErrFormat)
	}
	keys = make([]string, 0, len(arr))
	for _, x := range arr {
		s, ok := x.(string)
		if !ok {
			return nil, nil, fmt.Errorf("%w: filtered answer: keys", ErrFormat)
		}
		keys = append(keys, s)
	}
	return body, keys, nil
}
