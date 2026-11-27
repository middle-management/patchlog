package core

import "github.com/middle-management/patchlog/internal/ids"

// checkSource validates a batch's source at step 4 (§7.5). It returns the
// source as recorded and, for a local source the caller may read
// unrestricted (with the grant in Source-Authorization, if given), whose
// source.at it checked, the source that makes blobs available (§7.8). Any
// other caller's local source is recorded unchecked and makes no blobs
// available, so the check reveals nothing about a namespace it can't read.
// A source.origin that is this deployment's own is 422 source for any
// caller. A local source.ns that is purged is 410 purged, with ns and
// head, for any caller (§7.5, §8.5, v0.91), and so is another
// deployment's whose purge-ns this deployment has followed, for a batch
// that counts there (followedPurgeOf, §G.1).
func (t *tx) checkSource(req Request, v any, n *nsRow, a *actor, st []*itemState) (any, *batchSource, *Error) {
	m, ok := v.(map[string]any)
	if !ok {
		return nil, nil, invalid("source must be an object")
	}
	for k := range m {
		switch k {
		case "origin", "ns", "at", "bundle", "ids":
		default:
			return nil, nil, invalid("unknown source member " + k)
		}
	}
	ns, _ := m["ns"].(string)
	at, _ := m["at"].(string)
	if !ValidNSName(ns) || at == "" {
		return nil, nil, invalid("source needs ns and at")
	}
	if o, has := m["origin"]; has {
		if o == t.e.opt.Origin {
			// For any caller: it reveals nothing (§7.5, §12.1).
			return nil, nil, apiErr(422, "source", "message", "source.origin is this deployment's own")
		}
		if pe := t.followedPurgeOf(m, n, a, st); pe != nil {
			return nil, nil, pe
		}
		return m, nil, nil // another deployment's blobs are uploaded
	}
	sn := t.nsByName(ns)
	if sn != nil && sn.purged {
		pe := t.purgedNS(sn)
		pe.Body["ns"] = ns
		return nil, nil, pe
	}
	if sn == nil || !t.sourceUnrestricted(sn, req) {
		return m, nil, nil
	}
	id, err := ids.Parse(at)
	if err != nil {
		return nil, nil, apiErr(422, "source", "message", "source.at is not in the chain of source.ns")
	}
	seq, ok := t.nsLogSeq(sn.id, id)
	if !ok {
		return nil, nil, apiErr(422, "source", "message", "source.at is not in the chain of source.ns")
	}
	return m, &batchSource{n: sn, atSeq: seq, creds: req.anyCreds()}, nil
}
