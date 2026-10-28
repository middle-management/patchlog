package core

import (
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/seal"
)

// A resource stream's purge and prune events (§7.3, §E.2.2).
//
// A resource stream follows the namespace log for the entries that purge
// or prune its resource. Each is sent as a purge or prune event whose data
// is the namespace entry without its id and prev, and which carries no SSE
// id: field, so an EventSource's Last-Event-ID stays the last revision or
// tombstone it received and a reconnect resumes the resource log, never
// the namespace's. In a sealed namespace the data is a JWE under the
// resource's K_r of the current epoch, with pl { ns, name, kind }, kind the
// event type, padded as the namespace pads: a grant that reads only that
// resource, and so holds only its K_r, opens it. Such a JWE is sealed as
// it is served, and not stored, as namespace ranges sealed again aren't:
// it has no id to be stored under.

// resourceEvents keeps, of the namespace entries es (a page of n's log),
// those that purge or prune resource name, as their events' data: without
// id and prev.
func resourceEvents(es []map[string]any, name string) []map[string]any {
	var out []map[string]any
	for _, m := range es {
		if m["resource"] != name || m["kind"] != "purge" && m["kind"] != "prune" {
			continue
		}
		d := make(map[string]any, len(m))
		for k, v := range m {
			if k != "id" && k != "prev" {
				d[k] = v
			}
		}
		out = append(out, d)
	}
	return out
}

// sealResourceEvents seals the events' data es of resource name of the
// sealed namespace n, one JWE each, under K_r of n's current epoch with pl
// { ns, name, kind } (§E.2.2).
func (t *gate) sealResourceEvents(n *nsRow, name string, es []map[string]any) []string {
	if len(es) == 0 {
		return nil
	}
	cfg := t.config(n.configSeq)
	kr, err := seal.ResourceKey(t.epochKey(n.id, cfg.Epoch), n.name, name)
	t.must(err)
	kid := seal.Kid(n.name, cfg.Epoch)
	out := make([]string, len(es))
	for i, d := range es {
		kind, _ := d["kind"].(string)
		jwe, err := seal.SealMaybePadded(kr, kid, seal.ResourceEventPL(n.name, name, kind), jsonv.Canonical(d), cfg.Pad)
		t.must(err)
		out[i] = jwe
	}
	return out
}
