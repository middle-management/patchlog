package client

import (
	"context"
)

// Merged gestures on an author's stack (§11.2, §F.3).
//
// A gesture a merge carried into the base counts for the author who wrote
// it in source.ns, so authors keep their stacks after a release, but only
// when the batch counts as a merge under §F.3: no origin in source,
// source.at in the branch's chain (the branch's namespace log), and the
// grant it was written under, by root sub and kid, listed in the base's
// merge.authors (the namespace document at the base's head, as the merge
// tooling reads it). Any other batch, or a merge whose branch can't be read
// (purged, forbidden), counts for whoever wrote the batch, since source is
// asserted, not verified.

// mergeAuthor is one principal of merge.authors.
type mergeAuthor struct{ sub, kid string }

// parseMergeAuthors reads "merge": { "authors": [{ "sub", "kid" }] } from a
// namespace document.
func parseMergeAuthors(doc map[string]any) []mergeAuthor {
	m, _ := doc["merge"].(map[string]any)
	arr, _ := m["authors"].([]any)
	var out []mergeAuthor
	for _, x := range arr {
		o, _ := x.(map[string]any)
		sub, _ := o["sub"].(string)
		kid, _ := o["kid"].(string)
		if sub != "" {
			out = append(out, mergeAuthor{sub, kid})
		}
	}
	return out
}

// mergerListed reports whether the entry was written under a grant whose
// root sub and kid are listed, or, with authentication disabled
// ("grant": null), whose author is (§F.3, §F.6; the same rule as
// merge.EntryListed).
func mergerListed(authors []mergeAuthor, e NSEntry, disabled bool) bool {
	switch {
	case e.Grant != nil:
		if e.Grant.Kid == "" || e.Grant.Sub == "" {
			return false
		}
		for _, a := range authors {
			if a.sub == e.Grant.Sub && a.kid == e.Grant.Kid {
				return true
			}
		}
	case e.GrantNull && disabled && e.Author != "":
		for _, a := range authors {
			if a.sub == e.Author {
				return true
			}
		}
	}
	return false
}

// mergeSource returns the branch and branch revision a batch entry claims
// to have been merged from: a source without origin naming a namespace and
// a revision.
func mergeSource(e NSEntry) (ns, at string, ok bool) {
	if e.Kind != "batch" || !e.HasSource || e.Source == nil {
		return "", "", false
	}
	if _, remote := e.Source["origin"]; remote {
		return "", "", false
	}
	ns, _ = e.Source["ns"].(string)
	at, _ = e.Source["at"].(string)
	return ns, at, ns != "" && at != ""
}

// gestureAuthors maps "resource\ngesture" to the authors that wrote it in a
// namespace log, in log order.
type gestureAuthors map[string][]string

func (g gestureAuthors) add(res, gesture, author string) {
	if gesture == "" {
		return
	}
	k := res + "\n" + gesture
	for _, a := range g[k] {
		if a == author {
			return
		}
	}
	g[k] = append(g[k], author)
}

// mergeResolver decides, per batch, whether it is a counted merge and who
// wrote its gestures in the branch. Reads are cached per call.
type mergeResolver struct {
	c        *Client
	ctx      context.Context
	base     string
	baseHead string
	loaded   bool
	authors  []mergeAuthor
	disabled bool
	branches map[string]*branchLog
}

// branchLog is a branch's namespace log, read once.
type branchLog struct {
	ids     map[string]int // entry id -> position
	entries []NSEntry
	ok      bool // readable
}

func (c *Client) newMergeResolver(ctx context.Context, base, baseHead string) *mergeResolver {
	return &mergeResolver{c: c, ctx: ctx, base: base, baseHead: baseHead, branches: map[string]*branchLog{}}
}

// unreadable reports errors that mean "this client can't see it": the
// batch then simply isn't tracked as a merge.
func unreadable(err error) bool { return IsNotFound(err) || IsGone(err) || IsAuth(err) }

func (m *mergeResolver) load() error {
	if m.loaded {
		return nil
	}
	doc, err := m.c.NSDoc(m.ctx, m.base, m.baseHead)
	if err != nil {
		if unreadable(err) {
			m.loaded = true // no merge.authors to read: nothing is a merge
			return nil
		}
		return err
	}
	authors := parseMergeAuthors(doc.Value)
	if len(authors) > 0 {
		if m.disabled, err = m.c.AuthDisabled(m.ctx); err != nil {
			return err
		}
	}
	m.authors, m.loaded = authors, true
	return nil
}

func (m *mergeResolver) branch(ns string) (*branchLog, error) {
	if b, ok := m.branches[ns]; ok {
		return b, nil
	}
	b := &branchLog{}
	h, err := m.c.NSHead(m.ctx, ns)
	if err == nil {
		b.entries, err = m.c.NSLog(m.ctx, ns, h.ID, "")
	}
	if err != nil {
		if unreadable(err) {
			m.branches[ns] = b
			return b, nil
		}
		return nil, err
	}
	b.ok = true
	b.ids = make(map[string]int, len(b.entries))
	for i, e := range b.entries {
		b.ids[e.ID] = i
	}
	m.branches[ns] = b
	return b, nil
}

// authorsOf returns who wrote each gesture of a counted merge batch in its
// branch (up to source.at), or nil when the batch doesn't count.
func (m *mergeResolver) authorsOf(e NSEntry) (gestureAuthors, error) {
	ns, at, ok := mergeSource(e)
	if !ok {
		return nil, nil
	}
	if err := m.load(); err != nil {
		return nil, err
	}
	if !mergerListed(m.authors, e, m.disabled) {
		return nil, nil
	}
	b, err := m.branch(ns)
	if err != nil || !b.ok {
		return nil, err
	}
	pos, ok := b.ids[at]
	if !ok {
		return nil, nil // source.at is not in the branch's chain
	}
	out := gestureAuthors{}
	for _, x := range b.entries[:pos+1] {
		switch x.Kind {
		case "head", "tombstone":
			out.add(x.Resource, x.Gesture, x.Author)
		case "batch":
			for res, steps := range x.Gestures {
				for _, sg := range steps {
					out.add(res, sg.Gesture, x.Author)
				}
			}
		}
	}
	return out, nil
}
