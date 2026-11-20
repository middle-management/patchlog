package core

import (
	"sync"

	"github.com/middle-management/patchlog/internal/grantcheck"
)

// fview is one subject set's view of a covered namespace at one
// checkpoint (§B.11.9 Visible): the subjects of its gs and the grant's
// read filter. Every filtered read path, the gestures listing and the
// index judge names with visible. It memoises each name's answer, so
// long-poll waiters sharing an fview judge each entry once (§B.11.9
// Cost); its methods are safe for concurrent use, but each call reads
// through the transaction it is given.
type fview struct {
	fs       *fscope
	cp       *fcp
	gs       string
	subjects []string
	filter   *grantcheck.ReadFilter
	// a is the reader: its grant's actor, or one standing for a cookie,
	// named and bucketed by the prefix as edgeReader's are.
	a *actor

	mu   sync.Mutex
	memo map[string]bool
}

// GS is the view's subject set (§B.11.9 gs).
func (fv *fview) GS() string { return fv.gs }

// CP is the checkpoint the view judges at.
func (fv *fview) CP() *fcp { return fv.cp }

// newFview builds subjects' view at cp; filter judges visibility.
func (t *tx) newFview(fs *fscope, cp *fcp, gs string, subjects []string, filter *grantcheck.ReadFilter, a *actor) *fview {
	// Each item the view judges has its own budget of validationSteps
	// for the rules' schema tests (§6.6 Validation work).
	filter.Steps = t.e.opt.MaxValidationSteps
	return &fview{fs: fs, cp: cp, gs: gs, subjects: subjects, filter: filter, a: a, memo: map[string]bool{}}
}

// visible reports whether name is visible to the view: the grant's
// blocks, key scope and roles, counted as §C.2 item 5 counts them, allow
// reading it (ReadFilter.AllowsItem).
func (fv *fview) visible(t *tx, name string) bool {
	fv.mu.Lock()
	v, ok := fv.memo[name]
	fv.mu.Unlock()
	if ok {
		return v
	}
	v = fv.filter.AllowsItem(name)
	fv.mu.Lock()
	fv.memo[name] = v
	fv.mu.Unlock()
	return v
}

// candidates calls fn, in ascending byte order, with every name the
// namespace has or had after after (and under prefix, if not ""), until
// fn returns false. They are a superset: callers still ask visible.
func (fv *fview) candidates(t *tx, after, prefix string, fn func(name string) bool) {
	for from := after; ; {
		names := t.namesIn(fv.fs.n, from, prefix, 256)
		for _, name := range names {
			if !fn(name) {
				return
			}
		}
		if len(names) < 256 {
			return
		}
		from = names[len(names)-1]
	}
}
