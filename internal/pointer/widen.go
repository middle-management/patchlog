package pointer

// WidenArray applies the array rule of merges and undo (§F.3 Conflicts
// inside arrays, §11.2 The inverse and The guard) to w, a write of one op
// that turned pre into post: a write whose last segment indexes an array
// counts as one to the whole outermost array holding it, the shortest
// proper prefix of w whose value is an array. The write's parent is judged
// in the document before the op (a removed element, or an append with "-")
// and, failing that, after it (an added element). /a/0/b/1, with a and
// a[0].b arrays, is a write to /a. A write whose last segment is an object
// member inside an element (/a/0/k), even one named "-", is not widened.
func WidenArray(pre, post any, w Pointer) Pointer {
	if a := widenIn(pre, w); len(a) < len(w) {
		return a
	}
	return widenIn(post, w)
}

// widenIn widens w where its parent is an array in doc, to the outermost
// array of doc holding it; it returns a copy of w otherwise.
func widenIn(doc any, w Pointer) Pointer {
	if len(w) == 0 {
		return w
	}
	parent := w[:len(w)-1]
	if !isArray(doc, parent) {
		return append(Pointer{}, w...)
	}
	for i := range len(parent) {
		if isArray(doc, w[:i]) {
			return append(Pointer{}, w[:i]...)
		}
	}
	// The parent itself: the outermost array.
	return append(Pointer{}, parent...)
}

// isArray reports whether p's value in doc is an array.
func isArray(doc any, p Pointer) bool {
	v, ok := Get(doc, p)
	_, arr := v.([]any)
	return ok && arr
}
