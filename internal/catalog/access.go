package catalog

import (
	"sort"

	"github.com/middle-management/patchlog/internal/tree"
)

// AccessDelta is one (node, subject, role) whose presence a change alters.
type AccessDelta struct {
	Node    string `json:"node"`
	Subject string `json:"subject"`
	Role    string `json:"role"`
}

// AccessDiff is how a change alters effective roles (§B.11.2), judged by
// the test of §B.11.4: a role counts as present if it, or a role that
// includes it (in the node's item's content namespace, or for a folder in
// every trusted content namespace), is present.
type AccessDiff struct {
	// Widens lists roles present after that weren't before.
	Widens []AccessDelta `json:"widens,omitempty"`
	// Narrows lists roles present before that aren't after.
	Narrows []AccessDelta `json:"narrows,omitempty"`
}

// Kind summarises the diff: "narrows", "widens", "both" or "none".
func (d AccessDiff) Kind() string {
	switch {
	case len(d.Widens) > 0 && len(d.Narrows) > 0:
		return "both"
	case len(d.Widens) > 0:
		return "widens"
	case len(d.Narrows) > 0:
		return "narrows"
	}
	return "none"
}

// DiffAccess compares every node's effective roles per subject in before
// and after (§B.11.4: for every subject, the effective roles on every node
// afterwards against those before). A node only in after widens by all its
// roles, a node only in before narrows by all of them. incs are the
// declared role inclusions of the trusted content namespaces
// (ParseIncludes), keyed by namespace.
func DiffAccess(before, after *tree.Graph, incs map[string]Includes) AccessDiff {
	var d AccessDiff
	names := map[string]bool{}
	for _, n := range before.Names() {
		names[n] = true
	}
	for _, n := range after.Names() {
		names[n] = true
	}
	sorted := make([]string, 0, len(names))
	for n := range names {
		sorted = append(sorted, n)
	}
	sort.Strings(sorted)
	for _, name := range sorted {
		b := Effective(before, name, nil)
		a := Effective(after, name, nil)
		g := after
		if after.Node(name) == nil {
			g = before
		}
		for _, subj := range subjectsOf(a, b) {
			for _, r := range a[subj] {
				if !present(g, name, r, b[subj], incs) {
					d.Widens = append(d.Widens, AccessDelta{Node: name, Subject: subj, Role: r})
				}
			}
			for _, r := range b[subj] {
				if !present(g, name, r, a[subj], incs) {
					d.Narrows = append(d.Narrows, AccessDelta{Node: name, Subject: subj, Role: r})
				}
			}
		}
	}
	return d
}

func subjectsOf(ms ...map[string][]string) []string {
	seen := map[string]bool{}
	var out []string
	for _, m := range ms {
		for s := range m {
			if !seen[s] {
				seen[s] = true
				out = append(out, s)
			}
		}
	}
	sort.Strings(out)
	return out
}

// Powers returns the catalog roles that carry a tree power (move or
// place) in a catalog namespace document's roles (§B.11.1).
func Powers(config map[string]any) map[string]bool {
	out := map[string]bool{}
	roles, _ := config["roles"].(map[string]any)
	for r, def := range roles {
		d, _ := def.(map[string]any)
		if d["move"] == true || d["place"] == true {
			out[r] = true
		}
	}
	return out
}

// StripPowers returns a copy of a folder document whose $access no longer
// assigns roles with tree powers: how a release creates a folder in its
// narrowing step, so that the widening step adds those roles (§F.9). The
// second result reports whether anything was removed.
func StripPowers(doc map[string]any, powers map[string]bool) (map[string]any, bool) {
	acc, ok := doc["$access"].(map[string]any)
	if !ok {
		return doc, false
	}
	out := map[string]any{}
	for k, v := range doc {
		out[k] = v
	}
	nacc := map[string]any{}
	stripped := false
	for subj, v := range acc {
		arr, isArr := v.([]any)
		if !isArr {
			nacc[subj] = v // inherit, or something the schema decides on
			continue
		}
		keep := []any{}
		for _, r := range arr {
			if s, _ := r.(string); powers[s] {
				stripped = true
				continue
			}
			keep = append(keep, r)
		}
		if len(keep) > 0 {
			nacc[subj] = keep
		} else if len(arr) > 0 {
			stripped = true
		}
	}
	out["$access"] = nacc
	return out, stripped
}
