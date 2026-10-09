package merge_test

import (
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/merge"
	"github.com/middle-management/patchlog/internal/seal"
)

// §C.7, §F.3: in a target that requires nonces, the step that keeps a
// resource at the base's version only adds a fresh $nonce, and resolution
// and squash sets get one too.
func TestRequiredNoncesMerge(t *testing.T) {
	t.Parallel()
	s := clienttest.New(t, clienttest.Options{})
	c := s.Client(t, client.WithAuthor("alice"))
	e := &env{t: t, s: s, c: c}
	must(c.CreateNamespace(ctx, "matches", map[string]any{"read": "public", "nonce": "required", "merge": devAuthors}))
	nonced := func(ps ...map[string]any) []any {
		return append(ops(ps...), op("add", "/$nonce", seal.NewNonce()))
	}
	for _, n := range []string{"derby", "cup", "semi"} {
		must(c.Create(ctx, "matches", n, nonced(op("add", "", map[string]any{"score": "0-0"}))))
	}
	e.branch("matches", "r7")
	for _, n := range []string{"derby", "cup"} {
		must(c.Append(ctx, "r7", n, e.head("r7", n).ID, nonced(op("replace", "/score", "1-0"))))
		must(c.Append(ctx, "matches", n, e.head("matches", n).ID, nonced(op("replace", "/score", "0-1"))))
	}
	must(c.Append(ctx, "r7", "semi", e.head("r7", "semi").ID, nonced(op("replace", "/score", "1-0"))))
	must(c.Append(ctx, "r7", "semi", e.head("r7", "semi").ID, nonced(op("add", "/x", true))))

	p := e.plan("matches", "r7", merge.Options{Squash: true})
	if !p.TargetNonce {
		t.Fatal("TargetNonce not set")
	}
	lastNonce := func(st client.Step) bool {
		ps, _ := st.Patches.([]any)
		o, _ := ps[len(ps)-1].(map[string]any)
		v, _ := o["value"].(string)
		return o["op"] == "add" && o["path"] == "/$nonce" && seal.ValidNonce(v)
	}
	// Kept at the base: a lone fresh nonce.
	noErr(t, p.Resolve("derby"))
	d := p.Resource("derby")
	if ps, _ := d.Steps[0].Patches.([]any); !d.Kept || len(ps) != 1 || !lastNonce(d.Steps[0]) {
		t.Fatalf("keep step %+v", d.Steps)
	}
	// A resolution set.
	noErr(t, p.Resolve("cup", client.PatchStep(ops(op("replace", "/score", "1-1")))))
	if cs := p.Resource("cup").Steps; len(cs) != 1 || !lastNonce(cs[0]) {
		t.Fatalf("resolution %+v", cs)
	}
	// A squash set, its nonce fresh rather than the branch's.
	sm := p.Resource("semi")
	if !sm.Squashed || len(sm.Steps) != 1 || !lastNonce(sm.Steps[0]) {
		t.Fatalf("squash %+v", sm)
	}
	if ps := sm.Steps[0].Patches.([]any); len(ps) != 3 {
		t.Fatalf("squash set %v", ps)
	}
	before := e.head("matches", "derby").ID
	must(p.Apply(ctx))
	if e.head("matches", "derby").ID == before {
		t.Fatal("keep not recorded")
	}
	for n, want := range map[string]string{"derby": "0-1", "cup": "1-1", "semi": "1-0"} {
		if doc := e.doc("matches", n).(map[string]any); doc["score"] != want {
			t.Fatalf("%s: %v", n, doc)
		}
	}
}

// §C.7, §F.9: a release into a catalog target that requires nonces splits
// a node into two halves; step 2 writes the narrow half with a fresh
// $nonce, and step 4 still finds it there and matches its planned digest.
func TestRequiredNoncesReleaseSplit(t *testing.T) {
	t.Parallel()
	w := newRelWorld(t)
	w.startCatalog()
	h := must(w.ops.NSHead(ctx, "cat-season"))
	must(w.ops.PatchConfig(ctx, "cat-season", h.Config, ops(op("add", "/nonce", "required"))))
	w.branch("cat-season", "cat-season-r7")
	bn := seal.NewNonce()
	w.appendTo("cat-season-r7", "matches.cup", op("replace", "/parents", parentsOf("embargo")), op("add", "/$nonce", bn))
	w.writeRelease("release-9", map[string]string{"cat-season": "cat-season-r7"})
	o := w.opts("release-9")
	o.Splits = map[string]map[string]any{"cat-season": {"matches.cup": map[string]any{"parents": parentsOf("vault")}}}
	rp := must(merge.PlanRelease(ctx, w.anna, o))
	if got := stepsOf(rp); !rp.Clean() || len(got) != 2 {
		t.Fatalf("plan %q, conflicts %+v", got, rp.Conflicts)
	}
	noErr(t, merge.SaveReleasePlan(ctx, w.anna, o, rp))
	must(merge.ApproveRelease(ctx, w.anna, o))
	must(merge.ApplyRelease(ctx, w.anna, o))
	d := w.doc("cat-season", "matches.cup")
	if got := parentNames(d); len(got) != 1 || got[0] != "embargo" {
		t.Fatalf("matches.cup in %v", got)
	}
	if n, _ := d["$nonce"].(string); !seal.ValidNonce(n) || n == bn {
		t.Fatalf("matches.cup nonce %q", n)
	}
}

// §C.7, §F.9: in a state namespace that requires nonces, the release
// tool's own documents get a fresh $nonce in every revision: the stored
// plan (created, restored with a root replace after a delete, appended to
// at every step) and the catalog base's lock (taken and released).
func TestRequiredNoncesReleaseState(t *testing.T) {
	t.Parallel()
	w := newRelWorld(t)
	w.startCatalog()
	h := must(w.ops.NSHead(ctx, "releases"))
	must(w.ops.PatchConfig(ctx, "releases", h.Config, ops(op("add", "/nonce", "required"))))
	w.branch("cat-season", "cat-season-r8")
	w.appendTo("cat-season-r8", "season", op("replace", "/title", "Season 2026"))
	w.writeRelease("release-8", map[string]string{"cat-season": "cat-season-r8"})
	o := w.opts("release-8")
	plan, lock := merge.PlanName("release-8"), merge.LockName("cat-season")
	// nonces returns the $nonce of every revision of a state document,
	// oldest first, each fresh and differing from its parent's.
	nonces := func(name string) []string {
		t.Helper()
		h := must(w.anna.Head(ctx, "releases", name))
		var out []string
		for _, e := range must(w.anna.Log(ctx, "releases", name, h.ID, "")) {
			if e.Kind != "rev" {
				continue
			}
			d := must(w.anna.Doc(ctx, "releases", name, e.ID))
			n, _ := d.Value.(map[string]any)["$nonce"].(string)
			if !seal.ValidNonce(n) || (len(out) > 0 && n == out[len(out)-1]) {
				t.Fatalf("%s rev %s: $nonce %q after %v", name, e.ID, n, out)
			}
			out = append(out, n)
		}
		return out
	}

	noErr(t, merge.SaveReleasePlan(ctx, w.anna, o, must(merge.PlanRelease(ctx, w.anna, o))))
	h2 := must(w.anna.Head(ctx, "releases", plan))
	must(w.anna.Delete(ctx, "releases", plan, h2.ID))
	noErr(t, merge.SaveReleasePlan(ctx, w.anna, o, must(merge.PlanRelease(ctx, w.anna, o))))
	if ns := nonces(plan); len(ns) != 2 {
		t.Fatalf("plan revisions %v", ns)
	}
	must(merge.ApproveRelease(ctx, w.anna, o))
	rp := must(merge.ApplyRelease(ctx, w.anna, o))
	if rp.State != merge.ReleaseDone {
		t.Fatalf("release %s", rp.State)
	}
	if ns := nonces(plan); len(ns) < 5 {
		t.Fatalf("plan revisions %v", ns)
	}
	if ns := nonces(lock); len(ns) != 2 {
		t.Fatalf("lock revisions %v", ns)
	}
	if holder := must(merge.LockHolder(ctx, w.anna, o, "cat-season")); holder != "" {
		t.Fatalf("lock held by %s", holder)
	}
	if got := w.doc("cat-season", "season")["title"]; got != "Season 2026" {
		t.Fatalf("season title %v", got)
	}
}

// §C.7, §F.9: a merge service whose grant can't read the state namespace's
// document (its rules refer to /resource, §C.5) doesn't know the setting,
// so in a private namespace the stored plan gets a fresh $nonce when
// created, and at every save: one that requires them takes it, and so
// does one that doesn't.
func TestUnreadableNoncesReleaseState(t *testing.T) {
	t.Parallel()
	s := clienttest.New(t, clienttest.Options{Auth: true})
	k := clienttest.NewKey("k")
	plan := merge.PlanName("release-9")
	for _, setting := range []string{"required", "optional"} {
		t.Run(setting, func(t *testing.T) {
			t.Parallel()
			ns := "state-" + setting
			must(s.Client(t, client.WithBearer(s.OperatorGrant(t, ns))).CreateNamespace(ctx, ns,
				map[string]any{"read": "grant", "nonce": setting, "keys": []any{k.Entry("*")}}))
			svc := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "svc:merge", []string{ns}, []string{"read", "create", "append"},
				map[string]any{"rules": []any{map[string]any{"op": "test", "path": "/resource", "value": plan}}})))
			if _, err := svc.NonceRequired(ctx, ns); err == nil {
				t.Fatal("the merge service reads the namespace document")
			}
			o := merge.ReleaseOptions{Release: "/r/releases/release-9", StateNS: ns}
			noErr(t, merge.SaveReleasePlan(ctx, svc, o, &merge.ReleasePlan{Release: o.Release, Name: "release-9", State: merge.ReleasePlanned}))
			rp := must(merge.LoadReleasePlan(ctx, svc, o))
			rp.Notes = []string{"saved again"}
			noErr(t, merge.SaveReleasePlan(ctx, svc, o, rp))
			h := must(svc.Head(ctx, ns, plan))
			log := must(svc.Log(ctx, ns, plan, h.ID, ""))
			if len(log) != 2 {
				t.Fatalf("plan log %+v", log)
			}
			for _, e := range log {
				d := must(svc.Doc(ctx, ns, plan, e.ID))
				if n, _ := d.Value.(map[string]any)["$nonce"].(string); !seal.ValidNonce(n) {
					t.Fatalf("rev %s: $nonce %q", e.ID, n)
				}
			}
		})
	}
}
