package janitor_test

import (
	"strings"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/janitor"
)

// §F.6 (v0.34): abandoned is a claim the janitor verifies: "abandoned":
// true set by a config write whose recorded grant chains to a * key of the
// branch, inherited or its own. Then the branch is purged after its
// cleanup period, unmerged work and all.
func TestAbandonedClaim(t *testing.T) {
	s := clienttest.New(t, clienttest.Options{Auth: true})
	ops, editor := clienttest.NewKey("ops"), clienttest.NewKey("editor")
	nss := []string{"matches", "matches-r1", "matches-r2"}
	all := []string{"read", "create", "append", "config", "branch", "purge-ns"}
	long := map[string]any{"exp": s.Now().Add(24 * time.Hour).Format(time.RFC3339)}
	admin := s.Client(t, client.WithBearer(ops.Grant(t, s.Now(), "user:ops", nss, all, long)))
	ed := s.Client(t, client.WithBearer(editor.Grant(t, s.Now(), "user:ed", nss, all, long)))
	op := s.Client(t, client.WithBearer(s.OperatorGrant(t, "matches")))
	must(op.CreateNamespace(ctx, "matches", map[string]any{"read": "grant", "keys": []any{ops.Entry("*"), editor.Entry(all...)},
		"cleanup": map[string]any{"abandoned": "P1D"}}))
	must(admin.CreateDoc(ctx, "matches", "derby", map[string]any{"score": "0-0"}))
	for _, b := range []string{"matches-r1", "matches-r2"} {
		must(ed.CreateBranch(ctx, "matches", client.BranchRequest{Name: b}))
		h := must(ed.Head(ctx, b, "derby"))
		must(ed.Append(ctx, b, "derby", h.ID, []any{op1("replace", "/score", "1-0")}))
	}
	abandon := func(c *client.Client, ns string) {
		t.Helper()
		h := must(c.NSHead(ctx, ns))
		must(c.PatchConfig(ctx, ns, h.Config, []any{op1("add", "/frozen", true), op1("add", "/abandoned", true)}))
	}
	abandon(ed, "matches-r1")    // an editor without a * key
	abandon(admin, "matches-r2") // the base's * key, inherited

	later := func() time.Time { return s.Now().Add(48 * time.Hour) }
	j := janitor.New(admin, janitor.Options{Bases: []string{"matches"}, Now: later})
	d := must(j.Check(ctx, "matches", "matches-r1"))
	if d.Action != janitor.ActionKeep || d.Claim != "" || !strings.Contains(d.Reason, "abandoned claim not verified") {
		t.Fatalf("abandoned by an editor: %+v", d)
	}
	// Not before the cleanup period.
	d = must(janitor.New(admin, janitor.Options{Now: s.Now}).Check(ctx, "matches", "matches-r2"))
	if d.Action != janitor.ActionKeep || d.Claim != "abandoned" || !strings.Contains(d.Reason, "cleanup period") {
		t.Fatalf("abandoned, within the period: %+v", d)
	}
	d = must(j.Check(ctx, "matches", "matches-r2"))
	if d.Action != janitor.ActionPurged || d.Claim != "abandoned" {
		t.Fatalf("abandoned by an administrator: %+v", d)
	}
}

func op1(o, path string, v any) map[string]any {
	return map[string]any{"op": o, "path": path, "value": v}
}

// §1, §F.6: with authentication disabled no entry records a grant, and a
// janitor without one takes an abandoned claim as the development server's
// operator's.
func TestAbandonedClaimDev(t *testing.T) {
	e := newEnv(t, map[string]any{"read": "public", "cleanup": map[string]any{"abandoned": "P1D"}})
	e.branch("matches", "r1", nil)
	e.edit("r1", "derby", "1-0")
	e.config("r1", op1("add", "/frozen", true), op1("add", "/abandoned", true))
	e.s.Clock.Advance(48 * time.Hour)
	d := e.sweep(false)["r1"]
	if d.Action != janitor.ActionPurged || d.Claim != "abandoned" {
		t.Fatalf("abandoned in development mode: %+v", d)
	}
}
