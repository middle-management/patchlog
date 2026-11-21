package merge_test

import (
	"net/http"
	"reflect"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/client/clienttest"
	"github.com/middle-management/patchlog/internal/grant"
)

// MRG-11 (TOOLS §F.8, v0.87): an editor limited to some documents gets,
// on a branch made for it, a grant with the rules of its base grant, here
// one testing the document (§7.9). In the branch it writes what those
// rules let it read, and nothing else; filtered reads don't cover branches
// (§7.9 Where), so nothing that lists the branch is served to it, filtered
// or not: it lists only through a preview index (§A.4, not exercised
// here).
func TestV087BranchGrantWithBaseRules(t *testing.T) {
	t.Parallel()
	s := clienttest.New(t, clienttest.Options{Auth: true})
	k := clienttest.NewKey("ops")
	must(s.Client(t, client.WithBearer(s.OperatorGrant(t, "matches"))).CreateNamespace(ctx, "matches", map[string]any{"read": "grant", "keys": []any{k.Entry("*")}}))
	both := []string{"matches", "matches-r7"}
	owner := s.Client(t, client.WithBearer(k.Grant(t, s.Now(), "user:anna", both, grant.Verbs)))
	derby := must(owner.CreateDoc(ctx, "matches", "derby", map[string]any{"team": "a", "title": "Derby"})).ID
	cup := must(owner.CreateDoc(ctx, "matches", "cup", map[string]any{"team": "b", "title": "Cup"})).ID
	// The branching service creates the branch for the editor.
	must(owner.CreateBranch(ctx, "matches", client.BranchRequest{Name: "matches-r7", Patches: ops(op("replace", "/read", "grant"))}))

	liGrant := k.Grant(t, s.Now(), "user:li", both, []string{"read", "append"}, map[string]any{"rules": []any{op("test", "/doc/team", "a")}})
	li := s.Client(t, client.WithBearer(liGrant))
	// In the branch li drafts derby (team a), which its rules let it read;
	// moving it out of team a, or writing cup (team b), its rules refuse.
	draft := must(li.Append(ctx, "matches-r7", "derby", derby, ops(op("add", "/score", "1-0")))).ID
	if _, err := li.Append(ctx, "matches-r7", "derby", draft, ops(op("replace", "/team", "b"))); err == nil {
		t.Fatal("li moved derby out of team a")
	}
	if _, err := li.Append(ctx, "matches-r7", "cup", cup, ops(op("add", "/score", "0-1"))); err == nil {
		t.Fatal("li wrote cup, which its rules don't let it read")
	}
	if _, err := li.Doc(ctx, "matches-r7", "cup", cup); err == nil {
		t.Fatal("li read cup by revision in the branch")
	}
	h, err := li.Head(ctx, "matches-r7", "cup")
	none, nerr := li.Head(ctx, "matches-r7", "nothing")
	if err == nil && nerr == nil && !reflect.DeepEqual(h, none) {
		t.Fatalf("cup's head in the branch for li: %+v (a name never used: %+v)", h, none)
	}
	// Nothing lists the branch for li: neither unrestricted nor filtered.
	at := must(owner.NSHead(ctx, "matches-r7")).ID
	for what, err := range map[string]error{
		"heads": func() error { _, err := li.Heads(ctx, "matches-r7", at); return err }(),
		"log":   func() error { _, err := li.NSLog(ctx, "matches-r7", at, ""); return err }(),
	} {
		if ae, ok := client.AsAPIError(err); !ok || ae.Status != 403 {
			t.Fatalf("the branch's %s for li: %v, want 403", what, err)
		}
	}
	for _, path := range []string{"/ns/matches-r7/view/1h3svqdgo2zzbsi4ue4judyzylpexfd6q/heads", "/ns/matches-r7/view/1h3svqdgo2zzbsi4ue4judyzylpexfd6q/log"} {
		req, _ := http.NewRequestWithContext(ctx, "GET", s.URL+path, nil)
		req.Header.Set("Authorization", "Bearer "+liGrant)
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if res.StatusCode != 403 && res.StatusCode != 404 {
			t.Fatalf("GET %s for li: %d, want a refusal", path, res.StatusCode)
		}
	}
}
