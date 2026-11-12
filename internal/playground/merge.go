package playground

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/jsonv"
	"github.com/middle-management/patchlog/internal/merge"
)

// MergePrefix is where the playground's merge planner lives.
const MergePrefix = Prefix + "merge/"

// maxMergeResolutions bounds the resolutions of one plan request.
const maxMergeResolutions = 200

// The merge planner (§F.3). POST {MergePrefix}plan classifies a branch's
// changes against its base with internal/merge, as `patchlog merge plan`
// does, dry-runs the batch and answers with the plan and the batch body.
// It writes nothing: the page submits the batch itself, through the normal
// API, under the grant or author in its connection bar.
//
// Like the schema import planner it reads in process through the API
// handler with the headers of the request that asked, so a caller plans
// against what their own grant may read, and its transport lets through
// reads and a batch dry run only.

type mergePlanRequest struct {
	Branch string `json:"branch"`
	// Base is the namespace merged into (default: the branch's base).
	Base   string `json:"base"`
	Squash bool   `json:"squash"`
	// BranchAt pins the branch revision a re-plan classifies from, so the
	// resolutions a person wrote stay against the plan they saw.
	BranchAt string `json:"branchAt"`
	// Resolve maps a resource to its resolution against the base's head:
	// a patch set, a list of steps, "delete" or "keep".
	Resolve map[string]json.RawMessage `json:"resolve"`
}

// readOnlyCode is the code of the refusal the planner's transport answers a
// write with.
const readOnlyCode = "playground_read_only"

// readOnly is forward limited to requests that write nothing: GET, HEAD
// and a batch dry run (§7.5).
type readOnly struct{ forward }

func (f readOnly) RoundTrip(req *http.Request) (*http.Response, error) {
	switch {
	case req.Method == http.MethodGet || req.Method == http.MethodHead:
	case req.Method == http.MethodPost && strings.HasSuffix(req.URL.Path, "/batch") && req.URL.Query().Get("dry-run") == "1":
	default:
		if req.Body != nil {
			io.Copy(io.Discard, req.Body)
			req.Body.Close()
		}
		rec := httptest.NewRecorder()
		rec.Header().Set("Content-Type", "application/json")
		rec.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(rec).Encode(map[string]any{"code": readOnlyCode,
			"message": "the playground's planner writes nothing: " + req.Method + " " + req.URL.Path + " refused"})
		return rec.Result(), nil
	}
	return f.forward.RoundTrip(req)
}

func (s *importer) serveMerge(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case MergePrefix:
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			fail(w, http.StatusMethodNotAllowed, "bad_input", "GET only")
			return
		}
		reply(w, http.StatusOK, map[string]any{"proxy": "merge", "levels": []string{"", "at-rest"},
			"limits": map[string]any{"bytes": maxPlanBody, "resolutions": maxMergeResolutions}})
	case MergePrefix + "plan":
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST")
			fail(w, http.StatusMethodNotAllowed, "bad_input", "POST only")
			return
		}
		s.mergePlan(w, r)
	default:
		http.NotFound(w, r)
	}
}

// parseResolution reads a resolution as `patchlog merge -resolve` does: a
// patch set, a list of steps (each a patch set or "delete"), "delete", or
// "keep" (no steps: the base is kept as it is).
func parseResolution(raw json.RawMessage) ([]client.Step, error) {
	v, err := jsonv.Parse(raw)
	if err != nil {
		return nil, err
	}
	switch x := v.(type) {
	case string:
		switch x {
		case "delete":
			return []client.Step{client.DeleteStep()}, nil
		case "keep":
			return nil, nil
		}
		return nil, fmt.Errorf("unknown resolution %q", x)
	case []any:
		isSteps := len(x) > 0
		for _, e := range x {
			switch e.(type) {
			case []any, string:
			default:
				isSteps = false
			}
		}
		if !isSteps {
			return []client.Step{client.PatchStep(x)}, nil
		}
		var steps []client.Step
		for _, e := range x {
			if str, ok := e.(string); ok {
				if str != "delete" {
					return nil, fmt.Errorf("unknown step %q", str)
				}
				steps = append(steps, client.DeleteStep())
				continue
			}
			steps = append(steps, client.PatchStep(e))
		}
		return steps, nil
	}
	return nil, errors.New(`want a patch set, a list of steps, "delete" or "keep"`)
}

// mergeBatchBody is the batch the plan would submit, in the wire format of
// POST /ns/{base}/batch (§7.5), or nil when it has no items.
func mergeBatchBody(p *merge.Plan) map[string]any {
	req := p.Batch()
	if len(req.Items) == 0 {
		return nil
	}
	items := make([]any, 0, len(req.Items))
	for _, it := range req.Items {
		m := map[string]any{"resource": it.Resource, "steps": merge.StepsJSON(it.Steps)}
		if it.IfNoneMatch {
			m["ifNoneMatch"] = "*"
		} else {
			m["ifMatch"] = it.IfMatch
		}
		items = append(items, m)
	}
	return map[string]any{"items": items, "source": req.Source}
}

// upstream answers with what the API said, or a 502.
func upstream(w http.ResponseWriter, err error) {
	if ae, ok := client.AsAPIError(err); ok {
		reply(w, ae.Status, ae.Body)
		return
	}
	fail(w, http.StatusBadGateway, "upstream", err.Error())
}

func (s *importer) mergePlan(w http.ResponseWriter, r *http.Request) {
	var req mergePlanRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxPlanBody))
	if err := dec.Decode(&req); err != nil {
		fail(w, http.StatusBadRequest, "bad_input", "the body is not the expected JSON: "+err.Error())
		return
	}
	if !client.ValidNSName(req.Branch) {
		fail(w, http.StatusBadRequest, "bad_input", fmt.Sprintf("invalid branch name %q", req.Branch))
		return
	}
	if req.Base != "" && !client.ValidNSName(req.Base) {
		fail(w, http.StatusBadRequest, "bad_input", fmt.Sprintf("invalid base name %q", req.Base))
		return
	}
	if len(req.Resolve) > maxMergeResolutions {
		fail(w, http.StatusBadRequest, "bad_input", fmt.Sprintf("at most %d resolutions", maxMergeResolutions))
		return
	}
	resolve := map[string][]client.Step{}
	for name, raw := range req.Resolve {
		steps, err := parseResolution(raw)
		if err != nil {
			fail(w, http.StatusBadRequest, "bad_input", fmt.Sprintf("resolution of %s: %v", name, err))
			return
		}
		resolve[name] = steps
	}

	ctx, cancel := context.WithTimeout(r.Context(), planTimeout)
	defer cancel()
	hdr := http.Header{}
	for k, v := range r.Header {
		if !notForwarded[k] {
			hdr[k] = v
		}
	}
	c, err := client.New("http://api.invalid", client.WithHTTPClient(&http.Client{Transport: readOnly{forward{s.api, hdr}}}))
	if err != nil {
		fail(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}

	// The branch's document names its base; whoever may not read the branch
	// gets what the API would tell them.
	bh, err := c.NSHead(ctx, req.Branch)
	if err != nil {
		upstream(w, err)
		return
	}
	// What the page can't finish is refused before anything is planned.
	plain := func(ns string) bool {
		lvl, err := c.EncryptionLevel(ctx, ns)
		if err != nil {
			upstream(w, err)
			return false
		}
		if lvl == "sealed" || lvl == "e2e" {
			fail(w, http.StatusUnprocessableEntity, "merge_unsupported",
				fmt.Sprintf("%s is %s: the playground merges plain namespaces only; use `patchlog merge` with -identity, which holds the keys (§F.8)", ns, lvl))
			return false
		}
		return true
	}
	if !plain(req.Branch) {
		return
	}
	bdoc, err := c.NSDoc(ctx, req.Branch, bh.ID)
	if err != nil {
		upstream(w, err)
		return
	}
	target := req.Base
	if target == "" {
		if b, ok := bdoc.Value["base"].(map[string]any); ok {
			target, _ = b["ns"].(string)
		}
		if target == "" {
			fail(w, http.StatusUnprocessableEntity, "merge_unsupported", req.Branch+" is not a local branch: name the namespace to merge it into")
			return
		}
	}
	th, err := c.NSHead(ctx, target)
	if err != nil {
		upstream(w, err)
		return
	}
	if !plain(target) {
		return
	}
	tdoc, err := c.NSDoc(ctx, target, th.ID)
	if err != nil {
		upstream(w, err)
		return
	}
	if tdoc.Value["signatures"] == "required" {
		fail(w, http.StatusUnprocessableEntity, "merge_unsupported",
			target+" requires author signatures (§C.3.1), which the playground can't make: use `patchlog merge -sign-key`")
		return
	}

	p, err := merge.NewPlan(ctx, c, target, req.Branch, merge.Options{Squash: req.Squash, BranchAt: req.BranchAt})
	if err != nil {
		if _, ok := client.AsAPIError(err); ok {
			upstream(w, err)
			return
		}
		fail(w, http.StatusUnprocessableEntity, "merge", err.Error())
		return
	}
	for name, steps := range resolve {
		if err := p.Resolve(name, steps...); err != nil {
			fail(w, http.StatusUnprocessableEntity, "bad_resolution", err.Error())
			return
		}
	}

	out := map[string]any{
		"target": p.Target, "branch": p.Branch, "branchAt": p.BranchAt,
		"targetAt": p.TargetAt, "targetConfig": p.TargetConfig,
		"resources": p.Resources, "clean": p.Clean(), "leftOut": p.LeftOut(),
		"authorsDeclared": p.AuthorsDeclared, "mergeAuthors": p.MergeAuthors,
		"ignoredMerges": p.Ignored, "hints": p.Hints(), "squash": req.Squash,
		"branchFrozen": bdoc.Value["frozen"] == true, "branchMerged": bdoc.Value["merged"],
	}
	if out["resources"] == nil || len(p.Resources) == 0 {
		out["resources"] = []any{}
	}
	if p.Clean() {
		dry, derr := p.DryRun(ctx)
		if ae, ok := client.AsAPIError(derr); ok && ae.Code == readOnlyCode {
			// The dry run had to copy blobs first (§F.3 Blobs), a write.
			fail(w, http.StatusUnprocessableEntity, "merge_unsupported",
				"this merge has to copy the branch's blobs into "+target+" first, since you lack unrestricted read on "+req.Branch+
					" (§F.3, §7.8), and the playground's planner writes nothing: use `patchlog merge`")
			return
		}
		if dry != nil {
			items := make([]any, 0, len(dry.Items))
			for _, it := range dry.Items {
				items = append(items, it.Raw)
			}
			out["dryRun"] = items
		}
		if derr != nil {
			de := map[string]any{"message": derr.Error()}
			if ae, ok := client.AsAPIError(derr); ok {
				de["status"], de["code"], de["items"] = ae.Status, ae.Code, ae.Items()
			}
			out["dryRunError"] = de
		}
	}
	// After the dry run, so the batch is the one it judged. A plan that
	// still needs a person has none to submit.
	out["batch"] = nil
	if p.Clean() {
		out["batch"] = mergeBatchBody(p)
	}
	for _, k := range []string{"leftOut", "mergeAuthors", "ignoredMerges", "hints"} {
		if b, _ := json.Marshal(out[k]); string(b) == "null" {
			out[k] = []any{}
		}
	}
	reply(w, http.StatusOK, out)
}
