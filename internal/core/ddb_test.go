package core

// Engine-level tests of the DynamoDB backend (docs/DYNAMODB.md phase 1):
// the seam's delegations, the thin gate's answers, and the 501s, end to
// end through Open with a dynamodb:// URL against DynamoDB Local
// (DDB_ENDPOINT; skipped without it).

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/ddb"
	"github.com/middle-management/patchlog/internal/jsonv"
)

// ddbEngine opens an engine on a fresh table of DynamoDB Local, in -dev
// mode as phase 1 requires.
func ddbEngine(t *testing.T) *Engine {
	t.Helper()
	endpoint := os.Getenv("DDB_ENDPOINT")
	if endpoint == "" {
		t.Skip("DDB_ENDPOINT not set: skipping DynamoDB Local integration test")
	}
	url := fmt.Sprintf("dynamodb://coretest-%d?region=us-east-1&endpoint=%s", time.Now().UnixNano(), endpoint)
	if err := ddb.CreateTable(context.Background(), url); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ddb.DeleteTable(context.Background(), url) })
	e, err := Open(Options{
		Path:         url,
		AuthDisabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close() })
	return e
}

func patches(t *testing.T, s string) any {
	t.Helper()
	return jsonv.MustParse([]byte(s))
}

func ddbCreateNS(t *testing.T, e *Engine, ns, doc string) *WriteResult {
	t.Helper()
	res, err := e.WriteConfig(context.Background(), Request{NS: ns},
		ConfigChange{IfNoneMatch: true, Patches: patches(t, fmt.Sprintf(`[{"op":"add","path":"","value":%s}]`, doc))})
	if err != nil {
		t.Fatalf("create ns %s: %v", ns, err)
	}
	if res.Status != 201 || res.ConfigID == "" || res.NSID == "" {
		t.Fatalf("create ns %s: %+v", ns, res)
	}
	return res
}

func ddbWrite(t *testing.T, e *Engine, ns, name, ifMatch, patchSet string) *WriteResult {
	t.Helper()
	res, err := e.WriteResource(context.Background(), Request{NS: ns},
		Item{Resource: name, IfMatch: ifMatch, IfNoneMatch: ifMatch == "", Steps: []Step{{Patches: patches(t, patchSet)}}})
	if err != nil {
		t.Fatalf("write %s/%s: %v", ns, name, err)
	}
	return res
}

func TestDDBGateAnswers(t *testing.T) {
	e := ddbEngine(t)
	ctx := context.Background()

	// Absent namespace: 404.
	_, err := e.WriteResource(ctx, Request{NS: "gone"}, Item{Resource: "d", IfNoneMatch: true, Steps: []Step{{Patches: patches(t, `[{"op":"add","path":"","value":1}]`)}}})
	assertStatus(t, err, 404, "not_found")
	_, err = e.ResourceHead(ctx, "gone", "d", Credentials{})
	assertStatus(t, err, 404, "not_found")

	// Frozen: 409.
	fz := ddbCreateNS(t, e, "fz", `{"read":"public"}`)
	c, err := e.WriteConfig(ctx, Request{NS: "fz"}, ConfigChange{IfMatch: fz.ConfigID, Patches: patches(t, `[{"op":"add","path":"/frozen","value":true}]`)})
	if err != nil {
		t.Fatal(err)
	}
	if c.ConfigID == "" {
		t.Fatalf("config change: %+v", c)
	}
	_, err = e.WriteResource(ctx, Request{NS: "fz"}, Item{Resource: "d", IfNoneMatch: true, Steps: []Step{{Patches: patches(t, `[{"op":"add","path":"","value":1}]`)}}})
	assertStatus(t, err, 409, "frozen")
	if len(mustErr(t, err).Body) != 1 {
		t.Fatalf("frozen body %v, want only the code (no successor)", mustErr(t, err).Body)
	}

	// Namespace rules: 422, and the same rule passing a create.
	ddbCreateNS(t, e, "ruled", `{"read":"public","rules":[{"if":[{"op":"test","path":"/action","value":"append"}],"then":[{"op":"test","path":"/action","value":"create"}]}]}`)
	w := ddbWrite(t, e, "ruled", "d", "", `[{"op":"add","path":"","value":{"n":1}}]`)
	_, err = e.WriteResource(ctx, Request{NS: "ruled"}, Item{Resource: "d", IfMatch: w.Items[0].IDs[0], Steps: []Step{{Patches: patches(t, `[{"op":"add","path":"/m","value":2}]`)}}})
	assertStatus(t, err, 422, "rule")

	// Limits: 413 on the document.
	ddbCreateNS(t, e, "small", `{"read":"public","limits":{"documentSize":8}}`)
	_, err = e.WriteResource(ctx, Request{NS: "small"}, Item{Resource: "d", IfNoneMatch: true, Steps: []Step{{Patches: patches(t, `[{"op":"add","path":"","value":{"long":true}}]`)}}})
	assertStatus(t, err, 413, "limit")

	// If-Match on the configuration: 412.
	_, err = e.WriteConfig(ctx, Request{NS: "fz"}, ConfigChange{IfMatch: c.ConfigID + "x", Patches: patches(t, `[{"op":"add","path":"/x","value":1}]`)})
	assertStatus(t, err, 412, "stale")

	// A second create of the namespace: 412 (attribute_not_exists).
	_, err = e.WriteConfig(ctx, Request{NS: "fz"}, ConfigChange{IfNoneMatch: true, Patches: patches(t, `[{"op":"add","path":"","value":{}}]`)})
	assertStatus(t, err, 412, "stale")
}

func TestDDBUnsupported(t *testing.T) {
	e := ddbEngine(t)
	ctx := context.Background()
	ddbCreateNS(t, e, "demo", `{"read":"public"}`)

	check := func(what string, err error) {
		t.Helper()
		var ae *Error
		if err == nil || !strings.Contains(err.Error(), "unsupported") {
			t.Fatalf("%s: want 501 unsupported, got %v", what, err)
		}
		if ae = mustErr(t, err); ae.Status != 501 {
			t.Fatalf("%s: want 501, got %d", what, ae.Status)
		}
	}
	_, err := e.CreateBranch(ctx, Request{NS: "demo"}, BranchRequest{})
	check("branch", err)
	_, err = e.Gestures(ctx, "demo", "g1", "", Credentials{})
	check("gestures", err)
	_, _, err = e.Branches(ctx, "demo", Credentials{})
	check("branches", err)
	_, err = e.Prune(ctx, Request{NS: "demo"}, "d", PruneRequest{})
	check("prune", err)

	// Encrypted namespaces are refused at creation: Open refuses a key
	// store, so as on SQL without one, 422.
	_, err = e.WriteConfig(ctx, Request{NS: "enc"}, ConfigChange{IfNoneMatch: true, Patches: patches(t, `[{"op":"add","path":"","value":{"encryption":{"level":"sealed"}}}]`)})
	assertStatus(t, err, 422, "invalid")
}

func mustErr(t *testing.T, err error) *Error {
	t.Helper()
	ae, ok := err.(*Error)
	if !ok {
		t.Fatalf("want *Error, got %T: %v", err, err)
	}
	return ae
}

func assertStatus(t *testing.T, err error, status int, code string) {
	t.Helper()
	ae := mustErr(t, err)
	if ae.Status != status || ae.Code() != code {
		t.Fatalf("want %d %s, got %d %v", status, code, ae.Status, ae.Body)
	}
}

func TestDDBDeleteRule(t *testing.T) {
	e := ddbEngine(t)
	ctx := context.Background()
	// A rule reading the delete envelope: refuse deletes of documents
	// with a "locked" member (§6.4.1's doc on deletes).
	ddbCreateNS(t, e, "ruled", `{"read":"public","rules":[{"if":[{"op":"test","path":"/action","value":"delete"},{"op":"test","path":"/doc/locked","exists":true}],"then":[{"op":"test","path":"/action","value":"restore"}]}]}`)
	w := ddbWrite(t, e, "ruled", "doc1", "", `[{"op":"add","path":"","value":{"locked":true}}]`)
	_, err := e.WriteResource(ctx, Request{NS: "ruled"},
		Item{Resource: "doc1", IfMatch: w.Items[0].IDs[0], Steps: []Step{{Delete: true}}})
	assertStatus(t, err, 422, "rule")
}
