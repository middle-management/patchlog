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

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

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
	ctx := context.Background()
	table := fmt.Sprintf("coretest-%d", time.Now().UnixNano())
	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion("us-east-1"),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider("local", "local", "")),
		config.WithResponseChecksumValidation(aws.ResponseChecksumValidationUnset))
	if err != nil {
		t.Fatal(err)
	}
	client := dynamodb.NewFromConfig(cfg, func(o *dynamodb.Options) { o.BaseEndpoint = aws.String(endpoint) })
	if _, err := client.CreateTable(ctx, &dynamodb.CreateTableInput{
		TableName: aws.String(table),
		AttributeDefinitions: []types.AttributeDefinition{
			{AttributeName: aws.String("PK"), AttributeType: types.ScalarAttributeTypeS},
			{AttributeName: aws.String("SK"), AttributeType: types.ScalarAttributeTypeS},
			{AttributeName: aws.String("G1PK"), AttributeType: types.ScalarAttributeTypeS},
		},
		KeySchema: []types.KeySchemaElement{
			{AttributeName: aws.String("PK"), KeyType: types.KeyTypeHash},
			{AttributeName: aws.String("SK"), KeyType: types.KeyTypeRange},
		},
		GlobalSecondaryIndexes: []types.GlobalSecondaryIndex{{
			IndexName:  aws.String("GSI1"),
			KeySchema:  []types.KeySchemaElement{{AttributeName: aws.String("G1PK"), KeyType: types.KeyTypeHash}},
			Projection: &types.Projection{ProjectionType: types.ProjectionTypeAll},
		}},
		BillingMode: types.BillingModePayPerRequest,
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		client.DeleteTable(context.Background(), &dynamodb.DeleteTableInput{TableName: aws.String(table)})
	})
	e, err := Open(Options{
		Path:         fmt.Sprintf("dynamodb://%s?region=us-east-1&endpoint=%s", table, endpoint),
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
		Item{Resource: name, IfMatch: ifMatch, Steps: []Step{{Patches: patches(t, patchSet)}}})
	if err != nil {
		t.Fatalf("write %s/%s: %v", ns, name, err)
	}
	return res
}

func TestDDBFlow(t *testing.T) {
	e := ddbEngine(t)
	ctx := context.Background()

	// Create, write, and the serving reads.
	created := ddbCreateNS(t, e, "demo", `{"read":"public"}`)
	w1 := ddbWrite(t, e, "demo", "doc1", "", `[{"op":"add","path":"","value":{"n":1}}]`)
	if w1.Status != 201 || len(w1.Items) != 1 || len(w1.Items[0].IDs) != 1 {
		t.Fatalf("write: %+v", w1)
	}
	if w1.Entry == nil || w1.Entry.Kind != "head" || w1.Entry.Author != "anonymous" {
		t.Fatalf("entry: %+v", w1.Entry)
	}
	rev1 := w1.Items[0].IDs[0]

	head, err := e.ResourceHead(ctx, "demo", "doc1", Credentials{})
	if err != nil || head.State != Live || head.Head != rev1 || !head.Public {
		t.Fatalf("head: %+v %v", head, err)
	}
	rev, err := e.ResourceRev(ctx, "demo", "doc1", rev1, Credentials{})
	if err != nil || rev.Status != 200 || string(rev.Doc) != `{"n":1}` || len(rev.Digest) != 32 {
		t.Fatalf("rev: %+v %v", rev, err)
	}
	// The head read and /raw.
	rev, err = e.ResourceRev(ctx, "demo", "doc1", "", Credentials{})
	if err != nil || rev.Status != 200 || string(rev.Doc) != `{"n":1}` {
		t.Fatalf("rev at head: %+v %v", rev, err)
	}
	raw, err := e.ResourceRaw(ctx, "demo", "doc1", "", Credentials{})
	if err != nil || raw.Head.State != Live || raw.Rev == nil || string(raw.Rev.Doc) != `{"n":1}` {
		t.Fatalf("raw: %+v %v", raw, err)
	}

	// Append, then the logs.
	w2 := ddbWrite(t, e, "demo", "doc1", rev1, `[{"op":"add","path":"/m","value":2}]`)
	rev2 := w2.Items[0].IDs[0]
	rl, err := e.ResourceLog(ctx, "demo", "doc1", "", "", 0, Credentials{})
	if err != nil || rl.Status != 200 || len(rl.Entries) != 2 {
		t.Fatalf("resource log: %+v %v", rl, err)
	}
	if rl.Entries[1]["id"] != rev2 || rl.Entries[1]["parent"] != rev1 || rl.Entries[1]["kind"] != "head" {
		t.Fatalf("resource log entries: %v", rl.Entries)
	}
	if g, ok := rl.Entries[1]["grant"]; !ok || g != nil {
		t.Fatalf("dev entries serve grant null: %v", rl.Entries[1])
	}
	rl, err = e.ResourceLog(ctx, "demo", "doc1", "", rev1, 0, Credentials{})
	if err != nil || len(rl.Entries) != 1 || rl.Entries[0]["id"] != rev2 {
		t.Fatalf("resource log since: %+v %v", rl, err)
	}

	nl, err := e.NamespaceLog(ctx, "demo", "", "", 0, Credentials{})
	if err != nil || nl.Status != 200 || len(nl.Entries) != 3 {
		t.Fatalf("namespace log: %+v %v", nl, err)
	}
	if nl.Entries[0]["kind"] != "config" || nl.Entries[1]["kind"] != "head" {
		t.Fatalf("namespace log entries: %v %v", nl.Entries[0], nl.Entries[1])
	}
	tip := nl.Entries[2]["id"].(string)
	nl, err = e.NamespaceLog(ctx, "demo", nl.Entries[0]["id"].(string), "", 0, Credentials{})
	if err != nil || len(nl.Entries) != 1 {
		t.Fatalf("namespace log at: %+v %v", nl, err)
	}

	// The namespace reads: head, rev, heads.
	info, err := e.NamespaceHead(ctx, "demo", Credentials{})
	if err != nil || info.Head != tip || info.Config != created.ConfigID {
		t.Fatalf("ns head: %+v %v", info, err)
	}
	info, err = e.NamespaceRev(ctx, "demo", nl.Entries[0]["id"].(string), Credentials{})
	if err != nil || info.Config != created.ConfigID || string(info.Doc) != `{"read":"public"}` {
		t.Fatalf("ns rev: %+v %v", info, err)
	}
	heads, err := e.NamespaceHeads(ctx, "demo", tip, "", Credentials{})
	if err != nil || len(heads.Items) != 1 {
		t.Fatalf("heads: %+v %v", heads, err)
	}
	item := heads.Items[0]
	if item["resource"] != "doc1" || item["target"] != rev2 || item["digest"] == "" || item["size"] != float64(len(`{"n":1,"m":2}`)) {
		t.Fatalf("heads item: %v", item)
	}

	// The preconditions: a replay and a stale write.
	replay, err := e.WriteResource(ctx, Request{NS: "demo"},
		Item{Resource: "doc1", IfMatch: rev1, Steps: []Step{{Patches: patches(t, `[{"op":"add","path":"/m","value":2}]`)}}})
	if err != nil || replay.Status != 200 || !replay.Replayed || replay.Items[0].IDs[0] != rev2 {
		t.Fatalf("replay: %+v %v", replay, err)
	}
	_, err = e.WriteResource(ctx, Request{NS: "demo"},
		Item{Resource: "doc1", IfMatch: rev1, Steps: []Step{{Patches: patches(t, `[{"op":"add","path":"/x","value":9}]`)}}})
	assertStatus(t, err, 412, "stale")

	// Gestures ride along, unhashed.
	w3, err := e.WriteResource(ctx, Request{NS: "demo"},
		Item{Resource: "doc2", Steps: []Step{{Patches: patches(t, `[{"op":"add","path":"","value":{}}]`), Gesture: "gaaaaaaaaaaaaaaaaaaaaaaaaa", Undoes: "gzzzzzzzzzzzzzzzzzzzzzzzzz"}}})
	if err != nil {
		t.Fatal(err)
	}
	_ = w3
	rl, err = e.ResourceLog(ctx, "demo", "doc2", "", "", 0, Credentials{})
	if err != nil || rl.Entries[0]["gesture"] != "gaaaaaaaaaaaaaaaaaaaaaaaaa" || rl.Entries[0]["undoes"] != "gzzzzzzzzzzzzzzzzzzzzzzzzz" {
		t.Fatalf("gestures: %+v %v", rl, err)
	}
	nl, err = e.NamespaceLog(ctx, "demo", "", "", 0, Credentials{})
	if err != nil || nl.Entries[len(nl.Entries)-1]["gesture"] != "gaaaaaaaaaaaaaaaaaaaaaaaaa" {
		t.Fatalf("ns gesture: %+v %v", nl, err)
	}
}

func TestDDBGateAnswers(t *testing.T) {
	e := ddbEngine(t)
	ctx := context.Background()

	// Absent namespace: 404.
	_, err := e.WriteResource(ctx, Request{NS: "gone"}, Item{Resource: "d", Steps: []Step{{Patches: patches(t, `[{"op":"add","path":"","value":1}]`)}}})
	assertStatus(t, err, 404, "not_found")
	_, err = e.ResourceHead(ctx, "gone", "d", Credentials{})
	assertStatus(t, err, 404, "not_found")

	// Frozen: 409.
	ddbCreateNS(t, e, "fz", `{"read":"public"}`)
	c, err := e.WriteConfig(ctx, Request{NS: "fz"}, ConfigChange{Patches: patches(t, `[{"op":"add","path":"/frozen","value":true}]`)})
	if err != nil {
		t.Fatal(err)
	}
	if c.ConfigID == "" {
		t.Fatalf("config change: %+v", c)
	}
	_, err = e.WriteResource(ctx, Request{NS: "fz"}, Item{Resource: "d", Steps: []Step{{Patches: patches(t, `[{"op":"add","path":"","value":1}]`)}}})
	assertStatus(t, err, 409, "frozen")

	// Namespace rules: 422, and the same rule passing a create.
	ddbCreateNS(t, e, "ruled", `{"read":"public","rules":[{"if":[{"op":"test","path":"/action","value":"append"}],"then":[{"op":"test","path":"/action","value":"create"}]}]}`)
	_, err = e.WriteResource(ctx, Request{NS: "ruled"}, Item{Resource: "d", Steps: []Step{{Patches: patches(t, `[{"op":"add","path":"","value":{"n":1}}]`)}}})
	if err != nil {
		t.Fatalf("create under a create-only rule: %v", err)
	}
	_, err = e.WriteResource(ctx, Request{NS: "ruled"}, Item{Resource: "d", Steps: []Step{{Patches: patches(t, `[{"op":"add","path":"/m","value":2}]`)}}})
	assertStatus(t, err, 422, "rule")

	// Limits: 413 on the document.
	ddbCreateNS(t, e, "small", `{"read":"public","limits":{"documentSize":8}}`)
	_, err = e.WriteResource(ctx, Request{NS: "small"}, Item{Resource: "d", Steps: []Step{{Patches: patches(t, `[{"op":"add","path":"","value":{"long":true}}]`)}}})
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
	_, err := e.Batch(ctx, Request{NS: "demo"}, []Item{{Resource: "d", Steps: []Step{{Patches: patches(t, `[]`)}}}}, nil, nil, false)
	check("batch", err)
	_, err = e.CreateBranch(ctx, Request{NS: "demo"}, BranchRequest{})
	check("branch", err)
	_, err = e.Gestures(ctx, "demo", "g1", "", Credentials{})
	check("gestures", err)
	_, _, err = e.Branches(ctx, "demo", Credentials{})
	check("branches", err)
	_, err = e.Prune(ctx, Request{NS: "demo"}, "d", PruneRequest{})
	check("prune", err)
	_, err = e.Purge(ctx, Request{NS: "demo"}, "d", "", false)
	check("purge", err)
	_, err = e.NamespaceEvents(ctx, "demo", "", 0, Credentials{})
	check("events", err)
	_, err = e.WriteResource(ctx, Request{NS: "demo"}, Item{Resource: "d", Steps: []Step{{Delete: true}}})
	check("delete", err)

	// Encrypted namespaces are refused at creation.
	_, err = e.WriteConfig(ctx, Request{NS: "enc"}, ConfigChange{IfNoneMatch: true, Patches: patches(t, `[{"op":"add","path":"","value":{"encryption":{"level":"sealed"}}}]`)})
	check("sealed create", err)
}

func TestDDBOpenRequiresDev(t *testing.T) {
	endpoint := os.Getenv("DDB_ENDPOINT")
	if endpoint == "" {
		t.Skip("DDB_ENDPOINT not set: skipping DynamoDB Local integration test")
	}
	_, err := Open(Options{Path: "dynamodb://whatever?region=us-east-1&endpoint=" + endpoint})
	if err == nil || !strings.Contains(err.Error(), "-dev") {
		t.Fatalf("want the -dev requirement, got %v", err)
	}
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
