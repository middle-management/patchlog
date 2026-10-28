package ddbstore

// Schema references (§6.1): which resources of a namespace pin a schema
// revision — the revisions.schema_ref the SQL schema indexes — and the
// namespaces there are, for schemaReads' prefixes.
//
//   - REV items carry schemaRef, the path their document was typed by.
//   - SREF#<ref>#<name> marks that a revision of name was typed by ref:
//     written before the commit, outside its transaction (a batch of
//     typed items would otherwise outgrow its 100 actions), so a marker
//     may name a revision that never committed. Readers confirm with the
//     resource's last live revision's schemaRef, as SQL's refersIn does.
//   - #NAMESPACES holds one item per namespace, written by its creation.

import (
	"context"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/middle-management/patchlog/internal/ddb"
)

func keySchemaRef(ns, ref, name string) Key { return Key{nsPK(ns), "SREF#" + ref + "#" + name} }

func keyNSList(ns string) Key { return Key{"#NAMESPACES", ns} }

// PutSchemaRefs marks ns's pins (idempotent).
func (s *Store) PutSchemaRefs(ctx context.Context, ns string, pins []ddb.SchemaPin) error {
	for _, p := range pins {
		_, err := s.Client.PutItem(ctx, &dynamodb.PutItemInput{
			TableName: &s.Table,
			Item:      withKey(keySchemaRef(ns, p.Ref, p.Name), item{"ref": avS(p.Ref), "name": avS(p.Name)}),
		})
		if err != nil {
			return err
		}
	}
	return nil
}

// SchemaRefs lists ns's pins; with ref, only that schema's.
func (s *Store) SchemaRefs(ctx context.Context, ns, ref string) ([]ddb.SchemaPin, error) {
	prefix := "SREF#"
	if ref != "" {
		prefix += ref + "#"
	}
	var out []ddb.SchemaPin
	in := &dynamodb.QueryInput{
		TableName:                 &s.Table,
		KeyConditionExpression:    strptr("PK = :pk AND begins_with(SK, :p)"),
		ExpressionAttributeValues: map[string]types.AttributeValue{":pk": avS(nsPK(ns)), ":p": avS(prefix)},
		ConsistentRead:            boolptr(true),
	}
	for {
		q, err := s.Client.Query(ctx, in)
		if err != nil {
			return nil, err
		}
		for _, it := range q.Items {
			i := item(it)
			if ref == "" || i.s("ref") == ref {
				out = append(out, ddb.SchemaPin{Ref: i.s("ref"), Name: i.s("name")})
			}
		}
		if len(q.LastEvaluatedKey) == 0 {
			return out, nil
		}
		in.ExclusiveStartKey = q.LastEvaluatedKey
	}
}

// Namespaces lists every namespace's name.
func (s *Store) Namespaces(ctx context.Context) ([]string, error) {
	var out []string
	in := &dynamodb.QueryInput{
		TableName:                 &s.Table,
		KeyConditionExpression:    strptr("PK = :pk"),
		ExpressionAttributeValues: map[string]types.AttributeValue{":pk": avS("#NAMESPACES")},
		ConsistentRead:            boolptr(true),
	}
	for {
		q, err := s.Client.Query(ctx, in)
		if err != nil {
			return nil, err
		}
		for _, it := range q.Items {
			out = append(out, item(it).s("SK"))
		}
		if len(q.LastEvaluatedKey) == 0 {
			return out, nil
		}
		in.ExclusiveStartKey = q.LastEvaluatedKey
	}
}

// RevsByID lists the revisions with id named name, in every namespace
// (GSI1; the copies of §6.1).
func (s *Store) RevsByID(ctx context.Context, id, name string) ([]ddb.RevCopy, error) {
	var out []ddb.RevCopy
	err := s.eachG1(ctx, g1Keys(id, s.legacyG1), "", nil, func(i item) bool {
		if strings.HasPrefix(i.s("SK"), "REV#") && resNameFromRev(i.s("SK")) == name {
			out = append(out, ddb.RevCopy{NS: nsOfPK(i.s("PK")), RevInfo: scanRevInfo(i)})
		}
		return true
	})
	return out, err
}
