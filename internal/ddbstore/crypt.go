package ddbstore

// Encryption at rest (Addendum E.1). The store holds no keys: core
// encrypts what it writes (Commit.Seal, its own puts) and opens what the
// store folds (Store.Open). What it stores are the wrapped data keys:
// DEK#<name> per resource of a namespace, created put-if-absent before
// the commit that first needs one (a racing writer's wins, and an
// orphan whose commit failed is harmless), and the deployment's grants
// key, #DEPLOY DEK. A purge deletes them (cryptographic purge, §8.3).

import (
	"context"
	"errors"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/middle-management/patchlog/internal/ddb"
)

// keyDEK is name's data key in ns, or the deployment's grants key for ns
// "".
func keyDEK(ns, name string) Key {
	if ns == "" {
		return Key{"#DEPLOY", "DEK"}
	}
	return Key{nsPK(ns), "DEK#" + name}
}

// DEK reads name's data key in ns (ns "": the grants key); nil when none.
func (s *Store) DEK(ctx context.Context, ns, name string) (*ddb.WrappedDEK, error) {
	it, err := s.getItem(ctx, keyDEK(ns, name))
	if it == nil || err != nil {
		return nil, err
	}
	return &ddb.WrappedDEK{Wrapped: item(it).b("wrapped"), KeyStore: item(it).s("keystore")}, nil
}

// PutDEK stores a data key unless one exists, and returns the one stored.
func (s *Store) PutDEK(ctx context.Context, ns, name string, k ddb.WrappedDEK, now int64) (*ddb.WrappedDEK, error) {
	_, err := s.Client.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: &s.Table, Item: withKey(keyDEK(ns, name), item{"wrapped": avB(k.Wrapped), "keystore": avS(k.KeyStore), "created": avI(now)}),
		ConditionExpression: strptr("attribute_not_exists(PK)"),
	})
	var cf *types.ConditionalCheckFailedException
	if errors.As(err, &cf) {
		return s.DEK(ctx, ns, name)
	}
	if err != nil {
		return nil, err
	}
	return &k, nil
}

// DeleteDEKs destroys name's data key in ns, or every one of ns's for
// name "".
func (s *Store) DeleteDEKs(ctx context.Context, ns, name string) error {
	if name != "" {
		return s.deleteKey(ctx, keyDEK(ns, name))
	}
	return s.eachItem(ctx, ns, "DEK#", func(i item) error {
		return s.deleteKey(ctx, Key{i.s("PK"), i.s("SK")})
	})
}

// AnyDEK is one stored data key, the grants key if there is one, for
// checking at start-up that the key store unwraps them; nil for none.
func (s *Store) AnyDEK(ctx context.Context) (ns, name string, k *ddb.WrappedDEK, err error) {
	if k, err = s.DEK(ctx, "", ""); k != nil || err != nil {
		return "", "", k, err
	}
	in := &dynamodb.ScanInput{
		TableName:                 &s.Table,
		FilterExpression:          strptr("begins_with(SK, :p)"),
		ExpressionAttributeValues: map[string]types.AttributeValue{":p": avS("DEK#")},
	}
	for {
		out, err := s.Client.Scan(ctx, in)
		if err != nil {
			return "", "", nil, err
		}
		for _, raw := range out.Items {
			i := item(raw)
			return i.s("PK")[len("NS#"):], i.s("SK")[len("DEK#"):], &ddb.WrappedDEK{Wrapped: i.b("wrapped"), KeyStore: i.s("keystore")}, nil
		}
		if len(out.LastEvaluatedKey) == 0 {
			return "", "", nil, nil
		}
		in.ExclusiveStartKey = out.LastEvaluatedKey
	}
}

func keyEncrypting(ns string) Key { return Key{nsPK(ns), "#ENCRYPTING"} }

// Encrypting lists the namespaces whose content is still to be encrypted
// (Commit.Encrypting) — a scan, for the sweep.
func (s *Store) Encrypting(ctx context.Context) ([]string, error) {
	in := &dynamodb.ScanInput{
		TableName:                 &s.Table,
		FilterExpression:          strptr("SK = :e"),
		ExpressionAttributeValues: map[string]types.AttributeValue{":e": avS("#ENCRYPTING")},
		ConsistentRead:            boolptr(true),
	}
	var out []string
	for {
		q, err := s.Client.Scan(ctx, in)
		if err != nil {
			return nil, err
		}
		for _, it := range q.Items {
			out = append(out, item(it).s("ns"))
		}
		if len(q.LastEvaluatedKey) == 0 {
			return out, nil
		}
		in.ExclusiveStartKey = q.LastEvaluatedKey
	}
}

// DoneEncrypting deletes ns's marker.
func (s *Store) DoneEncrypting(ctx context.Context, ns string) error {
	return s.deleteKey(ctx, keyEncrypting(ns))
}

// EncryptContent encrypts what of ns is still plaintext: every revision's
// patch set, head document and snapshot (seal: of name, a kind and its
// key, the plaintext), and moves the bytes of every attachment and
// pending entry under its resource's key (reown: the hash and owner that
// now name them). Each value is replaced only if it is still the one
// read, so a write since keeps its own. It returns the grants the
// namespace's entries and revisions were written under, for the caller
// to encrypt.
func (s *Store) EncryptContent(ctx context.Context, ns string, seal func(name, kind, key, plain string) (string, error),
	reown func(*ddb.BlobRow) ([]byte, string, error)) (grants []string, err error) {
	seen := map[string]bool{}
	grant := func(i item) {
		if g := i.s("grantId"); g != "" && !seen[g] {
			seen[g] = true
			grants = append(grants, g)
		}
	}
	in := &dynamodb.QueryInput{
		TableName:                 &s.Table,
		KeyConditionExpression:    strptr("PK = :pk"),
		ExpressionAttributeValues: map[string]types.AttributeValue{":pk": avS(nsPK(ns))},
		ConsistentRead:            boolptr(true),
	}
	replace := func(i item, attr, kind, name, key string) error {
		old := i.s(attr)
		if old == "" || strings.HasPrefix(old, ddb.Sealed) {
			return nil
		}
		v, err := seal(name, kind, key, old)
		if err != nil {
			return err
		}
		_, err = s.Client.UpdateItem(ctx, &dynamodb.UpdateItemInput{
			TableName: &s.Table, Key: keyAV(Key{i.s("PK"), i.s("SK")}),
			UpdateExpression:          strptr("SET #a = :n"),
			ConditionExpression:       strptr("#a = :o"),
			ExpressionAttributeNames:  map[string]string{"#a": attr},
			ExpressionAttributeValues: map[string]types.AttributeValue{":n": avS(v), ":o": avS(old)},
		})
		var cf *types.ConditionalCheckFailedException
		if errors.As(err, &cf) {
			return nil // written since
		}
		return err
	}
	for {
		q, err := s.Client.Query(ctx, in)
		if err != nil {
			return nil, err
		}
		for _, raw := range q.Items {
			i := item(raw)
			sk := i.s("SK")
			switch {
			case strings.HasPrefix(sk, "LOG#"):
				grant(i)
			case strings.HasPrefix(sk, "REV#"):
				grant(i)
				err = replace(i, "patches", "rev", resNameFromRev(sk), i.s("id"))
			case strings.HasPrefix(sk, "DOC#") && strings.HasSuffix(sk, "#HEAD"):
				name := strings.TrimSuffix(strings.TrimPrefix(sk, "DOC#"), "#HEAD")
				err = replace(i, "doc", "head", name, strconv.FormatUint(i.n("revPos"), 10))
			case strings.HasPrefix(sk, "SNAP#"):
				name := strings.TrimPrefix(resNameFromRev(sk), "SNAP#")
				err = replace(i, "doc", "snap", name, strconv.FormatUint(i.n("pos"), 10))
			case strings.HasPrefix(sk, "BLOB#") || strings.HasPrefix(sk, "PEND#"):
				b := scanBlob(i)
				if b.Owner != "" || b.Pruned {
					continue
				}
				var hash []byte
				var owner string
				if hash, owner, err = reown(b); err != nil {
					return nil, err
				}
				_, err = s.Client.UpdateItem(ctx, &dynamodb.UpdateItemInput{
					TableName: &s.Table, Key: keyAV(Key{i.s("PK"), sk}),
					UpdateExpression:          strptr("SET #h = :h, #o = :o"),
					ConditionExpression:       strptr("#h = :old AND attribute_not_exists(#o)"),
					ExpressionAttributeNames:  map[string]string{"#h": "hash", "#o": "owner"},
					ExpressionAttributeValues: map[string]types.AttributeValue{":h": avB(hash), ":o": avS(owner), ":old": avB(b.Hash)},
				})
				var cf *types.ConditionalCheckFailedException
				if errors.As(err, &cf) {
					err = nil
				}
			}
			if err != nil {
				return nil, err
			}
		}
		if len(q.LastEvaluatedKey) == 0 {
			return grants, nil
		}
		in.ExclusiveStartKey = q.LastEvaluatedKey
	}
}
