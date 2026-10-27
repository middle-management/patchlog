package ddbstore

// Branches (§7.6). A branch is a namespace whose #META names its base,
// the position in the base's log it branched at and the base's
// configuration then; it reads every resource it hasn't written through
// to the base as of that entry (core's resolve). Creating one is a commit
// to the base (Commit.Branch): its "branch" entry, chained on the base's
// tip and pinned on its configuration, and in the same transaction the
// branch itself — its #META, configuration genesis and first entry, as
// CreateNamespace writes them — and a BRANCH#<name> item in the base,
// which lists its branches (Branches). A branch's first write to a
// resource it reads through starts a chain of its own whose first
// revision names its foreign parent (parentNs, parentPos).

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/jsonv"
)

// branchActions counts a branch's actions beyond the base's commit: its
// #META, configuration, entry, tip and entry marker, the namespace list's
// item, and the base's BRANCH# item.
const branchActions = 7

func keyBranch(base, name string) Key { return Key{nsPK(base), "BRANCH#" + name} }

// branchActs are the branch c creates, created with c's entry in the base
// (entry): the branch exists exactly when the base records it.
func (s *Store) branchActs(c *Commit, entry logRow) []types.TransactWriteItem {
	b := c.Branch
	if b == nil {
		return nil
	}
	body := jsonv.Canonical(map[string]any{"kind": "config", "target": b.CfgID})
	first := logRow{pos: 1, id: ids.Hash(nil, body).String(), kind: "config", body: string(body), author: c.Author,
		created: c.Created, cfgPos: 1, grantID: c.Grant, noAuth: c.NoAuth}
	meta := &nsMeta{frozen: b.Frozen, configPos: 1, configID: b.CfgID, base: c.NS, baseAt: b.AtPos, baseCfgPos: c.CfgPos}
	out := buildCreateTx(s.Table, b.Name, meta, b.CfgID, b.Patches, b.Doc, first)
	out = append(out,
		types.TransactWriteItem{Put: &types.Put{TableName: &s.Table, Item: withKey(keyNSList(b.Name), item{})}},
		types.TransactWriteItem{Put: &types.Put{
			TableName: &s.Table, Item: withKey(keyBranch(c.NS, b.Name), item{"name": avS(b.Name), "entryPos": avN(entry.pos)}),
			ConditionExpression: strptr("attribute_not_exists(PK)"),
		}},
	)
	if c.Grant != "" {
		out = append(out, grantMark(s.Table, b.Name, c.Grant, 1))
	}
	if b.EpochKey != nil {
		out = append(out, epochKeyAct(s.Table, b.Name, b.EpochKey, c.Created))
	}
	return out
}

// Branches lists base's branches, in byte order of name.
func (s *Store) Branches(ctx context.Context, base string) ([]BranchRow, error) {
	var out []BranchRow
	err := s.eachItem(ctx, base, "BRANCH#", func(i item) error {
		out = append(out, BranchRow{Name: i.s("name"), EntryPos: i.n("entryPos")})
		return nil
	})
	return out, err
}

// Branch reads base's branch name; nil when it has none of that name.
func (s *Store) Branch(ctx context.Context, base, name string) (*BranchRow, error) {
	it, err := s.getItem(ctx, keyBranch(base, name))
	if it == nil || err != nil {
		return nil, err
	}
	return &BranchRow{Name: name, EntryPos: item(it).n("entryPos")}, nil
}
