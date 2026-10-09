package client

import (
	"github.com/middle-management/patchlog/internal/ids"
	"github.com/middle-management/patchlog/internal/jsonv"
)

func parentPtr(parent string) (*ids.ID, error) {
	if parent == "" {
		return nil, nil
	}
	p, err := ids.Parse(parent)
	if err != nil {
		return nil, err
	}
	return &p, nil
}

// ExpectedRevision computes the revision id (§3.3) that appending patches
// on parent produces ("" = genesis). patches may be any JSON-marshalable
// value or raw JSON; it is canonicalised as the server stores it. Use it to
// chain several steps for one resource in a batch, or to check a write.
func ExpectedRevision(parent string, patches any) (string, error) {
	p, err := parentPtr(parent)
	if err != nil {
		return "", err
	}
	v, err := Value(patches)
	if err != nil {
		return "", err
	}
	return ids.Revision(p, jsonv.Canonical(v)).String(), nil
}

// ExpectedTombstone computes the tombstone id (§3.4) of deleting head.
func ExpectedTombstone(head string) (string, error) {
	p, err := ids.Parse(head)
	if err != nil {
		return "", err
	}
	return ids.Tombstone(p).String(), nil
}

// ExpectedConfigGenesis computes the config revision id of a namespace
// created with document doc (the genesis patch set of GenesisPatches).
func ExpectedConfigGenesis(doc any) (string, error) {
	return ExpectedRevision("", GenesisPatches(doc))
}

// FirstBranchEntry computes a local branch's first ns_id: its own log starts
// with { kind: "config", target: configGenesis }, whose prev is empty. The
// configGenesis is the target of the base's branch entry (§3.5, §7.6).
func FirstBranchEntry(configGenesis string) (string, error) {
	if _, err := ids.Parse(configGenesis); err != nil {
		return "", err
	}
	body := jsonv.Canonical(map[string]any{"kind": "config", "target": configGenesis})
	return ids.Hash(nil, body).String(), nil
}
