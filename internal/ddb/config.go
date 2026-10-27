package ddb

import (
	"context"

	"github.com/middle-management/patchlog/internal/jsonv"
)

// Configurations (the chain of ns_config, D.2): genesis is CreateNamespace;
// a config change is a Commit (commit.go).

// readConfigState reads the namespace's meta and current configuration
// document (two point reads).
func (s *Store) readConfigState(ctx context.Context, ns string) (*nsMeta, any, error) {
	m, err := s.getMeta(ctx, ns)
	if err != nil || m == nil {
		return m, nil, err
	}
	it, err := s.getItem(ctx, keyCfg(ns, m.configPos))
	if err != nil {
		return nil, nil, err
	}
	if it == nil {
		return nil, nil, apiErr(500, "stored_config", "namespace", ns)
	}
	doc, err := jsonv.Parse([]byte(item(it).s("doc")))
	return m, doc, err
}

// ReadConfig serves the current namespace document and its id.
func (s *Store) ReadConfig(ctx context.Context, ns string) (doc any, cfgID string, err error) {
	m, doc, err := s.readConfigState(ctx, ns)
	if err != nil {
		return nil, "", err
	}
	if m == nil {
		return nil, "", apiErr(404, "not_found", "namespace", ns)
	}
	return doc, m.configID, nil
}
