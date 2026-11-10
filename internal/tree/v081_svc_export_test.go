package tree

import (
	"context"
	"time"

	"github.com/middle-management/patchlog/internal/client"
)

// SnapshotBornEpoch is snapshotBornEpoch, and BornPending bornPending, for
// tests (§E.2.6).
func SnapshotBornEpoch(ns string, e client.LogEntry) int { return snapshotBornEpoch(ns, e) }

const BornPending = bornPending

// RecordSubjects records subjects behind gs in the service's edge store,
// as an exchange does, for tests that plant a set stored under an earlier
// draft (§B.11.5).
func (s *Service) RecordSubjects(ctx context.Context, gs string, subjects []string, exp time.Time) error {
	return s.edge.Record(ctx, gs, subjects, exp, s.opt.Now())
}
