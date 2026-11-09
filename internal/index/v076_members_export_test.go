package index

import "context"

// OnMemberBootstrap calls f before the follower of a namespace visibility
// reads gives it its first checkpoint (members.go), and may hold it there
// until ctx is done (tests). Set it before Run.
func (ix *Index) OnMemberBootstrap(f func(ctx context.Context, m string)) { ix.testMemberBootstrap = f }

// OnBeforeAnswer calls f once a reader's views are computed, before the
// answer is: a query's head pointer, or /_refs (tests).
func (ix *Index) OnBeforeAnswer(f func()) { ix.testBeforeAnswer = f }
