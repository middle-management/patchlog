package client

import (
	"testing"

	"github.com/middle-management/patchlog/internal/seal"
)

// sealedRev is a revision whose patch set is one sealed op with the given
// kid and pl.ns (§E.3.1).
func sealedRev(t *testing.T, kid, plNS string) LogEntry {
	t.Helper()
	jwe, err := seal.Seal(make([]byte, 32), kid, seal.PL{"ns": plNS, "name": "r", "parent": nil}, []byte(`[]`))
	if err != nil {
		t.Fatal(err)
	}
	return LogEntry{Kind: "rev", HasPatches: true, Patches: []any{map[string]any{"op": "sealed", "value": jwe}}}
}

// A revision a branch reads through from a base is not the branch's own
// op, whatever its kid names: the snapshot kid is the epoch in force
// (§E.3.1 Patch sets, "where the op is its own (its pl.ns names this
// namespace)"), and a derived view's epoch is not known from it (ENC-6).
func TestV077SnapshotEpochByPLNS(t *testing.T) {
	cases := []struct {
		name       string
		kid, plNS  string
		wantEpoch  int
		wantDocKid string
	}{
		{"base op, kid naming ns", "n#3", "n0", 7, ""},
		{"base op, base kid", "n0#2", "n0", 7, ""},
		{"own op", "n#3", "n", 3, "n#3"},
		{"own op, kid naming a base", "n0#2", "n", 0, ""},
	}
	for _, tc := range cases {
		d := &E2EDoc{ns: "n", log: []LogEntry{sealedRev(t, tc.kid, tc.plNS)}}
		if got := snapshotEpoch("n", 7, d); got != tc.wantEpoch {
			t.Errorf("%s: snapshotEpoch = %d, want %d", tc.name, got, tc.wantEpoch)
		}
		if got := d.Kid(); got != tc.wantDocKid {
			t.Errorf("%s: Kid() = %q, want %q", tc.name, got, tc.wantDocKid)
		}
	}
	// Below a horizon, the snapshot's kid decides (its pl.ns is the kid's).
	d := &E2EDoc{ns: "n", since: "x", sinceKid: "n0#2"}
	if got := snapshotEpoch("n", 7, d); got != 7 {
		t.Errorf("base snapshot: snapshotEpoch = %d, want 7", got)
	}
	if got := d.Kid(); got != "" {
		t.Errorf("base snapshot: Kid() = %q, want \"\"", got)
	}
	d = &E2EDoc{ns: "n", since: "x", sinceKid: "n#4"}
	if got, kid := snapshotEpoch("n", 7, d), d.Kid(); got != 4 || kid != "n#4" {
		t.Errorf("own snapshot: snapshotEpoch = %d, Kid() = %q, want 4, n#4", got, kid)
	}
}
