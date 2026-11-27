package core

import (
	"errors"
	"testing"
	"time"

	"github.com/middle-management/patchlog/internal/pgtest"
)

// Instances on one Spanner database lease slots of their own, and one whose
// lease lapsed takes no ids until it renews it (spslots.go).
func TestPGSpannerIDSlots(t *testing.T) {
	if !pgtest.Spanner() {
		t.Skip("Spanner only")
	}
	url := pgtest.NewDB(t)
	a := openInstance(t, url, t.TempDir())
	b := openInstance(t, url, t.TempDir())
	if a.spSeqs.slot == b.spSeqs.slot {
		t.Fatalf("both instances in slot %d", a.spSeqs.slot)
	}
	a.slots.mu.Lock()
	a.slots.renewed = time.Now().Add(-slotValid - time.Second)
	a.slots.mu.Unlock()
	func() {
		defer func() {
			if err, _ := recover().(error); !errors.Is(err, errSlotLapsed) {
				t.Fatalf("id taken under a lapsed lease: %v", err)
			}
		}()
		a.spSeqs.take(1, 0, 1)
	}()
	a.slots.renew(t.Context())
	a.spSeqs.take(1, 0, 1)
}
