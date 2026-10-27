package core

import (
	"reflect"
	"testing"
)

// CIS-36: a deployment that sees a base's purge applies it (§4, §G.3):
// there is no option to record purges as notices only. Not following at
// all is FollowInterval's (negative, or SyncRemotes never called).
func TestV073NoIgnorePurges(t *testing.T) {
	if _, ok := reflect.TypeOf(RemoteOptions{}).FieldByName("IgnorePurges"); ok {
		t.Fatal("RemoteOptions.IgnorePurges still records purges without applying them")
	}
}
