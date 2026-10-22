package main

import (
	"io"
	"os"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/merge"
)

// §F.9 The merge lock: release status shows each catalog base's lock,
// { holder, plan } or free, and which a person must release.
func TestV073ReleaseStatusLocks(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout := os.Stdout
	os.Stdout = w
	rp := &merge.ReleasePlan{Digest: "1mine"}
	printLocks(rp, []*merge.Lock{
		{NS: "releases", Name: "merge-lock.cat", State: client.Live},
		{NS: "releases", Name: "merge-lock.cat2", State: client.Live, Holder: "svc:merge", Plan: "1mine"},
		{NS: "releases", Name: "merge-lock.cat3", State: client.Live, Holder: "svc:other"},
		{NS: "releases", Name: "merge-lock.cat4", State: client.Live, Legacy: "/r/releases/release-6"},
	})
	w.Close()
	os.Stdout = stdout
	b, _ := io.ReadAll(r)
	want := []string{
		"lock releases/merge-lock.cat: free",
		"lock releases/merge-lock.cat2: held by svc:merge for this plan",
		"lock releases/merge-lock.cat3: held by svc:other for plan (none)",
		"lock releases/merge-lock.cat4: held by an earlier version's merge of /r/releases/release-6; a person releases it",
	}
	for _, s := range want {
		if !strings.Contains(string(b), s) {
			t.Fatalf("missing %q in\n%s", s, b)
		}
	}
}
