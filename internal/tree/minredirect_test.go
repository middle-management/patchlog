package tree_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
)

// TestMinAfterWriteConcurrent: write to the catalog, then at once list with
// the write's min from many clients, following redirects: no URL repeats,
// at most one redirect, and the listing shows the write (§B.5, §A.5).
func TestMinAfterWriteConcurrent(t *testing.T) {
	w := setup(t)
	x := startSvc(t, w.c, svcOpts{})
	x.caughtUp("cat", "matches")
	for i := range 15 {
		name := fmt.Sprintf("f%d", i)
		wr := must(w.c.CreateDoc(context.Background(), "cat", name, map[string]any{"title": name, "parents": parents()}))
		var wg sync.WaitGroup
		errs := make(chan error, 16)
		for range 8 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				path := "/cat/roots?min=cat:" + wr.NSID
				var seen []string
				for {
					if slices.Contains(seen, path) || len(seen) > 2 {
						errs <- fmt.Errorf("redirects %v → %s", seen, path)
						return
					}
					seen = append(seen, path)
					r, err := noRedirect.Get(x.http.URL + path)
					if err != nil {
						errs <- err
						return
					}
					b, _ := io.ReadAll(r.Body)
					r.Body.Close()
					if r.StatusCode == http.StatusFound {
						path = r.Header.Get("Location")
						continue
					}
					if r.StatusCode != 200 {
						errs <- fmt.Errorf("%s: %d %s", path, r.StatusCode, b)
						return
					}
					var m map[string]any
					if err := json.Unmarshal(b, &m); err != nil {
						errs <- err
						return
					}
					if got := names(m["roots"]); !slices.Contains(strings.Split(got, ","), name) {
						errs <- fmt.Errorf("%s: roots %s miss %s (via %v)", path, got, name, seen)
					}
					return
				}
			}()
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			t.Error(err)
		}
		if t.Failed() {
			return
		}
	}
}
