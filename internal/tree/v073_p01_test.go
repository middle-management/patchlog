package tree

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/client"
)

// §7.2, §12.1 (GB-20, GB-21): an edge-grant exchange's body is compared
// as a media type, a charset naming UTF-8 its only parameter, and any
// other Content-Type is 415 with code unsupported_type.
func TestV073EdgeGrantsMediaType(t *testing.T) {
	t.Parallel()
	core := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"spec":"0.73","auth":"grants","origin":"https://cms.example"}`))
	}))
	t.Cleanup(core.Close)
	c, err := client.New(core.URL)
	if err != nil {
		t.Fatal(err)
	}
	s := &Service{c: c, opt: Options{Logf: t.Logf}}
	for _, tc := range []struct {
		ct     string
		status int
		code   string
	}{
		{"text/plain", 415, "unsupported_type"},
		{"application/json; charset=latin1", 415, "unsupported_type"},
		{"application/json; foo=bar", 415, "unsupported_type"},
		{"application/json; charset=utf-8; charset=latin1", 415, "unsupported_type"},
		{"application/json-patch+json", 415, "unsupported_type"},
		// The media type is right: the empty list is refused after it.
		{"application/json", 400, "bad_input"},
		{"Application/JSON; Charset=UTF-8", 400, "bad_input"},
		{`application/json;charset="utf-8"`, 400, "bad_input"},
	} {
		req := httptest.NewRequest("POST", "/edge-grants", strings.NewReader(`{"grants":[]}`))
		req.Header.Set("Content-Type", tc.ct)
		w := httptest.NewRecorder()
		s.issueEdgeGrants(w, req)
		var body map[string]any
		json.Unmarshal(w.Body.Bytes(), &body)
		if w.Code != tc.status || body["code"] != tc.code {
			t.Errorf("%s: %d %s, want %d %s", tc.ct, w.Code, w.Body, tc.status, tc.code)
		}
	}
}
