package core

import "testing"

func TestValidRemoteOrigin(t *testing.T) {
	good := []string{"https://cms.example", "https://cms.example:8443", "http://localhost:8080", "http://127.0.0.1:9", "http://[::1]:8080", "http://localhost"}
	bad := []string{"http://cms.example", "https://cms.example/", "https://CMS.example", "https://cms.example:443",
		"http://localhost:80", "ftp://cms.example", "https://u@cms.example", "https://cms.example?x", "cms.example", "https://"}
	for _, s := range good {
		if !ValidRemoteOrigin(s) {
			t.Errorf("%q rejected", s)
		}
	}
	for _, s := range bad {
		if ValidRemoteOrigin(s) {
			t.Errorf("%q accepted", s)
		}
	}
}
