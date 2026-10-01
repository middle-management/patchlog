package main

import "testing"

func TestHealthURL(t *testing.T) {
	for in, want := range map[string]string{
		":8081":                      "http://localhost:8081/_health",
		"index:8081":                 "http://index:8081/_health",
		"localhost:8080/_ready":      "http://localhost:8080/_ready",
		"http://tree:8082/_health":   "http://tree:8082/_health",
		"https://cms.example/_ready": "https://cms.example/_ready",
	} {
		if got := healthURL(in); got != want {
			t.Errorf("healthURL(%q) = %q, want %q", in, got, want)
		}
	}
}
