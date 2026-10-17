package main

import "testing"

// Gateway mode refuses plain HTTP except on loopback addresses.
func TestDavLoopback(t *testing.T) {
	for addr, want := range map[string]bool{
		"127.0.0.1:8090": true, "[::1]:8090": true, "localhost:8090": true, "127.0.0.2:1": true,
		":8090": false, "0.0.0.0:8090": false, "[::]:8090": false, "192.168.1.5:8090": false, "example.com:80": false, "nonsense": false,
	} {
		if got := loopback(addr); got != want {
			t.Errorf("loopback(%q) = %v", addr, got)
		}
	}
}
