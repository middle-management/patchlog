package main

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

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

// Gateway mode warns of grants sent upstream over plain HTTP to another
// host; secret files others may read are warned of.
func TestDavWarnings(t *testing.T) {
	for api, want := range map[string]bool{
		"http://localhost:8080": false, "http://127.0.0.1:8080": false, "http://[::1]:8080": false, "https://cms.example": false,
		"http://cms.example": true, "http://10.0.0.5:8080": true, "http://core:8080": true,
	} {
		if got := plainRemote(api); got != want {
			t.Errorf("plainRemote(%q) = %v", api, got)
		}
	}
	dir := t.TempDir()
	for mode, want := range map[os.FileMode]bool{0o600: false, 0o400: false, 0o640: true, 0o644: true} {
		f := filepath.Join(dir, mode.String())
		if err := os.WriteFile(f, []byte("secret"), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(f, mode); err != nil {
			t.Fatal(err)
		}
		fi, err := os.Stat(f)
		if err != nil {
			t.Fatal(err)
		}
		if got := loose(fi); got != want {
			t.Errorf("loose(%v) = %v", mode, got)
		}
	}
}

// -tree-url takes a default tree service and catalogs' own, as serve's
// does.
func TestDavTreeURLs(t *testing.T) {
	def, per, err := treeServices([]string{"http://tree:8082", "cat=http://tree-cat:8082/x", "dag=https://t.example"})
	if err != nil || def != "http://tree:8082" || !reflect.DeepEqual(per, map[string]string{"cat": "http://tree-cat:8082/x", "dag": "https://t.example"}) {
		t.Fatalf("%q %v %v", def, per, err)
	}
	for _, bad := range [][]string{{"http://a", "http://b"}, {"cat=http://a", "cat=http://b"}} {
		if _, _, err := treeServices(bad); err == nil {
			t.Errorf("%q taken", bad)
		}
	}
}
