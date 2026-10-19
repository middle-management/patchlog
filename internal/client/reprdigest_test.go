package client

import "testing"

// reprSHA256 takes the sha-256 member of a Repr-Digest dictionary (RFC
// 9530), in any position, and nothing that isn't one.
func TestReprSHA256(t *testing.T) {
	d := ReprDigest([]byte(`{"a":1}`))
	b64 := d[len("sha-256=:") : len(d)-1]
	for field, want := range map[string]string{
		d:                                    d,
		"sha-512=:AAAA:, " + d:               d,
		"  " + d + " ,unixsum=:AAA=:":        d,
		"":                                   "",
		"sha-512=:" + b64 + ":":              "",
		"sha-256=" + b64:                     "",
		"sha-256=:AAAA:":                     "", // not 32 bytes
		"sha-256=:" + b64[:len(b64)-1] + ":": "",
	} {
		if got := reprSHA256(field); got != want {
			t.Errorf("%q: %q, want %q", field, got, want)
		}
	}
}
