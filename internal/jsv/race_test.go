//go:build race

package jsv

// raceEnabled: sync.Pool drops items at random under the race detector, so
// allocation counts mean nothing.
const raceEnabled = true
