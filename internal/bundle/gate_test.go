package bundle

import (
	"math/rand"
	"testing"
	"time"
)

// A namespace's gate sends a request only once the server admits it,
// however the server orders it among the requests in flight: one sent
// later and handled first, drawing more, leaves it a token all the same
// (§6.6). The server's bucket is modelled as core's: it admits a request
// while it holds a token and takes off its draw when it handles it,
// below zero if need be.
func TestGateAdmitsInAnyOrder(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	const rate, burst = 10.0, 100.0
	for run := 0; run < 500; run++ {
		most := 1 + r.Intn(40)
		k := min(6, int(burst)/most) // gateFor's batches in flight
		t0 := time.Unix(0, 0)
		// The gate takes the bucket to hold no more than the server's
		// does: the tightest is as much.
		level := bucketLevel{tokens: 1 + float64(r.Intn(int(burst))), last: t0}
		g := &gate{rate: rate, burst: burst, level: level}
		server := level
		type req struct {
			d            *gateDraw
			batch        int
			land, answer time.Time
			landed       bool
		}
		var live []*req
		left := make([]int, k)
		now := t0
		send := func(batch int) {
			left[batch]--
			tokens := 1 + r.Intn(most)
			d := &gateDraw{at: now.Add(g.wait(now, tokens)), tokens: tokens}
			g.draws = append(g.draws, d)
			land := d.at.Add(time.Duration(r.Intn(800)) * time.Millisecond)
			live = append(live, &req{d: d, batch: batch, land: land, answer: land.Add(time.Duration(r.Intn(800)) * time.Millisecond)})
		}
		for b := range left {
			left[b] = 15
			send(b)
		}
		for len(live) > 0 {
			next, at := 0, time.Time{}
			for i, q := range live {
				t := q.answer
				if !q.landed {
					t = q.land
				}
				if i == 0 || t.Before(at) {
					next, at = i, t
				}
			}
			now = at
			q := live[next]
			if !q.landed {
				have := server.at(now, rate, burst)
				if have < 1-1e-9 { // but for rounding
					t.Fatalf("run %d: a request drawing %d found %.2f tokens", run, q.d.tokens, have)
				}
				server = bucketLevel{tokens: have - float64(q.d.tokens), last: now}
				q.landed = true
				continue
			}
			g.answered(q.d, now)
			live = append(live[:next], live[next+1:]...)
			if left[q.batch] > 0 {
				send(q.batch)
			}
		}
	}
}
