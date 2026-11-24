package core

import (
	"math/rand/v2"
	"sync"
	"testing"
)

// Ids on Spanner grow along a chain, stay in its bucket, are above its head
// whatever the clock, and are never handed out twice (seqGen).
func TestSeqGen(t *testing.T) {
	var g seqGen
	chain := int64(rand.Uint64() >> 1)
	b := spBucket(chain)
	first := g.take(chain, 0, 3)
	if spBucket(first[0]) != b {
		t.Fatalf("first id %d in bucket %d, the chain's is %d", first[0], spBucket(first[0]), b)
	}
	for i := 1; i < len(first); i++ {
		if first[i] != first[i-1]+1 {
			t.Fatalf("ids of one take not consecutive: %v", first)
		}
	}
	// A head far ahead (another instance's clock): the next is above it.
	ahead := first[2] + 1<<30
	next := g.take(chain, ahead, 1)[0]
	if next <= ahead || spBucket(next) != b {
		t.Fatalf("id %d after head %d", next, ahead)
	}
	// A branch goes on from its base's chain: the base's bucket.
	base := g.take(int64(rand.Uint64()>>1), 0, 1)[0]
	branch := int64(rand.Uint64() >> 1)
	if v := g.take(branch, base, 1)[0]; v <= base || spBucket(v) != spBucket(base) {
		t.Fatalf("branch id %d after base head %d", v, base)
	}
	// Concurrent takes never repeat an id.
	seen := sync.Map{}
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 1000 {
				for _, v := range g.take(chain, 0, 2) {
					if _, dup := seen.LoadOrStore(v, true); dup {
						t.Errorf("id %d handed out twice", v)
					}
				}
			}
		})
	}
	wg.Wait()
}

// The tailer's shards and the id buckets cover every key.
func TestSpannerShards(t *testing.T) {
	for _, k := range []int64{0, 1, 1<<62 + 5, 1<<63 - 1} {
		if s := spShard(k); s < 0 || s >= spShards {
			t.Fatalf("shard %d of %d", s, k)
		}
		if b := spBucket(k); b < 0 || b >= 1<<spBucketBits {
			t.Fatalf("bucket %d of %d", b, k)
		}
	}
}
