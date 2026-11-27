package fetch

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestCacheHitMissAndTTL(t *testing.T) {
	r := NewResolver([]string{"127.0.0.1"}, time.Minute)
	r.lookupf = func(_ context.Context, _ string) (string, error) { return "", nil }

	r.cacheSet("a.example", entry{ip: "1.2.3.4", at: time.Now()})
	if e, ok := r.cacheGet("a.example"); !ok || e.ip != "1.2.3.4" {
		t.Fatalf("expected a cache hit, got %v %v", e, ok)
	}
	if _, ok := r.cacheGet("nope.example"); ok {
		t.Fatal("expected a miss")
	}

	// expired entry is reported as a miss
	r.cacheSet("old.example", entry{ip: "9.9.9.9", at: time.Now().Add(-2 * time.Hour)})
	if _, ok := r.cacheGet("old.example"); ok {
		t.Fatal("expected the expired entry to be a miss")
	}
}

func TestCacheEvictionStaysBounded(t *testing.T) {
	r := NewResolver([]string{"127.0.0.1"}, time.Hour)
	r.maxPer = 128
	for i := 0; i < 2000; i++ {
		r.cacheSet(fmt.Sprintf("h%d.example", i), entry{ip: "1.1.1.1", at: time.Now()})
	}
	total := 0
	for i := range r.shards {
		if n := len(r.shards[i].m); n > r.maxPer {
			t.Fatalf("shard %d holds %d > maxPer %d", i, n, r.maxPer)
		}
		total += len(r.shards[i].m)
	}
	if total == 0 {
		t.Fatal("eviction emptied everything")
	}
}

// TestCacheConcurrent hammers the cache from many goroutines: run with -race.
func TestCacheConcurrent(t *testing.T) {
	r := NewResolver([]string{"127.0.0.1"}, time.Hour)
	r.maxPer = 512
	var wg sync.WaitGroup
	for w := 0; w < 64; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < 20000; i++ {
				h := fmt.Sprintf("host-%d-%d.example", w, i%3000)
				r.cacheSet(h, entry{ip: "1.2.3.4", at: time.Now()})
				r.cacheGet(h)
			}
		}(w)
	}
	wg.Wait()
}

// BenchmarkShardedCache and BenchmarkSyncMapCache reproduce the pathology: a
// single sync.Map degrades as the live key set grows, the sharded cache does
// not. Both hammer 1.5M keys from 128 goroutines, like a mass run.
func benchKeys(n int) []string {
	ks := make([]string, n)
	for i := range ks {
		ks[i] = fmt.Sprintf("site-%d.example.com", i)
	}
	return ks
}

func BenchmarkShardedCache(b *testing.B) {
	const n = 1_500_000
	ks := benchKeys(n)
	r := NewResolver([]string{"127.0.0.1"}, time.Hour)
	r.maxPer = 0
	for _, k := range ks {
		r.cacheSet(k, entry{ip: "1.1.1.1", at: time.Now()})
	}
	var ctr uint64
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			i++
			k := ks[(int(ctr)+i*7919)%n]
			if _, ok := r.cacheGet(k); !ok {
				r.cacheSet(k, entry{ip: "1.1.1.1", at: time.Now()})
			}
		}
	})
}

type smEntry struct {
	ip string
	at time.Time
}

func BenchmarkSyncMapCache(b *testing.B) {
	const n = 1_500_000
	ks := benchKeys(n)
	var m sync.Map
	for _, k := range ks {
		m.Store(k, smEntry{ip: "1.1.1.1", at: time.Now()})
	}
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			i++
			k := ks[(i*7919)%n]
			if _, ok := m.Load(k); !ok {
				m.Store(k, smEntry{ip: "1.1.1.1", at: time.Now()})
			}
		}
	})
}
