package output

import (
	"hash/fnv"
	"sync"
	"sync/atomic"

	"github.com/eminalolita-coder/git-scanner/internal/model"
)

// AsyncWriter decouples finding production from disk writes. Writes are
// non-blocking up to the buffer size; overflow is counted and dropped.
type AsyncWriter struct {
	ch      chan model.Finding
	inner   Writer
	done    chan struct{}
	dropped atomic.Int64
	once    sync.Once
}

// NewAsync wraps w with a buffered channel and a single writer goroutine.
func NewAsync(w Writer, buf int) *AsyncWriter {
	if buf <= 0 {
		buf = 8192
	}
	a := &AsyncWriter{ch: make(chan model.Finding, buf), inner: w, done: make(chan struct{})}
	go func() {
		defer close(a.done)
		for f := range a.ch {
			_ = a.inner.Write(f)
		}
	}()
	return a
}

// Write enqueues a finding. It BLOCKS when the channel is full instead of
// dropping: on a real run a burst of findings used to be silently lost, and
// losing findings is worse than a little backpressure. drops stays as a
// counter for observability.
func (a *AsyncWriter) Write(f model.Finding) error {
	select {
	case a.ch <- f:
		return nil
	default:
	}
	// channel full: wait for the writer to catch up
	select {
	case a.ch <- f:
		return nil
	case <-a.done:
		return nil
	}
}

// Close flushes and closes the inner writer. Safe to call twice.
func (a *AsyncWriter) Close() error {
	var err error
	a.once.Do(func() {
		close(a.ch)
		<-a.done
		err = a.inner.Close()
	})
	return err
}

// Path returns the inner writer path.
func (a *AsyncWriter) Path() string { return a.inner.Path() }

// Dropped returns the number of findings dropped on overflow.
func (a *AsyncWriter) Dropped() int64 { return a.dropped.Load() }

// ShardedDedup is a sharded, lock-striped de-duplicator.
type ShardedDedup struct {
	shards []*dedupShard
	mask   uint64
}

type dedupShard struct {
	mu sync.Mutex
	m  map[string]struct{}
}

// NewShardedDedup builds a de-duplicator with n shards.
func NewShardedDedup(n int) *ShardedDedup {
	if n <= 0 {
		n = 64
	}
	// round up to a power of two
	p := 1
	for p < n {
		p <<= 1
	}
	d := &ShardedDedup{shards: make([]*dedupShard, p), mask: uint64(p - 1)}
	for i := range d.shards {
		d.shards[i] = &dedupShard{m: make(map[string]struct{})}
	}
	return d
}

// First reports whether key is new (and records it).
func (d *ShardedDedup) First(key string) bool {
	h := fnv.New64a()
	_, _ = h.Write([]byte(key))
	s := d.shards[h.Sum64()&d.mask]
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.m[key]; ok {
		return false
	}
	s.m[key] = struct{}{}
	return true
}

// Len returns the total number of recorded keys.
func (d *ShardedDedup) Len() int {
	total := 0
	for _, s := range d.shards {
		s.mu.Lock()
		total += len(s.m)
		s.mu.Unlock()
	}
	return total
}
