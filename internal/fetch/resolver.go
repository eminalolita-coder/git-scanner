// Package fetch provides a high-throughput HTTP fetcher for mass scanning:
// pooled DNS resolution, cached lookups and dialing by IP while preserving
// TLS SNI and the Host header.
package fetch

import (
	"bufio"
	"context"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Resolver resolves hosts concurrently with an in-memory cache. It is safe for
// concurrent use.
//
// The cache is SHARDED on purpose. A single sync.Map collapses on a mass run:
// once its dirty map holds millions of live keys, every Load of a key that has
// not been promoted takes the map's global mutex, and promotions copy the whole
// map under it. With tens of thousands of workers doing a lookup per dial the
// contention serialises everything and throughput falls off a cliff (observed:
// stuck at ~1.1M hosts with ~0 CPU and no sockets, whatever the concurrency).
// 256 shards keep the critical sections short and independent.
type Resolver struct {
	shards  [shardCount]shard
	maxPer  int // entries per shard before eviction (0 = unbounded)
	inner   *net.Resolver
	ttl     time.Duration
	hits    atomic.Int64
	misses  atomic.Int64
	errors  atomic.Int64
	lookupf func(ctx context.Context, host string) (string, error)
	servers []string // normalized "host:port" DNS servers
}

const (
	shardCount = 256
	shardMask  = shardCount - 1
	// 256 shards * 2^18 = 67M hosts cached before any eviction: enough for a
	// 41M-domain list with room to spare, at roughly 64B per entry.
	defaultMaxPerShard = 1 << 18
)

type shard struct {
	mu sync.RWMutex
	m  map[string]entry
}

type entry struct {
	ip  string
	err error
	at  time.Time
}

func (r *Resolver) shardFor(host string) *shard {
	h := uint32(2166136261) // FNV-1a
	for i := 0; i < len(host); i++ {
		h ^= uint32(host[i])
		h *= 16777619
	}
	return &r.shards[h&shardMask]
}

func (r *Resolver) cacheGet(host string) (entry, bool) {
	s := r.shardFor(host)
	s.mu.RLock()
	e, ok := s.m[host]
	s.mu.RUnlock()
	if !ok {
		return entry{}, false
	}
	if r.ttl > 0 && time.Since(e.at) >= r.ttl {
		return entry{}, false
	}
	return e, true
}

func (r *Resolver) cacheSet(host string, e entry) {
	s := r.shardFor(host)
	s.mu.Lock()
	if r.maxPer > 0 && len(s.m) >= r.maxPer {
		r.evictLocked(s)
	}
	s.m[host] = e
	s.mu.Unlock()
}

// evictLocked drops expired entries and, if the shard is still full, a batch of
// live ones so the next calls stay cheap.
func (r *Resolver) evictLocked(s *shard) {
	now := time.Now()
	for k, e := range s.m {
		if r.ttl > 0 && now.Sub(e.at) >= r.ttl {
			delete(s.m, k)
		}
	}
	if len(s.m) < r.maxPer {
		return
	}
	drop := len(s.m) - r.maxPer + r.maxPer/8
	for k := range s.m {
		delete(s.m, k)
		if drop--; drop <= 0 {
			break
		}
	}
}

// srcAddrs are the loopback source addresses rotated across DNS dials. The
// kernel routes all of 127.0.0.0/8 to lo, and the ~64k ephemeral port range
// applies per (address, port) pair, so several addresses multiply the number
// of concurrent DNS sockets a mass run can hold.
var srcAddrs = []net.IP{
	net.ParseIP("127.0.0.1"), net.ParseIP("127.0.0.2"),
	net.ParseIP("127.0.0.3"), net.ParseIP("127.0.0.4"),
	net.ParseIP("127.0.0.5"), net.ParseIP("127.0.0.6"),
	net.ParseIP("127.0.0.7"), net.ParseIP("127.0.0.8"),
}

// NewResolver builds a resolver bound to the given DNS servers. Empty servers
// fall back to the system resolvers.
func NewResolver(servers []string, ttl time.Duration) *Resolver {
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	r := &Resolver{ttl: ttl, maxPer: defaultMaxPerShard}
	for i := range r.shards {
		r.shards[i].m = make(map[string]entry, 64)
	}
	if len(servers) == 0 {
		servers = systemResolvers()
	}
	// accept both "1.1.1.1" and "1.1.1.1:5353"
	for i, s := range servers {
		s = strings.TrimSpace(s)
		if _, _, err := net.SplitHostPort(s); err != nil {
			s = net.JoinHostPort(s, "53")
		}
		servers[i] = s
	}
	if len(servers) > 0 {
		r.servers = servers
		idx := atomic.Int64{}
		sidx := atomic.Int64{}
		r.inner = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				srv := servers[int(idx.Add(1)-1)%len(servers)]
				d := net.Dialer{Timeout: 3 * time.Second}
				// Spread source sockets over several loopback addresses. The
				// ephemeral port range (~64k) is per (address, port) pair, so
				// pointing everything at 127.0.0.1 caps a big run at 64k
				// sockets and the resolver starts failing with "cannot find
				// an open port". All of 127.0.0.0/8 is local.
				if strings.HasPrefix(srv, "127.") {
					d.LocalAddr = &net.UDPAddr{IP: srcAddrs[int(sidx.Add(1)-1)%len(srcAddrs)]}
				}
				return d.DialContext(ctx, "udp", srv)
			},
		}
	} else {
		r.inner = net.DefaultResolver
	}
	r.lookupf = r.lookupUncached
	return r
}

func systemResolvers() []string {
	f, err := os.Open("/etc/resolv.conf")
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) == 2 && fields[0] == "nameserver" {
			out = append(out, net.JoinHostPort(fields[1], "53"))
		}
	}
	return out
}

// Lookup returns the first IP for host, using the cache.
func (r *Resolver) Lookup(ctx context.Context, host string) (string, error) {
	if host == "" {
		return "", nil
	}
	if ip := net.ParseIP(host); ip != nil {
		return host, nil
	}
	if v, ok := r.cacheGet(host); ok {
		r.hits.Add(1)
		return v.ip, v.err
	}
	r.misses.Add(1)
	ip, err := r.lookupf(ctx, host)
	r.cacheSet(host, entry{ip: ip, err: err, at: time.Now()})
	if err != nil {
		r.errors.Add(1)
	}
	return ip, err
}

func (r *Resolver) lookupUncached(ctx context.Context, host string) (string, error) {
	// ONE A query, no retry: at 40M lookups a retry chain multiplies the load on
	// the resolver for nothing. Measured on the VPS: ~10 DNS queries per host
	// with the old (A, retry, AAAA, plus the dial fallback) shape, ~1 with this.
	lctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	ips, err := r.inner.LookupIP(lctx, "ip4", host)
	if err == nil && len(ips) > 0 {
		return ips[0].String(), nil
	}
	if err != nil {
		return "", err
	}
	// resolved but no A record: try AAAA once (IPv6-only hosts)
	lctx6, cancel6 := context.WithTimeout(ctx, 3*time.Second)
	defer cancel6()
	ips6, err6 := r.inner.LookupIP(lctx6, "ip6", host)
	if err6 == nil && len(ips6) > 0 {
		return ips6[0].String(), nil
	}
	return "", &net.DNSError{Err: "no address", Name: host}
}

// PreResolve resolves many hosts with a worker pool, warming the cache.
func (r *Resolver) PreResolve(ctx context.Context, hosts []string, workers int) {
	if workers <= 0 {
		workers = 500
	}
	jobs := make(chan string, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for h := range jobs {
				_, _ = r.Lookup(ctx, h)
			}
		}()
	}
	for _, h := range hosts {
		select {
		case jobs <- h:
		case <-ctx.Done():
			close(jobs)
			wg.Wait()
			return
		}
	}
	close(jobs)
	wg.Wait()
}

// Seed stores a known host -> ip mapping, bypassing resolution.
func (r *Resolver) Seed(host, ip string) {
	if host == "" || ip == "" {
		return
	}
	r.cacheSet(host, entry{ip: ip, at: time.Now()})
}

// Stats returns (cacheHits, lookups, errors).
func (r *Resolver) Stats() (int64, int64, int64) {
	return r.hits.Load(), r.misses.Load(), r.errors.Load()
}

// SetLookup overrides the resolution function (useful for tests).
func (r *Resolver) SetLookup(fn func(ctx context.Context, host string) (string, error)) {
	r.lookupf = fn
}
