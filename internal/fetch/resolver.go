// Package fetch provides a high-throughput HTTP fetcher for mass scanning:
// pooled DNS resolution, cached lookups and dialing by IP while preserving
// TLS SNI and the Host header.
package fetch

import (
	"bufio"
	"context"
	"errors"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Resolver resolves hosts concurrently with an in-memory cache. It is safe for
// concurrent use.
type Resolver struct {
	cache   sync.Map // host -> entry
	inner   *net.Resolver
	ttl     time.Duration
	hits    atomic.Int64
	misses  atomic.Int64
	errors  atomic.Int64
	lookupf func(ctx context.Context, host string) (string, error)
	servers []string // normalized "host:port" DNS servers
}

type entry struct {
	ip  string
	err error
	at  time.Time
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
	r := &Resolver{ttl: ttl}
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
	if v, ok := r.cache.Load(host); ok {
		e := v.(entry)
		if time.Since(e.at) < r.ttl {
			r.hits.Add(1)
			return e.ip, e.err
		}
	}
	r.misses.Add(1)
	ip, err := r.lookupf(ctx, host)
	r.cache.Store(host, entry{ip: ip, err: err, at: time.Now()})
	if err != nil {
		r.errors.Add(1)
	}
	return ip, err
}

func (r *Resolver) lookupUncached(ctx context.Context, host string) (string, error) {
	// Look up A first: LookupIPAddr issues an A and an AAAA query in parallel,
	// which means two sockets and two upstream queries per host. On a mass run
	// that doubles both the DNS load and the ephemeral ports held (the range is
	// only 64k). IPv4 covers the vast majority of hosts; IPv6 is a fallback.
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		lctx, cancel := context.WithTimeout(ctx, 4*time.Second)
		ips, err := r.inner.LookupIP(lctx, "ip4", host)
		cancel()
		if err == nil && len(ips) > 0 {
			return ips[0].String(), nil
		}
		if err != nil {
			lastErr = err
			var dnsErr *net.DNSError
			if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
				return "", err // NXDOMAIN: no point retrying
			}
			continue // transient (timeout/SERVFAIL): retry once
		}
		break // resolved, but no A record
	}

	lctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	ips, err := r.inner.LookupIP(lctx, "ip6", host)
	if err == nil && len(ips) > 0 {
		return ips[0].String(), nil
	}
	if err != nil {
		return "", err
	}
	if lastErr != nil {
		return "", lastErr
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
	r.cache.Store(host, entry{ip: ip, at: time.Now()})
}

// Stats returns (cacheHits, lookups, errors).
func (r *Resolver) Stats() (int64, int64, int64) {
	return r.hits.Load(), r.misses.Load(), r.errors.Load()
}

// SetLookup overrides the resolution function (useful for tests).
func (r *Resolver) SetLookup(fn func(ctx context.Context, host string) (string, error)) {
	r.lookupf = fn
}
