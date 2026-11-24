package fetch

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSeedAndCache(t *testing.T) {
	r := NewResolver(nil, time.Minute)
	r.Seed("a.test", "1.2.3.4")
	ip, err := r.Lookup(context.Background(), "a.test")
	if err != nil || ip != "1.2.3.4" {
		t.Fatalf("seeded lookup = %q, %v", ip, err)
	}
	hits, misses, _ := r.Stats()
	if hits != 1 || misses != 0 {
		t.Errorf("expected 1 hit 0 misses, got %d/%d", hits, misses)
	}
	// literal IP passes through
	if ip, _ := r.Lookup(context.Background(), "9.9.9.9"); ip != "9.9.9.9" {
		t.Errorf("ip passthrough failed: %q", ip)
	}
}

func TestPreResolveUsesLookupFunc(t *testing.T) {
	r := NewResolver(nil, time.Minute)
	calls := 0
	r.SetLookup(func(_ context.Context, host string) (string, error) {
		calls++
		if host == "bad.test" {
			return "", errors.New("nx")
		}
		return "10.0.0.1", nil
	})
	r.PreResolve(context.Background(), []string{"a.test", "b.test", "bad.test", "a.test"}, 2)
	if calls < 3 {
		t.Errorf("expected at least 3 lookups, got %d", calls)
	}
	if ip, _ := r.Lookup(context.Background(), "a.test"); ip != "10.0.0.1" {
		t.Errorf("unexpected ip %q", ip)
	}
}

func TestClientDialsByIP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Host header must be the fake domain (with port), proving the
		// original host is preserved while dialing the seeded IP
		if !strings.HasPrefix(r.Host, "fake.test") {
			t.Errorf("host header = %q", r.Host)
		}
		_, _ = w.Write([]byte("hello GITHUB_TOKEN=ghp_test"))
	}))
	defer srv.Close()

	addr := strings.TrimPrefix(srv.URL, "http://")
	_, port, _ := splitHostPort(addr)
	host := "fake.test:" + port

	res := NewResolver(nil, time.Minute)
	res.Seed("fake.test", "127.0.0.1")

	c := New(Options{Timeout: 3 * time.Second, Resolver: res})
	code, body, err := c.Fetch(context.Background(), "http", host, "/")
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if code != 200 || !strings.Contains(string(body), "ghp_test") {
		t.Fatalf("unexpected response %d %q", code, body)
	}
}

func splitHostPort(addr string) (string, string, error) {
	i := strings.LastIndexByte(addr, ':')
	if i < 0 {
		return addr, "", nil
	}
	return addr[:i], addr[i+1:], nil
}
