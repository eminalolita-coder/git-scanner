package fetch

import (
	"context"
	"testing"
	"time"
)

func TestResolverAcceptsBareIP(t *testing.T) {
	// "1.1.1.1" must be normalized to "1.1.1.1:53", otherwise the udp dial
	// fails with "missing port in address" and every host looks dead.
	r := NewResolver([]string{"1.1.1.1", "8.8.8.8:5353"}, time.Minute)
	if len(r.servers) != 2 {
		t.Fatalf("servers = %v", r.servers)
	}
	if r.servers[0] != "1.1.1.1:53" {
		t.Errorf("bare ip not normalized: %q", r.servers[0])
	}
	if r.servers[1] != "8.8.8.8:5353" {
		t.Errorf("explicit port mangled: %q", r.servers[1])
	}
}

func TestResolverRetriesOnTimeout(t *testing.T) {
	r := NewResolver([]string{"1.1.1.1"}, time.Minute)
	calls := 0
	r.SetLookup(func(ctx context.Context, host string) (string, error) {
		calls++
		return "10.0.0.1", nil
	})
	if _, err := r.Lookup(context.Background(), "a.test"); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Errorf("expected a single call, got %d", calls)
	}
}
