package proxy

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/eminalolita-coder/git-scanner/internal/config"
)

func TestDisabled(t *testing.T) {
	m, err := New(config.Proxy{})
	if err != nil {
		t.Fatal(err)
	}
	if m.Enabled() {
		t.Error("expected disabled")
	}
	if m.ProxyFunc() != nil {
		t.Error("expected nil proxy func when disabled")
	}
}

func TestLoadFileAndRotate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "proxies.txt")
	_ = os.WriteFile(path, []byte("# comment\n1.1.1.1:8080\nhttp://user:pass@2.2.2.2:3128\n"), 0o644)

	m, err := New(config.Proxy{Enabled: true, Protocol: "http", File: path})
	if err != nil {
		t.Fatal(err)
	}
	if !m.Enabled() {
		t.Fatal("expected enabled")
	}
	// first two calls should yield the two distinct proxies
	a := m.next()
	b := m.next()
	if a == nil || b == nil {
		t.Fatal("nil proxy url")
	}
	if a.String() == b.String() {
		t.Errorf("expected rotation, got %q twice", a)
	}
	opts := m.GitProxy()
	if opts == nil || opts.Username != "" && opts.URL == "" {
		t.Errorf("bad git proxy opts: %+v", opts)
	}
}
