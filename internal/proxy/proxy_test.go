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
	if m.GitProxyNext() != nil {
		t.Error("expected nil git proxy when disabled")
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
	a := m.next()
	b := m.next()
	if a == nil || b == nil {
		t.Fatal("nil proxy url")
	}
	if a.String() == b.String() {
		t.Errorf("expected rotation, got %q twice", a)
	}
	if opts := m.GitProxy(); opts == nil || opts.URL == "" {
		t.Errorf("bad git proxy opts: %+v", opts)
	}
}

func TestGitProxyNextRotatesAndKeepsSocks(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "socks.txt")
	_ = os.WriteFile(path, []byte("socks5://127.0.0.1:1080\nsocks5://user:pw@127.0.0.1:1081\n"), 0o644)

	m, err := New(config.Proxy{Enabled: true, Protocol: "socks5", File: path})
	if err != nil {
		t.Fatal(err)
	}
	first := m.GitProxyNext()
	second := m.GitProxyNext()
	if first == nil || second == nil {
		t.Fatal("nil proxy")
	}
	if first.URL == second.URL {
		t.Errorf("expected rotation, got %q twice", first.URL)
	}
	if first.URL[:9] != "socks5://" {
		t.Errorf("scheme not preserved: %q", first.URL)
	}
	if first.Username == "" && second.Username == "" {
		t.Error("expected one proxy with credentials")
	}
}
