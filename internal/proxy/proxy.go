// Package proxy loads and rotates outbound HTTP/SOCKS proxies for the scanner,
// the checkers and git cloning.
package proxy

import (
	"bufio"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync/atomic"

	"github.com/go-git/go-git/v5/plumbing/transport"
	githttp "github.com/go-git/go-git/v5/plumbing/transport/http"

	"github.com/eminalolita-coder/git-scanner/internal/config"
)

// Manager rotates a pool of proxies.
type Manager struct {
	urls     []string
	protocol string
	idx      uint64
}

// New builds a manager from config. Returns a disabled manager when off.
func New(cfg config.Proxy) (*Manager, error) {
	m := &Manager{protocol: cfg.Protocol}
	if !cfg.Enabled {
		return m, nil
	}
	if cfg.URL != "" {
		m.urls = append(m.urls, cfg.URL)
	}
	if cfg.File != "" {
		urls, err := loadFile(cfg.File, cfg.Protocol)
		if err != nil {
			return nil, err
		}
		m.urls = append(m.urls, urls...)
	}
	return m, nil
}

func loadFile(path, protocol string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !strings.Contains(line, "://") {
			line = protocol + "://" + line
		}
		out = append(out, line)
	}
	return out, sc.Err()
}

// Enabled reports whether the manager has proxies to use.
func (m *Manager) Enabled() bool { return m != nil && len(m.urls) > 0 }

// next returns the next proxy URL in round-robin order.
func (m *Manager) next() *url.URL {
	if !m.Enabled() {
		return nil
	}
	n := atomic.AddUint64(&m.idx, 1)
	u, err := url.Parse(m.urls[(n-1)%uint64(len(m.urls))])
	if err != nil {
		return nil
	}
	return u
}

// ProxyFunc is suitable for http.Transport.Proxy, rotating per request.
func (m *Manager) ProxyFunc() func(*http.Request) (*url.URL, error) {
	if !m.Enabled() {
		return nil
	}
	return func(*http.Request) (*url.URL, error) { return m.next(), nil }
}

// GitProxy returns transport.ProxyOptions for go-git (no rotation).
func (m *Manager) GitProxy() *transport.ProxyOptions {
	if !m.Enabled() {
		return nil
	}
	return proxyOptionsFrom(m.urls[0])
}

// GitProxyNext returns transport.ProxyOptions for the next clone, rotating
// round-robin. go-git feeds the URL to net/http, which supports http, https,
// socks4/socks5 and socks5h schemes.
func (m *Manager) GitProxyNext() *transport.ProxyOptions {
	if !m.Enabled() {
		return nil
	}
	u := m.next()
	if u == nil {
		return nil
	}
	opts := &transport.ProxyOptions{URL: u.Scheme + "://" + u.Host}
	if u.User != nil {
		opts.Username = u.User.Username()
		opts.Password, _ = u.User.Password()
	}
	return opts
}

func proxyOptionsFrom(raw string) *transport.ProxyOptions {
	u, err := url.Parse(raw)
	if err != nil {
		return nil
	}
	opts := &transport.ProxyOptions{URL: u.Scheme + "://" + u.Host}
	if u.User != nil {
		opts.Username = u.User.Username()
		opts.Password, _ = u.User.Password()
	}
	return opts
}

// GitAuth returns basic auth for the proxy (when credentials are embedded).
func (m *Manager) GitAuth() transport.AuthMethod {
	if !m.Enabled() {
		return nil
	}
	u, err := url.Parse(m.urls[0])
	if err != nil || u.User == nil {
		return nil
	}
	pass, _ := u.User.Password()
	return &githttp.BasicAuth{Username: u.User.Username(), Password: pass}
}
