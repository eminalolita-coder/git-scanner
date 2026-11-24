package fetch

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"
)

// Options configures the fetcher.
type Options struct {
	Timeout           time.Duration
	Resolver          *Resolver
	MaxBody           int64
	MaxIdleConns      int
	MaxIdlePerHost    int
	MaxConnsPerHost   int
	DisableKeepAlives bool
	UserAgent         string
	Insecure          bool
}

// Client is a tuned HTTP client that resolves and dials by IP.
type Client struct {
	hc      *http.Client
	res     *Resolver
	ua      string
	maxBody int64
	reqs    atomic.Int64
	errs    atomic.Int64
}

// New builds a Client with the given options.
func New(o Options) *Client {
	if o.Timeout <= 0 {
		o.Timeout = 5 * time.Second
	}
	if o.MaxBody <= 0 {
		o.MaxBody = 2 << 20
	}
	if o.MaxIdleConns <= 0 {
		o.MaxIdleConns = 20000
	}
	if o.MaxIdlePerHost <= 0 {
		o.MaxIdlePerHost = 8
	}
	if o.MaxConnsPerHost <= 0 {
		o.MaxConnsPerHost = 16
	}
	if o.UserAgent == "" {
		o.UserAgent = "git-scanner/1.0"
	}
	res := o.Resolver
	if res == nil {
		res = NewResolver(nil, 10*time.Minute)
	}

	dialer := &net.Dialer{Timeout: o.Timeout, KeepAlive: 30 * time.Second}
	tr := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return dialer.DialContext(ctx, network, addr)
			}
			ip, err := res.Lookup(ctx, host)
			if err != nil || ip == "" {
				return dialer.DialContext(ctx, network, addr)
			}
			// dial the resolved IP; net/http still uses the URL host for SNI
			return dialer.DialContext(ctx, network, net.JoinHostPort(ip, port))
		},
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: o.Insecure},
		TLSHandshakeTimeout: o.Timeout,
		MaxIdleConns:        o.MaxIdleConns,
		MaxIdleConnsPerHost: o.MaxIdlePerHost,
		MaxConnsPerHost:     o.MaxConnsPerHost,
		IdleConnTimeout:     30 * time.Second,
		DisableKeepAlives:   o.DisableKeepAlives,
		ForceAttemptHTTP2:   false,
		ReadBufferSize:      16 << 10,
		WriteBufferSize:     4 << 10,
	}
	return &Client{
		hc:      &http.Client{Transport: tr, Timeout: o.Timeout},
		res:     res,
		ua:      o.UserAgent,
		maxBody: o.MaxBody,
	}
}

// Resolver exposes the underlying resolver.
func (c *Client) Resolver() *Resolver { return c.res }

// Fetch performs a GET and returns the status and body (size-limited).
func (c *Client) Fetch(ctx context.Context, scheme, host, path string) (int, []byte, error) {
	if path == "" {
		path = "/"
	}
	url := scheme + "://" + host + path
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("User-Agent", c.ua)
	req.Header.Set("Accept", "*/*")
	c.reqs.Add(1)

	resp, err := c.hc.Do(req)
	if err != nil {
		c.errs.Add(1)
		return 0, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, c.maxBody))
	if err != nil {
		return resp.StatusCode, body, err
	}
	return resp.StatusCode, body, nil
}

// FetchAuto tries https then falls back to http on connection/TLS errors.
func (c *Client) FetchAuto(ctx context.Context, host, path string) (string, int, []byte, error) {
	scheme := "https"
	code, body, err := c.Fetch(ctx, scheme, host, path)
	if err == nil {
		return scheme, code, body, nil
	}
	if !retryable(err) {
		return scheme, code, body, err
	}
	scheme = "http"
	code, body, err = c.Fetch(ctx, scheme, host, path)
	return scheme, code, body, err
}

func retryable(err error) bool {
	if err == nil {
		return false
	}
	var dns *net.DNSError
	if errors.As(err, &dns) {
		return false
	}
	msg := err.Error()
	for _, s := range []string{"tls:", "handshake", "EOF", "reset by peer", "connection refused", "timeout", "no such host", "certificate"} {
		if strings.Contains(msg, s) {
			return true
		}
	}
	return false
}

// Stats returns (requests, errors).
func (c *Client) Stats() (int64, int64) { return c.reqs.Load(), c.errs.Load() }
