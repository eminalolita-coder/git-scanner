package scanner

import (
	"context"
	"crypto/tls"
	"net/http"
	"time"
)

var httpClient = &http.Client{
	Timeout: 30 * time.Second,
	Transport: &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		MaxIdleConns:        200,
		MaxIdleConnsPerHost: 20,
	},
}

func newRequest(ctx context.Context, url string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "git-scanner/1.0")
	req.Header.Set("Accept", "*/*")
	return req, nil
}
