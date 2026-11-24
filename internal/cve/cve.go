// Package cve probes targets for well-known CVEs and cloud-metadata
// exposure (exposed .git, SSRF sinks, Next.js image optimizer, etc.).
package cve

import (
	"context"
	"net/http"
	"strings"
	"time"
)

// CloudMetadataURLs are the common SSRF targets for credential theft.
var CloudMetadataURLs = []string{
	"http://169.254.169.254/latest/meta-data/iam/security-credentials/",
	"http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
	"http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
}

// HighValuePaths are files/config an SSRF or path-check may reach.
var HighValuePaths = []string{
	"/.git/HEAD",
	"/.git/config",
	"/.env",
	"/actuator/env",
	"/actuator/health",
	"/debug/pprof/",
	"/server-info",
	"/wp-config.php",
	"/composer.json",
	"/package.json",
}

// Result is the outcome of a probe.
type Result struct {
	URL    string
	Status int
	Match  bool
	Body   string
}

// Probe fetches a URL and reports whether it looks reachable/notable.
func Probe(ctx context.Context, client *http.Client, rawURL string) Result {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return Result{URL: rawURL}
	}
	req.Header.Set("User-Agent", "git-scanner")
	resp, err := client.Do(req)
	if err != nil {
		return Result{URL: rawURL}
	}
	defer resp.Body.Close()
	buf := make([]byte, 2048)
	n, _ := resp.Body.Read(buf)
	body := string(buf[:n])
	return Result{
		URL:    rawURL,
		Status: resp.StatusCode,
		Match:  resp.StatusCode == 200 && notable(body),
		Body:   strings.TrimSpace(body),
	}
}

func notable(body string) bool {
	markers := []string{"ref:", "service_account", "AccessKeyId", "DB_", "APP_KEY", "gitdir"}
	for _, m := range markers {
		if strings.Contains(body, m) {
			return true
		}
	}
	return true
}
