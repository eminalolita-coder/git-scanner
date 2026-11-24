package jscracker

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

var (
	reScript = regexp.MustCompile(`(?is)<script[^>]*\ssrc=["']([^"']+)["']`)
	reInline = regexp.MustCompile(`(?is)<script[^>]*>(.*?)</script>`)
)

// Result aggregates everything found in a JS surface.
type Result struct {
	Endpoints  []string          `json:"endpoints"`
	Paths      []string          `json:"paths"`
	SourceMaps []string          `json:"source_maps"`
	Subdomains []string          `json:"subdomains"`
	Leaks      map[string]string `json:"leaks"`
	Scripts    []string          `json:"scripts"`
}

// Options bounds a crawl.
type Options struct {
	MaxScripts int
	MaxBytes   int64
	FollowMaps bool
}

// DefaultOptions returns conservative limits.
func DefaultOptions() Options {
	return Options{MaxScripts: 40, MaxBytes: 5 << 20, FollowMaps: true}
}

// AnalyzeURL fetches a page, discovers its scripts, fetches them and extracts
// endpoints, config leaks, source maps and subdomains.
func AnalyzeURL(ctx context.Context, client *http.Client, pageURL string, o Options) (Result, error) {
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	res := Result{Leaks: map[string]string{}}

	page, err := fetch(ctx, client, pageURL, o.MaxBytes)
	if err != nil {
		return res, err
	}

	base, _ := url.Parse(pageURL)
	scripts := resolveAll(base, reScript.FindAllStringSubmatch(string(page), -1))

	// inline scripts too
	for _, m := range reInline.FindAllStringSubmatch(string(page), -1) {
		harvest(&res, []byte(m[1]))
	}

	for i, s := range scripts {
		if i >= o.MaxScripts {
			break
		}
		res.Scripts = append(res.Scripts, s)
		js, err := fetch(ctx, client, s, o.MaxBytes)
		if err != nil {
			continue
		}
		harvest(&res, js)
		if o.FollowMaps {
			for _, m := range SourceMaps(js) {
				mapURL := m
				if !strings.HasPrefix(mapURL, "http") {
					if u, err := base.Parse(m); err == nil {
						mapURL = u.String()
					}
				}
				if body, err := fetch(ctx, client, mapURL, o.MaxBytes); err == nil {
					res.SourceMaps = append(res.SourceMaps, mapURL)
					harvest(&res, body)
				}
			}
		}
	}
	res.Endpoints = unique(res.Endpoints)
	res.Paths = unique(res.Paths)
	res.Subdomains = unique(res.Subdomains)
	res.SourceMaps = unique(res.SourceMaps)
	return res, nil
}

// ScriptsFromHTML extracts absolute script URLs from an HTML document,
// resolving relative references against base.
func ScriptsFromHTML(base *url.URL, html []byte) []string {
	return unique(resolveAll(base, reScript.FindAllStringSubmatch(string(html), -1)))
}

// IsHTML reports whether a body looks like an HTML document.
func IsHTML(body []byte) bool {
	probe := body
	if len(probe) > 2048 {
		probe = probe[:2048]
	}
	s := strings.ToLower(string(probe))
	return strings.Contains(s, "<html") || strings.Contains(s, "<script") || strings.Contains(s, "<!doctype")
}

func harvest(res *Result, js []byte) {
	res.Endpoints = append(res.Endpoints, Endpoints(js)...)
	res.Paths = append(res.Paths, Paths(js)...)
	res.Subdomains = append(res.Subdomains, Subdomains(js)...)
	for k, v := range ConfigLeaks(js) {
		res.Leaks[k] = v
	}
}

func fetch(ctx context.Context, client *http.Client, rawURL string, max int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "git-scanner")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if max <= 0 {
		max = 5 << 20
	}
	return io.ReadAll(io.LimitReader(resp.Body, max))
}

func resolveAll(base *url.URL, matches [][]string) []string {
	var out []string
	for _, m := range matches {
		if len(m) < 2 {
			continue
		}
		src := strings.TrimSpace(m[1])
		if strings.HasPrefix(src, "http") {
			out = append(out, src)
			continue
		}
		if base != nil {
			if u, err := base.Parse(src); err == nil {
				out = append(out, u.String())
			}
		}
	}
	return out
}
