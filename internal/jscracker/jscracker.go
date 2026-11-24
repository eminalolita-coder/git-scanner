// Package jscracker analyses JavaScript bundles to discover endpoints,
// subdomains and configuration leaks.
package jscracker

import (
	"regexp"
	"sort"
)

var (
	reURL    = regexp.MustCompile(`https?://[A-Za-z0-9.\-]+(?::\d+)?(?:/[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]*)?`)
	rePath   = regexp.MustCompile(`["'](/[A-Za-z0-9._~/-]{2,80})["']`)
	reAPIKey = regexp.MustCompile(`(?i)["']?([A-Za-z0-9_]*(?:api[_-]?key|token|secret|access[_-]?key)[A-Za-z0-9_]*)["']?\s*[:=]\s*["']([A-Za-z0-9_\-/+=.]{8,})["']`)
	reSource = regexp.MustCompile(`sourceMappingURL=([^\s*]+)`)
)

// Endpoints returns the unique URLs referenced by a JS bundle.
func Endpoints(js []byte) []string {
	return unique(reURL.FindAllString(string(js), -1))
}

// Paths returns the unique root-relative paths referenced by a JS bundle.
func Paths(js []byte) []string {
	var out []string
	for _, m := range rePath.FindAllSubmatch(js, -1) {
		out = append(out, string(m[1]))
	}
	return unique(out)
}

// SourceMaps returns referenced source map URLs.
func SourceMaps(js []byte) []string {
	var out []string
	for _, m := range reSource.FindAllSubmatch(js, -1) {
		out = append(out, string(m[1]))
	}
	return unique(out)
}

// ConfigLeaks returns key/value pairs that look like embedded configuration.
func ConfigLeaks(js []byte) map[string]string {
	out := map[string]string{}
	for _, m := range reAPIKey.FindAllSubmatch(js, -1) {
		out[string(m[1])] = string(m[2])
	}
	return out
}

// Subdomains extracts candidate hostnames from a bundle.
func Subdomains(js []byte) []string {
	var out []string
	for _, u := range Endpoints(js) {
		if h := indexHost(u); h != "" {
			out = append(out, h)
		}
	}
	return unique(out)
}

func indexHost(u string) string {
	// strip scheme
	s := u
	if i := indexOf(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	for i := 0; i < len(s); i++ {
		if s[i] == '/' || s[i] == ':' {
			return s[:i]
		}
	}
	return s
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func unique(in []string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, s := range in {
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}
