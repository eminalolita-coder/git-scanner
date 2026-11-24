// Package scanners holds standalone scan helpers: .env cracking, archive
// walking and target validation.
package scanners

import (
	"bufio"
	"bytes"
	"regexp"
	"strings"
)

// EnvPaths are the common locations where .env files leak.
var EnvPaths = []string{
	"/.env",
	"/.env.local",
	"/.env.production",
	"/.env.development",
	"/.env.staging",
	"/.env.backup",
	"/.env.example",
	"/.env.old",
	"/.env.bak",
	"/config/.env",
	"/app/.env",
	"/backend/.env",
	"/laravel/.env",
	"/private/.env",
	"/current/.env",
	"/public/.env",
	"/shared/.env",
	"/var/www/.env",
	"/srv/app/.env",
	"/opt/app/.env",
	"/.git/config",
	"/.git/HEAD",
	"/package.json",
	"/config/database.yml",
	"/appsettings.json",
	"/docker-compose.yml",
	"/.dockerenv",
}

var reAssign = regexp.MustCompile(`^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$`)

func init() {
	// fold in the additional web paths recovered from the reference binary
	EnvPaths = append(EnvPaths, WebPaths...)
}

// ParseEnv extracts KEY=VALUE pairs from a .env style document.
func ParseEnv(content []byte) map[string]string {
	out := make(map[string]string)
	sc := bufio.NewScanner(bytes.NewReader(content))
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		m := reAssign.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		val := strings.Trim(m[2], `"'`)
		out[m[1]] = val
	}
	return out
}

// CandidateURLs builds absolute URLs for every EnvPath on a base host.
func CandidateURLs(base string) []string {
	base = strings.TrimRight(base, "/")
	out := make([]string, 0, len(EnvPaths))
	for _, p := range EnvPaths {
		out = append(out, base+p)
	}
	return out
}
