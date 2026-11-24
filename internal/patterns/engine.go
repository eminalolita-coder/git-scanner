// Package patterns implements the secret-detection engine: a set of regex
// rules with optional entropy and keyword gates, plus de-duplication.
package patterns

import (
	"math"
	"regexp"
	"sort"
	"strings"
	"sync"
)

// Pattern is a single detection rule.
type Pattern struct {
	ID          string   `json:"id"`
	Description string   `json:"description"`
	Regex       string   `json:"regex"`
	SecretGroup int      `json:"secret_group"` // 0 = whole match
	Entropy     float64  `json:"entropy"`      // min Shannon entropy of the secret
	Keywords    []string `json:"keywords"`     // fast pre-filter (any-of, lowercase)
	Tags        []string `json:"tags"`
	Allowlist   []string `json:"allowlist"` // regexes that disqualify a match

	re    *regexp.Regexp
	allow []*regexp.Regexp
}

// RawMatch is a single detection before verification.
type RawMatch struct {
	Pattern *Pattern
	Secret  string
	Match   string
	Index   int
}

// Engine runs a compiled set of patterns over content.
type Engine struct {
	patterns      []*Pattern
	frozen        []*Pattern
	maxPerPattern int
	mu            sync.RWMutex
}

// NewEngine builds an engine. maxPerPattern limits hits per rule per chunk.
func NewEngine(maxPerPattern int) *Engine {
	if maxPerPattern <= 0 {
		maxPerPattern = 10
	}
	return &Engine{maxPerPattern: maxPerPattern}
}

// Add compiles and registers a pattern.
func (e *Engine) Add(p Pattern) error {
	re, err := regexp.Compile(p.Regex)
	if err != nil {
		return err
	}
	p.re = re
	for _, a := range p.Allowlist {
		ar, err := regexp.Compile(a)
		if err != nil {
			return err
		}
		p.allow = append(p.allow, ar)
	}
	e.mu.Lock()
	e.patterns = append(e.patterns, &p)
	e.mu.Unlock()
	return nil
}

// AddAll registers many patterns, returning the first error.
func (e *Engine) AddAll(ps []Pattern) error {
	for _, p := range ps {
		if err := e.Add(p); err != nil {
			return err
		}
	}
	return nil
}

// Count returns the number of registered patterns.
func (e *Engine) Count() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.patterns)
}

// Freeze snapshots the patterns so Scan can read them without locking. Call it
// after all Add/AddAll calls, before scanning in parallel.
func (e *Engine) Freeze() {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.frozen == nil {
		e.frozen = append([]*Pattern(nil), e.patterns...)
	}
}

// Scan runs all patterns over content and returns de-duplicated raw matches.
func (e *Engine) Scan(content []byte) []RawMatch {
	s := string(content)
	lower := strings.ToLower(s)
	rules := e.frozen
	if rules == nil {
		e.mu.RLock()
		rules = e.patterns
		e.mu.RUnlock()
	}

	var out []RawMatch
	seen := make(map[string]struct{})
	for _, p := range rules {
		if len(p.Keywords) > 0 && !containsAny(lower, p.Keywords) {
			continue
		}
		locs := p.re.FindAllStringSubmatchIndex(s, e.maxPerPattern)
		for _, loc := range locs {
			secret := group(s, loc, p.SecretGroup)
			if secret == "" {
				continue
			}
			if p.Entropy > 0 && Shannon(secret) < p.Entropy {
				continue
			}
			if allowlisted(secret, p.allow) {
				continue
			}
			key := p.ID + "\x00" + secret
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, RawMatch{
				Pattern: p,
				Secret:  secret,
				Match:   s[loc[0]:loc[1]],
				Index:   loc[0],
			})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Index < out[j].Index })
	return out
}

// ScanString is a convenience wrapper.
func (e *Engine) ScanString(s string) []RawMatch { return e.Scan([]byte(s)) }

func group(s string, loc []int, n int) string {
	if n <= 0 {
		return s[loc[0]:loc[1]]
	}
	i := 2 * n
	if i+1 >= len(loc) || loc[i] < 0 {
		return s[loc[0]:loc[1]]
	}
	return s[loc[i]:loc[i+1]]
}

func containsAny(lower string, keywords []string) bool {
	for _, k := range keywords {
		if strings.Contains(lower, k) {
			return true
		}
	}
	return false
}

func allowlisted(secret string, allow []*regexp.Regexp) bool {
	for _, re := range allow {
		if re.MatchString(secret) {
			return true
		}
	}
	return false
}

// Shannon returns the Shannon entropy (bits/char) of s.
func Shannon(s string) float64 {
	if s == "" {
		return 0
	}
	var counts [256]int
	for i := 0; i < len(s); i++ {
		counts[s[i]]++
	}
	var ent float64
	n := float64(len(s))
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		ent -= p * math.Log2(p)
	}
	return ent
}
