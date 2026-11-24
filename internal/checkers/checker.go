// Package checkers verifies detected secrets against their provider APIs.
package checkers

import (
	"context"
	"net/http"
	"sort"
	"strings"
	"time"
)

// Result is the outcome of a verification attempt.
type Result struct {
	Verified bool              `json:"verified"`
	Identity string            `json:"identity,omitempty"`
	Meta     map[string]string `json:"meta,omitempty"`
	Err      string            `json:"error,omitempty"`
}

// Checker verifies one family of secrets.
type Checker interface {
	// Name identifies the checker.
	Name() string
	// Match reports whether this checker handles the given rule id / tags.
	Match(ruleID string, tags []string) bool
	// Check performs verification. meta may hold auxiliary values (e.g. a
	// companion secret needed to complete the check).
	Check(ctx context.Context, secret string, meta map[string]string) Result
}

var registry []Checker

// Register adds a checker to the global registry.
func Register(c Checker) { registry = append(registry, c) }

// For returns the checkers matching a rule, most specific first.
func For(ruleID string, tags []string) []Checker {
	var out []Checker
	for _, c := range registry {
		if c.Match(ruleID, tags) {
			out = append(out, c)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Name() < out[j].Name() })
	return out
}

// Names lists registered checker names.
func Names() []string {
	var out []string
	for _, c := range registry {
		out = append(out, c.Name())
	}
	sort.Strings(out)
	return out
}

// httpChecker is a table-driven checker based on an HTTP probe.
type httpChecker struct {
	name    string
	tags    map[string]bool
	ruleIDs map[string]bool
	fn      func(ctx context.Context, secret string) Result
}

func (h *httpChecker) Name() string { return h.name }

func (h *httpChecker) Match(ruleID string, tags []string) bool {
	if h.ruleIDs[ruleID] {
		return true
	}
	for _, t := range tags {
		if h.tags[strings.ToLower(t)] {
			return true
		}
	}
	return false
}

func (h *httpChecker) Check(ctx context.Context, secret string, _ map[string]string) Result {
	if h.fn == nil {
		return Result{}
	}
	return h.fn(ctx, secret)
}

func tagsOf(list ...string) map[string]bool {
	m := make(map[string]bool, len(list))
	for _, t := range list {
		m[t] = true
	}
	return m
}

// DefaultTimeout is used when a checker needs a deadline.
const DefaultTimeout = 10 * time.Second

// SetHTTPClient overrides the client used by HTTP-based checkers, e.g. to plug
// in a proxy-aware transport. A nil client is ignored.
func SetHTTPClient(c *http.Client) {
	if c != nil {
		httpClient = c
	}
}
