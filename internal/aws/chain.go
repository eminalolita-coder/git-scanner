package aws

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// ChainOptions configures an assume-role chain walk.
type ChainOptions struct {
	MaxDepth    int
	ExternalID  string
	Duration    int
	SessionName string
	Match       string // regex filter on role name/arn
}

// ChainLink is one successful (or attempted) hop in a privilege chain.
type ChainLink struct {
	Depth      int       `json:"depth"`
	From       string    `json:"from"`
	RoleName   string    `json:"role_name"`
	RoleARN    string    `json:"role_arn"`
	AssumedARN string    `json:"assumed_arn,omitempty"`
	ExpiresAt  time.Time `json:"expires_at,omitempty"`
	Err        string    `json:"error,omitempty"`

	Creds AssumedCredentials `json:"-"`
}

// AssumeChains walks role-to-role assumption starting from base credentials.
// It tries each candidate role, and on success recurses up to MaxDepth.
func AssumeChains(ctx context.Context, client *http.Client, base Credentials, roles []Role, opts ChainOptions) []ChainLink {
	if opts.MaxDepth <= 0 {
		opts.MaxDepth = 2
	}
	var filter *regexp.Regexp
	if opts.Match != "" {
		if re, err := regexp.Compile(opts.Match); err == nil {
			filter = re
		}
	}

	type node struct {
		creds Credentials
		from  string
		depth int
	}

	startARN := "base"
	if id, err := GetCallerIdentity(ctx, client, base); err == nil {
		startARN = id.ARN
	}

	visited := map[string]bool{}
	queue := []node{{creds: base, from: startARN, depth: 0}}
	var out []ChainLink

	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		if cur.depth >= opts.MaxDepth {
			continue
		}
		for _, r := range roles {
			if visited[r.ARN] {
				continue
			}
			if filter != nil && !filter.MatchString(r.Name) && !filter.MatchString(r.ARN) {
				continue
			}
			res, err := AssumeRole(ctx, client, cur.creds, r.ARN, opts.SessionName, opts.ExternalID, opts.Duration)
			link := ChainLink{Depth: cur.depth + 1, From: cur.from, RoleName: r.Name, RoleARN: r.ARN}
			if err != nil {
				link.Err = err.Error()
				out = append(out, link)
				// do not mark visited: another path may succeed
				continue
			}
			visited[r.ARN] = true
			link.AssumedARN = res.ARN
			link.ExpiresAt = res.Credentials.Expiration
			link.Creds = res.Credentials
			out = append(out, link)
			queue = append(queue, node{creds: res.Credentials.Credentials(base.region("us-east-1")), from: res.ARN, depth: cur.depth + 1})
		}
	}
	return out
}

// ListRolesForChain returns candidate roles for an assume-role walk.
func ListRolesForChain(ctx context.Context, client *http.Client, c Credentials) []Role {
	return listIAMRoles(ctx, client, c)
}

// SuccessfulChains returns only the links that produced credentials.
func SuccessfulChains(links []ChainLink) []ChainLink {
	var out []ChainLink
	for _, l := range links {
		if l.Err == "" {
			out = append(out, l)
		}
	}
	return out
}

// EscalationRoutes returns, for each identity, the roles it can reach.
func EscalationRoutes(links []ChainLink) map[string][]string {
	routes := map[string][]string{}
	for _, l := range links {
		if l.Err == "" {
			routes[l.From] = append(routes[l.From], l.RoleName)
		}
	}
	return routes
}

// TrustsCaller is a best-effort check that a trust policy references the caller.
func TrustsCaller(policy, account, callerARN string) bool {
	if policy == "" {
		return false
	}
	if account != "" && strings.Contains(policy, "::"+account+":root") {
		return true
	}
	if callerARN != "" && strings.Contains(policy, callerARN) {
		return true
	}
	return strings.Contains(policy, "\"AWS\":\"*\"") || strings.Contains(policy, `"AWS":"*"`)
}

// DescribeChain renders a chain as an arrow string.
func DescribeChain(links []ChainLink) []string {
	var out []string
	for _, l := range links {
		if l.Err != "" {
			continue
		}
		out = append(out, fmt.Sprintf("%s -> %s", shorten(l.From), l.RoleName))
	}
	return out
}

func shorten(arn string) string {
	if i := strings.LastIndex(arn, "/"); i >= 0 {
		return arn[i+1:]
	}
	if strings.HasPrefix(arn, "arn:") {
		parts := strings.Split(arn, ":")
		return parts[len(parts)-1]
	}
	return arn
}
