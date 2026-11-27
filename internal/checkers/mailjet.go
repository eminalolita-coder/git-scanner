package checkers

import (
	"context"
	"fmt"
)

func init() {
	Register(&mailjetChecker{})
}

// mailjetChecker verifies a Mailjet API key pair. Mailjet Basic auth is
// base64(API_KEY:SECRET_KEY): a single key alone always answers 401, so the
// pair has to be assembled. Both halves are 32 hex chars on adjacent lines
// (MJ_APIKEY_PUBLIC / _PRIVATE), which the scanner pairs into meta["partner"].
type mailjetChecker struct{}

func (m *mailjetChecker) Name() string { return "mailjet" }

func (m *mailjetChecker) Match(ruleID string, tags []string) bool {
	return ruleID == "mailjet-key"
}

func (m *mailjetChecker) Check(ctx context.Context, secret string, meta map[string]string) Result {
	partner := ""
	if meta != nil {
		partner = meta["partner"]
	}
	if partner == "" {
		return Result{Err: "missing paired key (needs API_KEY + SECRET_KEY)"}
	}
	// the pair has no inherent order; try both orders
	combos := [][2]string{{secret, partner}, {partner, secret}}
	var lastErr string
	for _, c := range combos {
		code, _, err := getBody(ctx, "https://api.mailjet.com/v3/REST/user",
			map[string]string{"Authorization": "Basic " + base64Encode(c[0]+":"+c[1])})
		if err != nil {
			lastErr = err.Error()
			continue
		}
		if ok(code) {
			return Result{Verified: true, Identity: "mailjet key pair"}
		}
		lastErr = fmt.Sprintf("http %d", code)
	}
	return Result{Err: lastErr}
}
