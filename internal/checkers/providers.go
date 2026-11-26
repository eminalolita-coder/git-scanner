package checkers

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/smtp"
	"strings"
)

var httpClient = &http.Client{
	Timeout: DefaultTimeout,
	Transport: &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		MaxIdleConnsPerHost: 4,
	},
}

// getJSON performs a GET with optional headers and decodes JSON into out.
// It returns the HTTP status code.
func getJSON(ctx context.Context, url string, hdr map[string]string, out any) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("User-Agent", "git-scanner")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if out != nil && resp.StatusCode < 400 {
		_ = json.NewDecoder(resp.Body).Decode(out)
	}
	return resp.StatusCode, nil
}

func ok(code int) bool { return code >= 200 && code < 300 }

// getBody performs a GET and returns the status and body.
func getBody(ctx context.Context, url string, hdr map[string]string) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("User-Agent", "git-scanner")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	return resp.StatusCode, body, nil
}

// classifyGoogleKey interprets a Google API response for a key.
func classifyGoogleKey(code int, body []byte) Result {
	switch {
	case ok(code):
		return Result{Verified: true}
	case code == 400 || code == 403:
		s := string(body)
		if strings.Contains(s, "API_KEY_INVALID") || strings.Contains(s, "API key not valid") {
			return Result{Err: "key invalid"}
		}
		// key exists but the API/permissions are restricted
		return Result{Verified: true, Identity: "restricted",
			Meta: map[string]string{"http_status": fmt.Sprintf("%d", code)}}
	}
	return Result{Err: fmt.Sprintf("status %d", code)}
}

func init() {
	// GitHub
	Register(&httpChecker{
		name: "github", tags: tagsOf("github"),
		ruleIDs: tags0("github-pat", "github-oauth", "github-fine-grained-pat"),
		fn: func(ctx context.Context, secret string) Result {
			var u struct {
				Login string `json:"login"`
			}
			code, err := getJSON(ctx, "https://api.github.com/user", map[string]string{
				"Authorization": "token " + secret, "Accept": "application/vnd.github+json",
			}, &u)
			if err != nil {
				return Result{Err: err.Error()}
			}
			return Result{Verified: ok(code), Identity: u.Login}
		},
	})

	// GitLab
	Register(&httpChecker{
		name: "gitlab", tags: tagsOf("gitlab"),
		fn: func(ctx context.Context, secret string) Result {
			var u struct {
				Username string `json:"username"`
			}
			code, err := getJSON(ctx, "https://gitlab.com/api/v4/user", map[string]string{
				"Authorization": "Bearer " + secret,
			}, &u)
			if err != nil {
				return Result{Err: err.Error()}
			}
			return Result{Verified: ok(code), Identity: u.Username}
		},
	})

	// Slack
	Register(&httpChecker{
		name: "slack", tags: tagsOf("slack"),
		fn: func(ctx context.Context, secret string) Result {
			var r struct {
				OK   bool   `json:"ok"`
				User string `json:"user"`
				Team string `json:"team"`
			}
			_, err := getJSON(ctx, "https://slack.com/api/auth.test", map[string]string{
				"Authorization": "Bearer " + secret,
			}, &r)
			if err != nil {
				return Result{Err: err.Error()}
			}
			return Result{Verified: r.OK, Identity: r.Team + "/" + r.User}
		},
	})

	// Stripe
	Register(&httpChecker{
		name: "stripe", tags: tagsOf("stripe"),
		fn: func(ctx context.Context, secret string) Result {
			code, err := getJSON(ctx, "https://api.stripe.com/v1/balance", map[string]string{
				"Authorization": "Bearer " + secret,
			}, nil)
			if err != nil {
				return Result{Err: err.Error()}
			}
			return Result{Verified: ok(code)}
		},
	})

	// SendGrid
	Register(&httpChecker{
		name: "sendgrid", tags: tagsOf("sendgrid"),
		fn: func(ctx context.Context, secret string) Result {
			code, err := getJSON(ctx, "https://api.sendgrid.com/v3/scopes", map[string]string{
				"Authorization": "Bearer " + secret,
			}, nil)
			if err != nil {
				return Result{Err: err.Error()}
			}
			return Result{Verified: ok(code)}
		},
	})

	// OpenAI
	Register(&httpChecker{
		name: "openai", tags: tagsOf("openai"),
		fn: func(ctx context.Context, secret string) Result {
			code, err := getJSON(ctx, "https://api.openai.com/v1/models", map[string]string{
				"Authorization": "Bearer " + secret,
			}, nil)
			if err != nil {
				return Result{Err: err.Error()}
			}
			return Result{Verified: ok(code)}
		},
	})

	// Anthropic
	Register(&httpChecker{
		name: "anthropic", tags: tagsOf("anthropic"),
		fn: func(ctx context.Context, secret string) Result {
			code, err := getJSON(ctx, "https://api.anthropic.com/v1/models", map[string]string{
				"x-api-key": secret, "anthropic-version": "2023-06-01",
			}, nil)
			if err != nil {
				return Result{Err: err.Error()}
			}
			return Result{Verified: ok(code)}
		},
	})

	// DigitalOcean
	Register(&httpChecker{
		name: "digitalocean", tags: tagsOf("digitalocean"),
		fn: func(ctx context.Context, secret string) Result {
			var r struct {
				Account struct {
					Email string `json:"email"`
				} `json:"account"`
			}
			code, err := getJSON(ctx, "https://api.digitalocean.com/v2/account", map[string]string{
				"Authorization": "Bearer " + secret,
			}, &r)
			if err != nil {
				return Result{Err: err.Error()}
			}
			return Result{Verified: ok(code), Identity: r.Account.Email}
		},
	})

	// Telegram
	Register(&httpChecker{
		name: "telegram", tags: tagsOf("telegram"),
		fn: func(ctx context.Context, secret string) Result {
			var r struct {
				OK     bool `json:"ok"`
				Result struct {
					Username string `json:"username"`
				} `json:"result"`
			}
			_, err := getJSON(ctx, "https://api.telegram.org/bot"+secret+"/getMe", nil, &r)
			if err != nil {
				return Result{Err: err.Error()}
			}
			return Result{Verified: r.OK, Identity: r.Result.Username}
		},
	})

	// Discord
	Register(&httpChecker{
		name: "discord", tags: tagsOf("discord"),
		fn: func(ctx context.Context, secret string) Result {
			var r struct {
				Username string `json:"username"`
			}
			code, err := getJSON(ctx, "https://discord.com/api/v10/users/@me", map[string]string{
				"Authorization": "Bot " + secret,
			}, &r)
			if err != nil {
				return Result{Err: err.Error()}
			}
			return Result{Verified: ok(code), Identity: r.Username}
		},
	})

	// Vercel
	Register(&httpChecker{
		name: "vercel", tags: tagsOf("vercel"),
		fn: func(ctx context.Context, secret string) Result {
			code, err := getJSON(ctx, "https://api.vercel.com/v2/user", map[string]string{
				"Authorization": "Bearer " + secret,
			}, nil)
			if err != nil {
				return Result{Err: err.Error()}
			}
			return Result{Verified: ok(code)}
		},
	})

	// Mailgun
	Register(&httpChecker{
		name: "mailgun", tags: tagsOf("mailgun"),
		fn: func(ctx context.Context, secret string) Result {
			code, err := getJSON(ctx, "https://api.mailgun.net/v3/domains", map[string]string{
				"Authorization": "Basic " + basicAuth("api", secret),
			}, nil)
			if err != nil {
				return Result{Err: err.Error()}
			}
			return Result{Verified: ok(code)}
		},
	})

	// New Relic
	Register(&httpChecker{
		name: "newrelic", tags: tagsOf("newrelic"),
		fn: func(ctx context.Context, secret string) Result {
			code, err := getJSON(ctx, "https://api.newrelic.com/v2/users.json", map[string]string{
				"API-Key": secret,
			}, nil)
			if err != nil {
				return Result{Err: err.Error()}
			}
			return Result{Verified: ok(code)}
		},
	})

	// Google API key
	Register(&httpChecker{
		name: "gcp", tags: nil,
		ruleIDs: tags0("gcp-api-key"),
		fn: func(ctx context.Context, secret string) Result {
			code, body, err := getBody(ctx, "https://www.googleapis.com/discovery/v1/apis?key="+secret, nil)
			if err != nil {
				return Result{Err: err.Error()}
			}
			return classifyGoogleKey(code, body)
		},
	})

	// Firebase Realtime Database
	Register(&httpChecker{
		name: "firebase", tags: tagsOf("firebase"),
		ruleIDs: tags0("firebase-host"),
		fn: func(ctx context.Context, secret string) Result {
			host := secret
			if !strings.Contains(host, ".") {
				host += ".firebaseio.com"
			}
			code, _, err := getBody(ctx, "https://"+host+"/.json?shallow=true", nil)
			if err != nil {
				return Result{Err: err.Error()}
			}
			switch {
			case ok(code):
				return Result{Verified: true, Identity: host}
			case code == 401, code == 403:
				return Result{Verified: true, Identity: host + " (rules-restricted)",
					Meta: map[string]string{"http_status": fmt.Sprintf("%d", code)}}
			}
			return Result{Err: fmt.Sprintf("status %d", code)}
		},
	})

	// SMTP (passive-ish): secret must be user:pass@host:port or user:pass
	Register(&smtpChecker{name: "smtp", tags: tagsOf("smtp")})
}

func tags0(ids ...string) map[string]bool {
	m := make(map[string]bool, len(ids))
	for _, id := range ids {
		m[id] = true
	}
	return m
}

func basicAuth(user, pass string) string {
	return base64Encode(user + ":" + pass)
}

func base64Encode(s string) string {
	const tbl = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	var b strings.Builder
	for i := 0; i < len(s); i += 3 {
		var n uint32
		rem := len(s) - i
		n = uint32(s[i]) << 16
		if rem > 1 {
			n |= uint32(s[i+1]) << 8
		}
		if rem > 2 {
			n |= uint32(s[i+2])
		}
		b.WriteByte(tbl[(n>>18)&0x3f])
		b.WriteByte(tbl[(n>>12)&0x3f])
		if rem > 1 {
			b.WriteByte(tbl[(n>>6)&0x3f])
		} else {
			b.WriteByte('=')
		}
		if rem > 2 {
			b.WriteByte(tbl[n&0x3f])
		} else {
			b.WriteByte('=')
		}
	}
	return b.String()
}

type smtpChecker struct {
	name string
	tags map[string]bool
}

func (s *smtpChecker) Name() string { return s.name }
func (s *smtpChecker) Match(_ string, tags []string) bool {
	for _, t := range tags {
		if s.tags[t] {
			return true
		}
	}
	return false
}

func (s *smtpChecker) Check(_ context.Context, secret string, meta map[string]string) Result {
	host := meta["host"]
	port := meta["port"]
	if host == "" {
		return Result{}
	}
	if port == "" {
		port = "587"
	}
	user, pass, _ := strings.Cut(secret, ":")
	addr := net.JoinHostPort(host, port)
	c, err := smtp.Dial(addr)
	if err != nil {
		return Result{Err: err.Error()}
	}
	defer c.Close()
	if err := c.Hello("git-scanner"); err != nil {
		return Result{Err: err.Error()}
	}
	// Opportunistic STARTTLS: many servers require it before AUTH.
	if err := c.StartTLS(&tls.Config{ServerName: host, InsecureSkipVerify: true}); err == nil {
		// upgraded
	}
	if err := c.Auth(smtp.PlainAuth("", user, pass, host)); err != nil {
		return Result{Err: err.Error()}
	}
	return Result{Verified: true, Identity: user}
}
