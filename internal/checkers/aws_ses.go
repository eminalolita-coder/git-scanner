package checkers

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/smtp"
	"strings"
	"time"
)

func init() {
	Register(&sesSMTPChecker{})
}

// sesSMTPChecker verifies Amazon SES SMTP credentials by authenticating to
// the regional SES SMTP endpoint. This is independent of the STS/IAM check:
// an SES SMTP password is derived from a secret key and only works for SMTP,
// so a valid SMTP login proves the credential is live even when the API keys
// are unusable.
type sesSMTPChecker struct{}

func (s *sesSMTPChecker) Name() string { return "aws-ses-smtp" }

func (s *sesSMTPChecker) Match(ruleID string, tags []string) bool {
	// Only rules that carry an actual username (and, for the pair form, a
	// password). The endpoint and the lone password are indicators, not
	// credentials.
	switch ruleID {
	case "aws-ses-smtp-credential", "aws-ses-smtp-username":
		return true
	}
	return false
}

// sesRegions are tried in parallel; the first successful login wins.
var sesRegions = []string{
	"us-east-1", "us-east-2", "us-west-2", "eu-west-1", "eu-central-1",
	"eu-north-1", "ap-southeast-1", "ap-southeast-2", "ap-northeast-1",
	"ap-south-1", "sa-east-1", "ca-central-1",
}

func (s *sesSMTPChecker) Check(ctx context.Context, secret string, meta map[string]string) Result {
	user, pass := SplitSESPair(secret)
	if pass == "" {
		// aws-ses-smtp-username: the password was paired from the same file
		if p := meta["ses_password"]; p != "" && len(secret) == 20 {
			user, pass = secret, p
		}
	}
	if user == "" || pass == "" {
		return Result{Err: "missing SES SMTP username/password pair"}
	}
	regions := sesRegions
	if r := meta["region"]; r != "" {
		regions = append([]string{r}, regions...)
	}
	type attempt struct {
		region string
		err    error
	}
	ch := make(chan attempt, len(regions))
	for _, r := range regions {
		go func(region string) {
			ch <- attempt{region, sesAuth(ctx, "email-smtp."+region+".amazonaws.com:587", user, pass)}
		}(r)
	}
	var firstErr error
	for i := 0; i < len(regions); i++ {
		select {
		case a := <-ch:
			if a.err == nil {
				return Result{
					Verified: true,
					Identity: "SES SMTP " + a.region,
					Meta:     map[string]string{"region": a.region, "smtp_user": user},
				}
			}
			if firstErr == nil {
				firstErr = a.err
			}
		case <-ctx.Done():
			return Result{Err: "timeout"}
		}
	}
	return Result{Err: firstErr.Error()}
}

// SplitSESPair splits "AKIA…<separator>password" into username and password.
// SES SMTP usernames are the IAM access key id (20 chars) and the password is
// 44 characters of base64. Quotes, commas and the assignment "=" are
// separators; the "=" that pads the password is kept.
func SplitSESPair(secret string) (string, string) {
	const seps = "\"'`,;:= \t"
	s := strings.TrimSpace(secret)
	s = strings.TrimLeft(s, seps)
	if len(s) < 20 {
		return "", ""
	}
	prefix := strings.ToUpper(s[:4])
	if prefix != "AKIA" && prefix != "ASIA" {
		return "", ""
	}
	user := s[:20]
	rest := strings.TrimLeft(s[20:], seps)
	if i := strings.IndexAny(rest, "\"'`,; \t"); i >= 0 {
		rest = rest[:i]
	}
	rest = strings.TrimRight(rest, "\"'`,; \t")
	if len(rest) < 16 {
		return "", ""
	}
	return user, rest
}

// sesAuth performs an SMTP AUTH against a SES endpoint over STARTTLS.
func sesAuth(ctx context.Context, addr, user, pass string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	d := net.Dialer{Timeout: 8 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	defer conn.Close()

	deadline := time.Now().Add(8 * time.Second)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = conn.SetDeadline(deadline)

	c, err := smtp.NewClient(conn, host)
	if err != nil {
		return err
	}
	defer c.Close()
	if ok, _ := c.Extension("STARTTLS"); !ok {
		return errors.New("server does not offer STARTTLS")
	}
	if err := c.StartTLS(&tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}); err != nil {
		return err
	}
	if err := c.Auth(smtp.PlainAuth("", user, pass, host)); err != nil {
		return err
	}
	return c.Quit()
}
