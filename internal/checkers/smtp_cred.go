package checkers

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/smtp"
	"time"
)

func init() {
	Register(&smtpCredChecker{})
}

// smtpCredChecker verifies a generic SMTP credential found next to an SMTP
// provider host. The scanner pairs the host, port and user from the same file,
// so nothing depends on the variable names used.
type smtpCredChecker struct{}

func (s *smtpCredChecker) Name() string { return "smtp-cred" }

func (s *smtpCredChecker) Match(ruleID string, tags []string) bool {
	return ruleID == "smtp-credential"
}

func (s *smtpCredChecker) Check(ctx context.Context, secret string, meta map[string]string) Result {
	if meta == nil {
		return Result{Err: "no context"}
	}
	host, user := meta["host"], meta["smtp_user"]
	if host == "" || user == "" {
		return Result{Err: "missing host or user in context"}
	}
	port := meta["port"]
	if port == "" {
		port = "587"
	}
	err := smtpAuth(ctx, net.JoinHostPort(host, port), host, user, secret, port != "465")
	if err == nil {
		return Result{Verified: true, Identity: host + ":" + port}
	}
	// many providers also listen on implicit TLS 465
	if port != "465" {
		if err2 := smtpAuth(ctx, net.JoinHostPort(host, "465"), host, user, secret, false); err2 == nil {
			return Result{Verified: true, Identity: host + ":465"}
		}
	}
	return Result{Err: err.Error()}
}

// smtpAuth logs in, optionally upgrading with STARTTLS first.
func smtpAuth(ctx context.Context, addr, host, user, pass string, starttls bool) error {
	d := net.Dialer{Timeout: 8 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	defer conn.Close()

	deadline := time.Now().Add(10 * time.Second)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = conn.SetDeadline(deadline)

	var c *smtp.Client
	if starttls {
		c, err = smtp.NewClient(conn, host)
		if err != nil {
			return err
		}
		defer c.Close()
		if ok, _ := c.Extension("STARTTLS"); !ok {
			return errors.New("no STARTTLS")
		}
		if err := c.StartTLS(&tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}); err != nil {
			return err
		}
	} else {
		tconn := tls.Client(conn, &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12})
		if err := tconn.HandshakeContext(ctx); err != nil {
			return err
		}
		c, err = smtp.NewClient(tconn, host)
		if err != nil {
			return err
		}
		defer c.Close()
	}
	if err := c.Auth(smtp.PlainAuth("", user, pass, host)); err != nil {
		return err
	}
	return c.Quit()
}
