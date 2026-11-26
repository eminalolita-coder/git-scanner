package aws

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
)

// SESAccount describes the SES state reachable with a set of credentials.
type SESAccount struct {
	Region           string   `json:"region"`
	SendingEnabled   bool     `json:"sending_enabled"`
	ProductionAccess bool     `json:"production_access"`
	Sandbox          bool     `json:"sandbox"`
	Max24HourSend    float64  `json:"max_24_hour_send"`
	MaxSendRate      float64  `json:"max_send_rate"`
	SentLast24Hours  float64  `json:"sent_last_24_hours"`
	Identities       []string `json:"identities"`
}

// SESAccountInfo calls ses:GetAccount (SES v2) and ses:ListEmailIdentities.
// It proves SES access specifically: a key can be valid for STS and still be
// denied here, which is what matters for sending mail.
func SESAccountInfo(ctx context.Context, client *http.Client, c Credentials, region string) (*SESAccount, error) {
	if region == "" {
		region = "us-east-1"
	}
	body, err := sesGet(ctx, client, c, region, "/v2/email/account")
	if err != nil {
		return nil, err
	}
	var raw struct {
		SendingEnabled          bool `json:"SendingEnabled"`
		ProductionAccessEnabled bool `json:"ProductionAccessEnabled"`
		SendQuota               struct {
			Max24HourSend   float64 `json:"Max24HourSend"`
			MaxSendRate     float64 `json:"MaxSendRate"`
			SentLast24Hours float64 `json:"SentLast24Hours"`
		} `json:"SendQuota"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, err
	}
	out := &SESAccount{
		Region:           region,
		SendingEnabled:   raw.SendingEnabled,
		ProductionAccess: raw.ProductionAccessEnabled,
		Sandbox:          !raw.ProductionAccessEnabled,
		Max24HourSend:    raw.SendQuota.Max24HourSend,
		MaxSendRate:      raw.SendQuota.MaxSendRate,
		SentLast24Hours:  raw.SendQuota.SentLast24Hours,
	}
	// identities are a separate permission; absence is not fatal
	if idBody, err := sesGet(ctx, client, c, region, "/v2/email/identities"); err == nil {
		var ids struct {
			EmailIdentities []struct {
				IdentityName string `json:"IdentityName"`
			} `json:"EmailIdentities"`
		}
		if json.Unmarshal(idBody, &ids) == nil {
			for _, i := range ids.EmailIdentities {
				out.Identities = append(out.Identities, i.IdentityName)
			}
		}
	}
	return out, nil
}

// SESCanSend reports whether the credentials can send mail in the region.
func SESCanSend(ctx context.Context, client *http.Client, c Credentials, region string) (bool, error) {
	acc, err := SESAccountInfo(ctx, client, c, region)
	if err != nil {
		return false, err
	}
	return acc.SendingEnabled && acc.Max24HourSend > acc.SentLast24Hours, nil
}

func sesGet(ctx context.Context, client *http.Client, c Credentials, region, path string) ([]byte, error) {
	u := "https://email." + region + ".amazonaws.com" + path
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	SignV4(req, c, region, "ses", nil)
	resp, err := do(client, req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, &APIError{Status: resp.StatusCode, Body: brief(string(body))}
	}
	return body, nil
}
