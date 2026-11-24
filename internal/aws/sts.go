package aws

import (
	"context"
	"encoding/xml"
	"net/http"
	"time"
)

// AssumeRoleResult is the outcome of sts:AssumeRole.
type AssumeRoleResult struct {
	Credentials AssumedCredentials
	ARN         string
	RoleID      string
}

// AssumedCredentials are temporary credentials.
type AssumedCredentials struct {
	AccessKey    string
	SecretKey    string
	SessionToken string
	Expiration   time.Time
}

// Credentials converts to a signing Credentials value.
func (a AssumedCredentials) Credentials(region string) Credentials {
	return Credentials{AccessKey: a.AccessKey, SecretKey: a.SecretKey, SessionToken: a.SessionToken, Region: region}
}

// AssumeRole calls sts:AssumeRole for roleARN and returns temporary credentials.
func AssumeRole(ctx context.Context, client *http.Client, base Credentials, roleARN, sessionName, externalID string, durationSec int) (AssumeRoleResult, error) {
	if sessionName == "" {
		sessionName = "git-scanner"
	}
	params := map[string]string{
		"RoleArn":         roleARN,
		"RoleSessionName": sessionName,
	}
	if externalID != "" {
		params["ExternalId"] = externalID
	}
	if durationSec > 0 {
		params["DurationSeconds"] = itoa(durationSec)
	}
	region := base.region("us-east-1")
	body, err := Query(ctx, client, base, region, "sts", "AssumeRole", "2011-06-15", params, "")
	if err != nil {
		return AssumeRoleResult{}, err
	}
	var out struct {
		AssumeRoleResponse struct {
			Result struct {
				Credentials struct {
					AccessKeyId     string `xml:"AccessKeyId"`
					SecretAccessKey string `xml:"SecretAccessKey"`
					SessionToken    string `xml:"SessionToken"`
					Expiration      string `xml:"Expiration"`
				} `xml:"Credentials"`
				AssumedRoleUser struct {
					Arn string `xml:"Arn"`
					ID  string `xml:"AssumedRoleId"`
				} `xml:"AssumedRoleUser"`
			} `xml:"AssumeRoleResult"`
		} `xml:"AssumeRoleResponse"`
	}
	if err := xml.Unmarshal(body, &out); err != nil {
		return AssumeRoleResult{}, err
	}
	r := out.AssumeRoleResponse.Result
	exp, _ := time.Parse(time.RFC3339, r.Credentials.Expiration)
	return AssumeRoleResult{
		Credentials: AssumedCredentials{
			AccessKey:    r.Credentials.AccessKeyId,
			SecretKey:    r.Credentials.SecretAccessKey,
			SessionToken: r.Credentials.SessionToken,
			Expiration:   exp,
		},
		ARN:    r.AssumedRoleUser.Arn,
		RoleID: r.AssumedRoleUser.ID,
	}, nil
}

// GetSessionToken calls sts:GetSessionToken (useful to add an MFA-bound token).
func GetSessionToken(ctx context.Context, client *http.Client, base Credentials, serial, token string) (AssumedCredentials, error) {
	params := map[string]string{}
	if serial != "" {
		params["SerialNumber"] = serial
		params["TokenCode"] = token
	}
	region := base.region("us-east-1")
	body, err := Query(ctx, client, base, region, "sts", "GetSessionToken", "2011-06-15", params, "")
	if err != nil {
		return AssumedCredentials{}, err
	}
	var out struct {
		GetSessionTokenResponse struct {
			Result struct {
				Credentials struct {
					AccessKeyId     string `xml:"AccessKeyId"`
					SecretAccessKey string `xml:"SecretAccessKey"`
					SessionToken    string `xml:"SessionToken"`
					Expiration      string `xml:"Expiration"`
				} `xml:"Credentials"`
			} `xml:"GetSessionTokenResult"`
		} `xml:"GetSessionTokenResponse"`
	}
	if err := xml.Unmarshal(body, &out); err != nil {
		return AssumedCredentials{}, err
	}
	r := out.GetSessionTokenResponse.Result.Credentials
	exp, _ := time.Parse(time.RFC3339, r.Expiration)
	return AssumedCredentials{r.AccessKeyId, r.SecretAccessKey, r.SessionToken, exp}, nil
}
