// Package aws implements minimal, dependency-free AWS SigV4 signing and a few
// read-only API calls used to verify and enumerate credentials.
package aws

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// Credentials holds a key pair and optional session token.
type Credentials struct {
	AccessKey    string
	SecretKey    string
	SessionToken string
	Region       string
}

func (c Credentials) region(def string) string {
	if c.Region != "" {
		return c.Region
	}
	return def
}

// Identity is the result of STS GetCallerIdentity.
type Identity struct {
	Account string
	ARN     string
	UserID  string
}

// GetCallerIdentity calls sts:GetCallerIdentity with a signed request.
func GetCallerIdentity(ctx context.Context, client *http.Client, c Credentials) (Identity, error) {
	params := url.Values{}
	params.Set("Action", "GetCallerIdentity")
	params.Set("Version", "2011-06-15")
	region := c.region("us-east-1")
	endpoint := "https://sts.amazonaws.com/?" + params.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return Identity{}, err
	}
	SignV4(req, c, region, "sts", nil)

	resp, err := do(client, req)
	if err != nil {
		return Identity{}, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode != http.StatusOK {
		return Identity{}, &APIError{Status: resp.StatusCode, Body: string(body)}
	}
	var out struct {
		GetCallerIdentityResponse struct {
			Result struct {
				Account string `xml:"Account"`
				ARN     string `xml:"Arn"`
				UserID  string `xml:"UserId"`
			} `xml:"GetCallerIdentityResult"`
		} `xml:"GetCallerIdentityResponse"`
	}
	_ = xml.Unmarshal(body, &out)
	r := out.GetCallerIdentityResponse.Result
	return Identity{Account: r.Account, ARN: r.ARN, UserID: r.UserID}, nil
}

// Bucket is an S3 bucket entry.
type Bucket struct {
	Name string `xml:"Name"`
}

// ListBuckets returns the account's S3 buckets.
func ListBuckets(ctx context.Context, client *http.Client, c Credentials) ([]Bucket, error) {
	region := c.region("us-east-1")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://s3.amazonaws.com/", nil)
	if err != nil {
		return nil, err
	}
	SignV4(req, c, region, "s3", nil)
	resp, err := do(client, req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, &APIError{Status: resp.StatusCode, Body: string(body)}
	}
	var out struct {
		Buckets []Bucket `xml:"Buckets>Bucket"`
	}
	_ = xml.Unmarshal(body, &out)
	return out.Buckets, nil
}

// IAMUser is a minimal IAM user representation.
type IAMUser struct {
	UserName string `json:"UserName"`
	ARN      string `json:"Arn"`
}

// ListIAMUsers returns the account's IAM users (first 100).
func ListIAMUsers(ctx context.Context, client *http.Client, c Credentials) ([]IAMUser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://iam.amazonaws.com/?Action=ListUsers&Version=2010-05-08&MaxItems=100", nil)
	if err != nil {
		return nil, err
	}
	SignV4(req, c, "us-east-1", "iam", nil)
	resp, err := do(client, req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, &APIError{Status: resp.StatusCode, Body: string(body)}
	}
	var out struct {
		ListUsersResult struct {
			Users []struct {
				UserName string `xml:"UserName"`
				ARN      string `xml:"Arn"`
			} `xml:"member"`
		} `xml:"ListUsersResult"`
	}
	_ = xml.Unmarshal(body, &out)
	users := make([]IAMUser, 0, len(out.ListUsersResult.Users))
	for _, u := range out.ListUsersResult.Users {
		users = append(users, IAMUser{UserName: u.UserName, ARN: u.ARN})
	}
	return users, nil
}

// APIError carries a non-2xx AWS response.
type APIError struct {
	Status int
	Body   string
}

func (e *APIError) Error() string { return "aws api: status " + itoa(e.Status) }

// SignV4 signs req in place using AWS Signature Version 4.
func SignV4(req *http.Request, c Credentials, region, service string, body []byte) {
	now := time.Now().UTC()
	amzDate := now.Format("20060102T150405Z")
	dateStamp := now.Format("20060102")

	req.Header.Set("X-Amz-Date", amzDate)
	if c.SessionToken != "" {
		req.Header.Set("X-Amz-Security-Token", c.SessionToken)
	}

	host := req.URL.Host
	req.Header.Set("Host", host)

	payloadHash := hexSHA256(body)

	query := canonicalQuery(req.URL.Query())
	headers := map[string]string{"host": host, "x-amz-date": amzDate}
	if c.SessionToken != "" {
		headers["x-amz-security-token"] = c.SessionToken
	}
	signedHeaders, canonicalHeaders := canonicalHeadersOf(headers)

	canonicalRequest := strings.Join([]string{
		req.Method,
		canonicalURI(req.URL),
		query,
		canonicalHeaders,
		signedHeaders,
		payloadHash,
	}, "\n")

	scope := strings.Join([]string{dateStamp, region, service, "aws4_request"}, "/")
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256", amzDate, scope, hexSHA256([]byte(canonicalRequest)),
	}, "\n")

	kDate := hmacSHA256([]byte("AWS4"+c.SecretKey), dateStamp)
	kRegion := hmacSHA256(kDate, region)
	kService := hmacSHA256(kRegion, service)
	kSigning := hmacSHA256(kService, "aws4_request")
	sig := hex.EncodeToString(hmacSHA256(kSigning, stringToSign))

	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 "+
		"Credential="+c.AccessKey+"/"+scope+", "+
		"SignedHeaders="+signedHeaders+", "+
		"Signature="+sig)
}

func canonicalURI(u *url.URL) string {
	if u.Path == "" {
		return "/"
	}
	return u.EscapedPath()
}

func canonicalQuery(v url.Values) string {
	keys := make([]string, 0, len(v))
	for k := range v {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		vals := v[k]
		sort.Strings(vals)
		for _, val := range vals {
			parts = append(parts, uriEncode(k)+"="+uriEncode(val))
		}
	}
	return strings.Join(parts, "&")
}

func canonicalHeadersOf(h map[string]string) (string, string) {
	keys := make([]string, 0, len(h))
	for k := range h {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(k)
		b.WriteString(":")
		b.WriteString(strings.TrimSpace(h[k]))
		b.WriteString("\n")
	}
	return strings.Join(keys, ";"), b.String()
}

func uriEncode(s string) string {
	const unreserved = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.~"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if strings.IndexByte(unreserved, ch) >= 0 {
			b.WriteByte(ch)
			continue
		}
		b.WriteString("%")
		b.WriteString(strings.ToUpper(hex.EncodeToString([]byte{ch})))
	}
	return b.String()
}

func hexSHA256(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func hmacSHA256(key []byte, data string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return h.Sum(nil)
}

func do(client *http.Client, req *http.Request) (*http.Response, error) {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return client.Do(req)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [12]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

var _ = json.Marshal
