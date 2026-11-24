package aws

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
)

// endpointFor returns the default service endpoint for a region.
func endpointFor(service, region string) string {
	switch service {
	case "iam":
		return "https://iam.amazonaws.com"
	case "sts":
		return "https://sts.amazonaws.com"
	case "s3":
		if region == "" || region == "us-east-1" {
			return "https://s3.amazonaws.com"
		}
		return fmt.Sprintf("https://s3.%s.amazonaws.com", region)
	case "cloudformation":
		return fmt.Sprintf("https://cloudformation.%s.amazonaws.com", region)
	default:
		return fmt.Sprintf("https://%s.%s.amazonaws.com", service, region)
	}
}

// Query performs a signed query-protocol request (Action/Version form params)
// and returns the raw response body.
func Query(ctx context.Context, client *http.Client, c Credentials, region, service, action, version string, params map[string]string, endpoint string) ([]byte, error) {
	if endpoint == "" {
		endpoint = endpointFor(service, region)
	}
	form := url.Values{}
	form.Set("Action", action)
	form.Set("Version", version)
	for k, v := range params {
		form.Set(k, v)
	}
	body := []byte(form.Encode())

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint+"/", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	SignV4(req, c, region, service, body)

	resp, err := do(client, req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode >= 400 {
		return data, &APIError{Status: resp.StatusCode, Body: brief(string(data))}
	}
	return data, nil
}

// JSONCall performs a signed JSON-protocol request (X-Amz-Target header).
func JSONCall(ctx context.Context, client *http.Client, c Credentials, region, service, target string, payload any, endpoint string) ([]byte, error) {
	if endpoint == "" {
		endpoint = endpointFor(service, region)
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint+"/", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-amz-json-1.1")
	req.Header.Set("X-Amz-Target", target)
	SignV4(req, c, region, service, body)

	resp, err := do(client, req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode >= 400 {
		return data, &APIError{Status: resp.StatusCode, Body: brief(string(data))}
	}
	return data, nil
}

// CallerIdentity returns the account id of the credentials.
func CallerAccount(ctx context.Context, client *http.Client, c Credentials) (string, error) {
	id, err := GetCallerIdentity(ctx, client, c)
	if err != nil {
		return "", err
	}
	return id.Account, nil
}

func brief(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 300 {
		return s[:300] + "..."
	}
	return s
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
