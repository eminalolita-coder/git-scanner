package checkers

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func init() {
	Register(&gcpSAChecker{})
}

// gcpSAChecker verifies a GCP service account key by minting a JWT and
// exchanging it for an access token. This is independent of the API key
// checker: a service account key is a JSON document with a private key, not
// an API key, and must be validated differently.
type gcpSAChecker struct{}

func (g *gcpSAChecker) Name() string { return "gcp-service-account" }

func (g *gcpSAChecker) Match(ruleID string, tags []string) bool {
	return ruleID == "gcp-service-account"
}

func (g *gcpSAChecker) Check(ctx context.Context, secret string, meta map[string]string) Result {
	raw := ""
	if meta != nil {
		raw = meta["json"]
	}
	if raw == "" {
		return Result{Err: "missing service account JSON (re-scan to capture it)"}
	}
	var sa struct {
		Type         string `json:"type"`
		ProjectID    string `json:"project_id"`
		PrivateKeyID string `json:"private_key_id"`
		PrivateKey   string `json:"private_key"`
		ClientEmail  string `json:"client_email"`
		TokenURI     string `json:"token_uri"`
	}
	if err := json.Unmarshal([]byte(raw), &sa); err != nil {
		return Result{Err: "invalid JSON: " + err.Error()}
	}
	if sa.Type != "service_account" || sa.PrivateKey == "" || sa.ClientEmail == "" {
		return Result{Err: "not a service account key"}
	}
	if sa.TokenURI == "" {
		sa.TokenURI = "https://oauth2.googleapis.com/token"
	}

	block, _ := pem.Decode([]byte(sa.PrivateKey))
	if block == nil {
		return Result{Err: "invalid PEM private key"}
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return Result{Err: "parse private key: " + err.Error()}
	}
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return Result{Err: "private key is not RSA"}
	}

	b64 := func(b []byte) string {
		return strings.TrimRight(base64.URLEncoding.EncodeToString(b), "=")
	}
	header, _ := json.Marshal(map[string]string{
		"alg": "RS256", "typ": "JWT", "kid": sa.PrivateKeyID,
	})
	now := time.Now().Unix()
	claims, _ := json.Marshal(map[string]any{
		"iss":   sa.ClientEmail,
		"scope": "https://www.googleapis.com/auth/cloud-platform",
		"aud":   sa.TokenURI,
		"iat":   now,
		"exp":   now + 3600,
	})
	signingInput := b64(header) + "." + b64(claims)
	h := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, rsaKey, crypto.SHA256, h[:])
	if err != nil {
		return Result{Err: "sign JWT: " + err.Error()}
	}
	assertion := signingInput + "." + b64(sig)

	form := url.Values{}
	form.Set("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer")
	form.Set("assertion", assertion)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, sa.TokenURI, strings.NewReader(form.Encode()))
	if err != nil {
		return Result{Err: err.Error()}
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := httpClient.Do(req)
	if err != nil {
		return Result{Err: err.Error()}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode != http.StatusOK {
		msg := string(body)
		if len(msg) > 160 {
			msg = msg[:160]
		}
		return Result{Err: fmt.Sprintf("oauth2 %d: %s", resp.StatusCode, msg)}
	}
	var out struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
	}
	_ = json.Unmarshal(body, &out)
	return Result{
		Verified: true,
		Identity: sa.ClientEmail,
		Meta: map[string]string{
			"project":      sa.ProjectID,
			"client_email": sa.ClientEmail,
			"key_id":       sa.PrivateKeyID,
		},
	}
}
