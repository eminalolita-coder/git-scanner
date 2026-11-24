package aws

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestSignV4Headers(t *testing.T) {
	u, _ := url.Parse("https://sts.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15")
	req, _ := http.NewRequest(http.MethodGet, u.String(), nil)
	SignV4(req, Credentials{AccessKey: "AKIAIOSFODNN7EXAMPLE", SecretKey: "secret"}, "us-east-1", "sts", nil)

	auth := req.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "AWS4-HMAC-SHA256 ") {
		t.Fatalf("bad auth prefix: %q", auth)
	}
	if !strings.Contains(auth, "Credential=AKIAIOSFODNN7EXAMPLE/") {
		t.Errorf("missing credential scope: %q", auth)
	}
	if !strings.Contains(auth, "SignedHeaders=host;x-amz-date") {
		t.Errorf("bad signed headers: %q", auth)
	}
	if req.Header.Get("X-Amz-Date") == "" {
		t.Error("missing X-Amz-Date")
	}
}

func TestCanonicalQuerySorted(t *testing.T) {
	q := url.Values{}
	q.Set("Version", "2011-06-15")
	q.Set("Action", "GetCallerIdentity")
	got := canonicalQuery(q)
	want := "Action=GetCallerIdentity&Version=2011-06-15"
	if got != want {
		t.Errorf("canonicalQuery = %q, want %q", got, want)
	}
}

func TestSessionTokenSigned(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "https://sts.amazonaws.com/", nil)
	SignV4(req, Credentials{AccessKey: "A", SecretKey: "s", SessionToken: "tok"}, "us-east-1", "sts", nil)
	if !strings.Contains(req.Header.Get("Authorization"), "x-amz-security-token") {
		t.Error("session token not included in signed headers")
	}
}
