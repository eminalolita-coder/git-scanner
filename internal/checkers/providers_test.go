package checkers

import "testing"

func TestClassifyGoogleKey(t *testing.T) {
	cases := []struct {
		name     string
		code     int
		body     string
		verified bool
	}{
		{"ok", 200, `{"items":[]}`, true},
		{"restricted-403", 403, `{"error":{"status":"PERMISSION_DENIED"}}`, true},
		{"restricted-400", 400, `{"error":{"status":"FAILED_PRECONDITION"}}`, true},
		{"invalid-400", 400, `{"error":{"errors":[{"reason":"API_KEY_INVALID"}]}}`, false},
		{"invalid-text", 400, `API key not valid. Please pass a valid API key.`, false},
		{"server-error", 500, ``, false},
	}
	for _, c := range cases {
		got := classifyGoogleKey(c.code, []byte(c.body))
		if got.Verified != c.verified {
			t.Errorf("%s: verified=%v (err=%q), want %v", c.name, got.Verified, got.Err, c.verified)
		}
	}
}

func TestGCPCheckerMatchesRule(t *testing.T) {
	var found bool
	for _, c := range For("gcp-api-key", []string{"gcp"}) {
		if c.Name() == "gcp" {
			found = true
		}
	}
	if !found {
		t.Error("gcp checker did not match gcp-api-key")
	}
}
