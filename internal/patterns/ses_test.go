package patterns

import "testing"

const (
	sesUser = "AKIAIOSFODNN7EXAMPLE"
	sesPass = "Bf3xK9mQ2rT7vL1nW8sY4pZ6cH0jD5gA2eR9uI3oX7k="
)

func TestBestSESPasswordPairsEnvValue(t *testing.T) {
	// The "=" of the assignment is a word boundary; the password must not
	// include it.
	body := []byte("SMTP_USERNAME=" + sesUser + "\nSMTP_PASSWORD=" + sesPass + "\n")
	got := BestSESPassword(body, sesUser, DefaultSecretEntropy)
	if got != sesPass {
		t.Errorf("BestSESPassword = %q, want %q", got, sesPass)
	}
}

func TestBestSESPasswordExcludesSelf(t *testing.T) {
	if got := BestSESPassword([]byte(sesPass), sesPass, DefaultSecretEntropy); got != "" {
		t.Errorf("expected empty, got %q", got)
	}
}

func TestSESRulesMatch(t *testing.T) {
	eng := NewEngine(10)
	if err := eng.AddAll(Builtin()); err != nil {
		t.Fatalf("builtin rules: %v", err)
	}
	cases := []struct {
		name   string
		input  string
		ruleID string
	}{
		{"pair", sesUser + ":" + sesPass, "aws-ses-smtp-credential"},
		{"username", "SMTP_USERNAME=" + sesUser, "aws-ses-smtp-username"},
		{"password", "SMTP_PASSWORD=" + sesPass, "aws-ses-smtp-password"},
		{"endpoint", "host=email-smtp.eu-west-1.amazonaws.com", "aws-ses-smtp-endpoint"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			matches := eng.ScanString(tc.input)
			for _, m := range matches {
				if m.Pattern.ID == tc.ruleID {
					return
				}
			}
			t.Fatalf("%s: rule %s did not match %q (got %v)", tc.name, tc.ruleID, tc.input, idsOf(matches))
		})
	}
}

func idsOf(ms []RawMatch) []string {
	out := make([]string, 0, len(ms))
	for _, m := range ms {
		out = append(out, m.Pattern.ID)
	}
	return out
}
