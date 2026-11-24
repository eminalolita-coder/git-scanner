package cli

import "testing"

func TestPairedAWSSecret(t *testing.T) {
	body := []byte(`
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
`)
	got := pairedAWSSecret(body, "AKIAIOSFODNN7EXAMPLE")
	if got != "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" {
		t.Errorf("paired = %q", got)
	}
}

func TestPairedAWSSecretNoneIs40(t *testing.T) {
	// a presigned S3 URL has the access key but no 40-char secret
	body := []byte(`https://b.s3.amazonaws.com/f?X-Amz-Credential=AKIAXD7RVKF47MZD3HE5%2F20260101&X-Amz-Signature=20b4579f266899cd15b0902878b988`)
	if got := pairedAWSSecret(body, "AKIAXD7RVKF47MZD3HE5"); got != "" {
		t.Errorf("expected no pair, got %q", got)
	}
}

func TestPairedAWSSecretNotSelf(t *testing.T) {
	body := []byte("AKIAIOSFODNN7EXAMPLE")
	if got := pairedAWSSecret(body, "AKIAIOSFODNN7EXAMPLE"); got != "" {
		t.Errorf("expected empty (no other token), got %q", got)
	}
}
