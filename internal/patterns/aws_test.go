package patterns

import "testing"

func TestBestSecretCandidate(t *testing.T) {
	body := []byte("AKIAIOSFODNN7EXAMPLE\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n")
	got := BestSecretCandidate(body, "AKIAIOSFODNN7EXAMPLE", DefaultSecretEntropy)
	if got != "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" {
		t.Errorf("BestSecretCandidate = %q", got)
	}
}

func TestBestSecretCandidateRejectsSignature(t *testing.T) {
	// 40 chars but low entropy: "Signature=" + 30 hex
	sig := []byte(`https://b.s3.amazonaws.com/f?X-Amz-Credential=AKIAXD7RVKF47MZD3HE5%2F20260101&X-Amz-Signature=20b4579f266899cd15b0902878b988`)
	if got := BestSecretCandidate(sig, "AKIAXD7RVKF47MZD3HE5", DefaultSecretEntropy); got != "" {
		t.Errorf("expected no pair, got %q", got)
	}
}

func TestBestSecretCandidateExcludesSelf(t *testing.T) {
	if got := BestSecretCandidate([]byte("AKIAIOSFODNN7EXAMPLE"), "AKIAIOSFODNN7EXAMPLE", DefaultSecretEntropy); got != "" {
		t.Errorf("expected empty, got %q", got)
	}
}
