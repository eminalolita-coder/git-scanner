package patterns

import "regexp"

// reSecretCandidate matches a 40-character token at word boundaries. The
// character class covers base64 as used by AWS secret access keys.
var reSecretCandidate = regexp.MustCompile(`\b([A-Za-z0-9/+=]{40})\b`)

// reHex32 matches a 32-character lowercase hex token (Mailjet key half).
var reHex32 = regexp.MustCompile(`(?:^|[^0-9a-fA-F])([a-f0-9]{32})(?:[^0-9a-fA-F]|$)`)

// BestHex32 returns the first 32-hex token in content other than exclude. It
// pairs a Mailjet API_KEY with its SECRET_KEY, which sit on adjacent lines.
func BestHex32(content []byte, exclude string) string {
	for _, m := range reHex32.FindAllStringSubmatch(string(content), 40) {
		if m[1] != exclude {
			return m[1]
		}
	}
	return ""
}

// reSESPassword matches a 44-character token that starts with an alphanumeric
// and ends with base64 padding. Starting on an alphanumeric matters: in
// "SMTP_PASSWORD=abc…=" the "=" of the assignment is itself a word boundary,
// so a naive pattern would capture it as part of the password.
var reSESPassword = regexp.MustCompile(`(?:^|[^A-Za-z0-9])([A-Za-z0-9][A-Za-z0-9/+=]{43})(?:[^A-Za-z0-9]|$)`)

// BestSESPassword returns the highest-entropy 44-char token in content,
// excluding the given value, provided its entropy is at least minEntropy. It
// pairs an SES SMTP username (an IAM access key id) with its password.
func BestSESPassword(content []byte, exclude string, minEntropy float64) string {
	best := ""
	bestEnt := minEntropy
	for _, m := range reSESPassword.FindAllStringSubmatch(string(content), 40) {
		c := m[1]
		if c == exclude || looksLikeLabel(c) {
			continue
		}
		if e := Shannon(c); e > bestEnt {
			best, bestEnt = c, e
		}
	}
	return best
}

// BestSecretCandidate returns the highest-entropy 40-char token in content,
// excluding the given value, provided its entropy is at least minEntropy.
// It is a heuristic to pair an AWS access key id with a nearby secret key.
//
// Candidates shaped like "<word>=" (e.g. "Signature=20b4…") are rejected,
// since a run that merely happens to be 40 chars long is usually not a key.
func BestSecretCandidate(content []byte, exclude string, minEntropy float64) string {
	best := ""
	bestEnt := minEntropy
	for _, m := range reSecretCandidate.FindAllStringSubmatch(string(content), 40) {
		c := m[1]
		if c == exclude || looksLikeLabel(c) {
			continue
		}
		if e := Shannon(c); e > bestEnt {
			best, bestEnt = c, e
		}
	}
	return best
}

// looksLikeLabel reports whether c is "<letters>=" + tail, i.e. a label
// concatenated with its value rather than a bare key.
func looksLikeLabel(c string) bool {
	i := indexByte(c, '=')
	if i < 4 {
		return false
	}
	for j := 0; j < i; j++ {
		if c[j] < 'A' || (c[j] > 'Z' && c[j] < 'a') || c[j] > 'z' {
			return false
		}
	}
	return true
}

func indexByte(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}

// DefaultSecretEntropy is the pairing threshold used by the scanners.
const DefaultSecretEntropy = 4.2
