package scanners

import "testing"

func TestParseEnv(t *testing.T) {
	in := []byte(`
# comment
export DB_HOST=localhost
DB_USER="admin"
DB_PASS='s3cr3t'
EMPTY=
`)
	got := ParseEnv(in)
	if got["DB_HOST"] != "localhost" {
		t.Errorf("DB_HOST = %q", got["DB_HOST"])
	}
	if got["DB_USER"] != "admin" {
		t.Errorf("quotes not stripped: %q", got["DB_USER"])
	}
	if got["DB_PASS"] != "s3cr3t" {
		t.Errorf("single quotes not stripped: %q", got["DB_PASS"])
	}
}

func TestCandidateURLs(t *testing.T) {
	urls := CandidateURLs("https://host.tld/")
	if len(urls) == 0 {
		t.Fatal("expected candidate urls")
	}
	for _, u := range urls {
		if u[:8] != "https://" {
			t.Errorf("bad url: %q", u)
		}
	}
}
