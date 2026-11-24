package dumper

import "testing"

func TestForgeFromHost(t *testing.T) {
	cases := map[string]Forge{
		"github.com":         GitHub,
		"gitlab.example.com": GitLab,
		"gitlab.com":         GitLab,
		"bitbucket.org":      Bitbucket,
		"dev.azure.com":      AzureDevOps,
		"gitea.example.org":  Gitea,
		"gogs.example.org":   Gogs,
	}
	for host, want := range cases {
		if got := ForgeFromHost(host); got != want {
			t.Errorf("ForgeFromHost(%q) = %q, want %q", host, got, want)
		}
	}
}

func TestBasicAuth(t *testing.T) {
	// base64("user:pass")
	if got := basicAuth("user", "pass"); got != "Basic dXNlcjpwYXNz" {
		t.Errorf("basicAuth = %q", got)
	}
}

func TestStripGerritPrefix(t *testing.T) {
	in := []byte(")]}'\n{\"proj\":{}}")
	out := string(stripGerritPrefix(in))
	if out != `{"proj":{}}` {
		t.Errorf("stripGerritPrefix = %q", out)
	}
	plain := []byte(`{"a":1}`)
	if string(stripGerritPrefix(plain)) != `{"a":1}` {
		t.Error("plain json should be unchanged")
	}
}
