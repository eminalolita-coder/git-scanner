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

func TestParseRemote(t *testing.T) {
	cases := []struct {
		in    string
		forge Forge
		owner string
		ok    bool
	}{
		{"https://github.com/itad-55/isthatadeal.git", GitHub, "itad-55", true},
		{"https://github.com/itad-55/isthatadeal", GitHub, "itad-55", true},
		{"git@github.com:acme/website.git", GitHub, "acme", true},
		{"https://user:pass@gitlab.com/grp/proj.git", GitLab, "grp", true},
		{"https://gitea.ngl2.de/andre/site.git", Gitea, "andre", true},
		{"https://dev.azure.com/myorg/proj/_git/repo", AzureDevOps, "myorg", true},
		{"not a url", Forge(""), "", false},
	}
	for _, c := range cases {
		forge, _, owner, ok := ParseRemote(c.in)
		if ok != c.ok || (ok && (forge != c.forge || owner != c.owner)) {
			t.Errorf("ParseRemote(%q) = %v,%q,%v want %v,%q,%v", c.in, forge, owner, ok, c.forge, c.owner, c.ok)
		}
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
