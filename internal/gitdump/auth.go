package gitdump

import (
	"github.com/go-git/go-git/v5/plumbing/transport"
	"github.com/go-git/go-git/v5/plumbing/transport/http"
)

// tokenAuth builds transport auth for a host given a token. Different forges
// expect different basic-auth usernames; we map the common ones.
func tokenAuth(host, token string) transport.AuthMethod {
	if token == "" {
		return nil
	}
	switch host {
	case "gitlab":
		return &http.BasicAuth{Username: "oauth2", Password: token}
	case "bitbucket":
		return &http.BasicAuth{Username: "x-token-auth", Password: token}
	case "azuredevops":
		return &http.BasicAuth{Username: "pat", Password: token}
	default: // github, gitea, gogs, gerrit, generic
		return &http.BasicAuth{Username: "x-access-token", Password: token}
	}
}

// HostFromURL guesses a forge key from a repository URL.
func HostFromURL(url string) string {
	switch {
	case contains(url, "github.com"):
		return "github"
	case contains(url, "gitlab"):
		return "gitlab"
	case contains(url, "bitbucket"):
		return "bitbucket"
	case contains(url, "dev.azure.com"), contains(url, "visualstudio.com"):
		return "azuredevops"
	case contains(url, "codecommit"):
		return "codecommit"
	case contains(url, "gerrit"):
		return "gerrit"
	default:
		return ""
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	}())
}
