// Package dumper enumerates repositories a token can reach on a git forge and
// returns their clone URLs.
package dumper

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Forge identifies a hosting platform.
type Forge string

const (
	GitHub      Forge = "github"
	GitLab      Forge = "gitlab"
	Gitea       Forge = "gitea"
	Gogs        Forge = "gogs"
	Bitbucket   Forge = "bitbucket"
	AzureDevOps Forge = "azuredevops"
)

// Repo is a repository discovered on a forge.
type Repo struct {
	Name     string `json:"name"`
	FullName string `json:"full_name"`
	CloneURL string `json:"clone_url"`
	Private  bool   `json:"private"`
	Forge    Forge  `json:"forge"`
}

// ForgeFromHost guesses the forge from a hostname.
func ForgeFromHost(host string) Forge {
	h := strings.ToLower(host)
	switch {
	case strings.Contains(h, "github"):
		return GitHub
	case strings.Contains(h, "gitlab"):
		return GitLab
	case strings.Contains(h, "bitbucket"):
		return Bitbucket
	case strings.Contains(h, "dev.azure.com"), strings.Contains(h, "visualstudio.com"):
		return AzureDevOps
	case strings.Contains(h, "gitea"):
		return Gitea
	case strings.Contains(h, "gogs"):
		return Gogs
	default:
		return Gitea // most self-hosted are gitea/gogs compatible
	}
}

// Client lists repositories.
type Client struct {
	HTTP    *http.Client
	Forge   Forge
	BaseURL string // e.g. https://github.com or a self-hosted root
	Token   string
	max     int
}

// New builds a Client with sane defaults.
func New(forge Forge, base, token string) *Client {
	if base == "" {
		switch forge {
		case GitHub:
			base = "https://github.com"
		case GitLab:
			base = "https://gitlab.com"
		case Bitbucket:
			base = "https://bitbucket.org"
		}
	}
	return &Client{
		HTTP:    &http.Client{Timeout: 30 * time.Second},
		Forge:   forge,
		BaseURL: strings.TrimRight(base, "/"),
		Token:   token,
		max:     1000,
	}
}

// List enumerates up to max repositories.
func (c *Client) List(ctx context.Context) ([]Repo, error) {
	switch c.Forge {
	case GitHub:
		return c.listGitHub(ctx)
	case GitLab:
		return c.listGitLab(ctx)
	case Bitbucket:
		return c.listBitbucket(ctx)
	case Gitea, Gogs:
		return c.listGitea(ctx)
	default:
		return c.listGitea(ctx)
	}
}

func (c *Client) get(ctx context.Context, url string, hdr map[string]string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "git-scanner")
	req.Header.Set("Accept", "application/json")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("%s: status %d", url, resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func (c *Client) listGitHub(ctx context.Context) ([]Repo, error) {
	api := c.BaseURL
	if strings.Contains(api, "github.com") {
		api = "https://api.github.com"
	} else {
		api += "/api/v3"
	}
	hdr := map[string]string{"Authorization": "token " + c.Token}
	var out []Repo
	for page := 1; page <= c.max/100; page++ {
		var batch []struct {
			FullName string `json:"full_name"`
			CloneURL string `json:"clone_url"`
			Private  bool   `json:"private"`
			Name     string `json:"name"`
		}
		url := fmt.Sprintf("%s/user/repos?per_page=100&page=%d&affiliation=owner,collaborator,organization_member", api, page)
		if err := c.get(ctx, url, hdr, &batch); err != nil {
			return out, err
		}
		if len(batch) == 0 {
			break
		}
		for _, r := range batch {
			out = append(out, Repo{Name: r.Name, FullName: r.FullName, CloneURL: r.CloneURL, Private: r.Private, Forge: GitHub})
		}
	}
	return out, nil
}

func (c *Client) listGitLab(ctx context.Context) ([]Repo, error) {
	api := strings.TrimRight(c.BaseURL, "/") + "/api/v4"
	hdr := map[string]string{"PRIVATE-TOKEN": c.Token}
	var out []Repo
	for page := 1; page <= c.max/100; page++ {
		var batch []struct {
			PathWithNS string `json:"path_with_namespace"`
			HTTPURL    string `json:"http_url_to_repo"`
			Visibility string `json:"visibility"`
			Name       string `json:"name"`
		}
		url := fmt.Sprintf("%s/projects?membership=true&per_page=100&page=%d", api, page)
		if err := c.get(ctx, url, hdr, &batch); err != nil {
			return out, err
		}
		if len(batch) == 0 {
			break
		}
		for _, r := range batch {
			out = append(out, Repo{Name: r.Name, FullName: r.PathWithNS, CloneURL: r.HTTPURL, Private: r.Visibility != "public", Forge: GitLab})
		}
	}
	return out, nil
}

func (c *Client) listGitea(ctx context.Context) ([]Repo, error) {
	api := strings.TrimRight(c.BaseURL, "/") + "/api/v1"
	hdr := map[string]string{"Authorization": "token " + c.Token}
	var out []Repo
	for page := 1; page <= c.max/50; page++ {
		var batch []struct {
			FullName string `json:"full_name"`
			CloneURL string `json:"clone_url"`
			HTMLURL  string `json:"html_url"`
			Private  bool   `json:"private"`
			Name     string `json:"name"`
		}
		url := fmt.Sprintf("%s/user/repos?limit=50&page=%d", api, page)
		if err := c.get(ctx, url, hdr, &batch); err != nil {
			return out, err
		}
		if len(batch) == 0 {
			break
		}
		for _, r := range batch {
			clone := r.CloneURL
			if clone == "" {
				clone = r.HTMLURL + ".git"
			}
			out = append(out, Repo{Name: r.Name, FullName: r.FullName, CloneURL: clone, Private: r.Private, Forge: c.Forge})
		}
	}
	return out, nil
}

func (c *Client) listBitbucket(ctx context.Context) ([]Repo, error) {
	// token form "user:app-password"
	user, pass, _ := strings.Cut(c.Token, ":")
	hdr := map[string]string{"Authorization": basicAuth(user, pass)}
	var out []Repo
	next := strings.TrimRight(c.BaseURL, "/") + "/2.0/repositories/" + user + "?pagelen=100"
	for next != "" && len(out) < c.max {
		var batch struct {
			Values []struct {
				FullName string `json:"full_name"`
				Name     string `json:"name"`
				Links    struct {
					Clone []struct {
						Name string `json:"name"`
						Href string `json:"href"`
					} `json:"clone"`
				} `json:"links"`
			} `json:"values"`
			Next string `json:"next"`
		}
		if err := c.get(ctx, next, hdr, &batch); err != nil {
			return out, err
		}
		for _, r := range batch.Values {
			clone := ""
			for _, l := range r.Links.Clone {
				if l.Name == "https" {
					clone = l.Href
				}
			}
			out = append(out, Repo{Name: r.Name, FullName: r.FullName, CloneURL: clone, Forge: Bitbucket})
		}
		next = batch.Next
	}
	return out, nil
}

func basicAuth(user, pass string) string {
	const tbl = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	s := user + ":" + pass
	var b strings.Builder
	for i := 0; i < len(s); i += 3 {
		var n uint32
		rem := len(s) - i
		n = uint32(s[i]) << 16
		if rem > 1 {
			n |= uint32(s[i+1]) << 8
		}
		if rem > 2 {
			n |= uint32(s[i+2])
		}
		b.WriteByte(tbl[(n>>18)&0x3f])
		b.WriteByte(tbl[(n>>12)&0x3f])
		if rem > 1 {
			b.WriteByte(tbl[(n>>6)&0x3f])
		} else {
			b.WriteByte('=')
		}
		if rem > 2 {
			b.WriteByte(tbl[n&0x3f])
		} else {
			b.WriteByte('=')
		}
	}
	return "Basic " + b.String()
}
