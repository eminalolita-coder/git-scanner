// Package dumper enumerates repositories a token can reach on a git forge and
// returns their clone URLs.
package dumper

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
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
	Gerrit      Forge = "gerrit"
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
	case strings.Contains(h, "gerrit"):
		return Gerrit
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
	Token   string // "user:pass" for gerrit/bitbucket/azure
	Org     string // azure devops organisation
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

// SearchIdentity looks up accounts by commit author email on the forge.
func (c *Client) SearchIdentity(ctx context.Context, email string) ([]string, error) {
	if email == "" {
		return nil, nil
	}
	hdr := map[string]string{}
	if c.Token != "" {
		hdr["Authorization"] = "token " + c.Token
		hdr["PRIVATE-TOKEN"] = c.Token
	}
	switch c.Forge {
	case GitHub:
		api := c.BaseURL
		if strings.Contains(api, "github.com") || api == "" {
			api = "https://api.github.com"
		}
		var out struct {
			Items []struct {
				Login   string `json:"login"`
				HTMLURL string `json:"html_url"`
			} `json:"items"`
		}
		u := fmt.Sprintf("%s/search/users?q=%s+in:email", api, url.QueryEscape(email))
		if err := c.getWithFallback(ctx, u, hdr, &out); err != nil {
			return nil, err
		}
		var res []string
		for _, it := range out.Items {
			if it.HTMLURL != "" {
				res = append(res, it.HTMLURL)
			} else {
				res = append(res, it.Login)
			}
		}
		return res, nil
	case GitLab:
		api := strings.TrimRight(c.BaseURL, "/") + "/api/v4"
		var out []struct {
			Username string `json:"username"`
			WebURL   string `json:"web_url"`
		}
		u := fmt.Sprintf("%s/users?search=%s", api, url.QueryEscape(email))
		if err := c.getWithFallback(ctx, u, hdr, &out); err != nil {
			return nil, err
		}
		var res []string
		for _, it := range out {
			res = append(res, it.WebURL)
		}
		return res, nil
	case Gitea, Gogs:
		api := strings.TrimRight(c.BaseURL, "/") + "/api/v1"
		var out []struct {
			Login   string `json:"login"`
			HTMLURL string `json:"html_url"`
		}
		u := fmt.Sprintf("%s/users/search?q=%s", api, url.QueryEscape(email))
		if err := c.getWithFallback(ctx, u, hdr, &out); err != nil {
			return nil, err
		}
		var res []string
		for _, it := range out {
			res = append(res, it.HTMLURL)
		}
		return res, nil
	}
	return nil, fmt.Errorf("unsupported forge %s", c.Forge)
}

// getWithFallback performs a GET, retrying without credentials when an
// authenticated call fails (e.g. an expired leaked token).
func (c *Client) getWithFallback(ctx context.Context, url string, hdr map[string]string, out any) error {
	err := c.get(ctx, url, hdr, out)
	if err == nil {
		return nil
	}
	_, hasAuth := hdr["Authorization"]
	_, hasPT := hdr["PRIVATE-TOKEN"]
	if hasAuth || hasPT {
		return c.get(ctx, url, nil, out)
	}
	return err
}

// ParseRemote extracts the forge, base URL and owner from a git remote URL.
// It accepts https://host/owner/repo(.git) and git@host:owner/repo forms.
func ParseRemote(remote string) (Forge, string, string, bool) {
	u := strings.TrimSpace(strings.TrimSuffix(remote, ".git"))
	if u == "" {
		return "", "", "", false
	}
	if strings.HasPrefix(u, "git@") {
		rest := strings.TrimPrefix(u, "git@")
		host, path, ok := strings.Cut(rest, ":")
		if !ok {
			return "", "", "", false
		}
		return forgeBaseOwner(host, path)
	}
	if i := strings.Index(u, "://"); i >= 0 {
		u = u[i+3:]
	}
	if at := strings.IndexByte(u, '@'); at >= 0 && at < strings.IndexByte(u, '/') {
		u = u[at+1:]
	}
	host, path, _ := strings.Cut(u, "/")
	return forgeBaseOwner(host, path)
}

func forgeBaseOwner(host, path string) (Forge, string, string, bool) {
	f := ForgeFromHost(host)
	if f == "" {
		return "", "", "", false
	}
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) < 1 || parts[0] == "" {
		return "", "", "", false
	}
	base := "https://" + host
	if f == AzureDevOps && !strings.Contains(host, "dev.azure.com") {
		base = "https://" + host
	}
	return f, base, parts[0], true
}

// ListOwner lists an owner's repositories. It uses the token when present
// (private repos included) and falls back to the public owner endpoint.
func (c *Client) ListOwner(ctx context.Context, owner string) ([]Repo, error) {
	if owner == "" {
		return nil, fmt.Errorf("empty owner")
	}
	if c.Token != "" {
		if repos, err := c.List(ctx); err == nil && len(repos) > 0 {
			return repos, nil
		}
	}
	switch c.Forge {
	case GitHub:
		return c.listGitHubOwner(ctx, owner)
	case GitLab:
		return c.listGitLabOwner(ctx, owner)
	case Gitea, Gogs:
		return c.listGiteaOwner(ctx, owner)
	case Bitbucket:
		return c.listBitbucket(ctx)
	default:
		return nil, fmt.Errorf("unsupported forge %s", c.Forge)
	}
}

func (c *Client) listGitHubOwner(ctx context.Context, owner string) ([]Repo, error) {
	api := c.BaseURL
	if strings.Contains(api, "github.com") || api == "" {
		api = "https://api.github.com"
	} else {
		api += "/api/v3"
	}
	hdr := map[string]string{}
	if c.Token != "" {
		hdr["Authorization"] = "token " + c.Token
	}
	var out []Repo
	for page := 1; page <= c.max/100; page++ {
		var batch []struct {
			FullName string `json:"full_name"`
			CloneURL string `json:"clone_url"`
			Private  bool   `json:"private"`
			Name     string `json:"name"`
		}
		url := fmt.Sprintf("%s/users/%s/repos?per_page=100&page=%d", api, owner, page)
		if err := c.getWithFallback(ctx, url, hdr, &batch); err != nil {
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

func (c *Client) listGitLabOwner(ctx context.Context, owner string) ([]Repo, error) {
	api := strings.TrimRight(c.BaseURL, "/") + "/api/v4"
	hdr := map[string]string{}
	if c.Token != "" {
		hdr["PRIVATE-TOKEN"] = c.Token
	}
	var out []Repo
	for page := 1; page <= c.max/100; page++ {
		var batch []struct {
			PathWithNS string `json:"path_with_namespace"`
			HTTPURL    string `json:"http_url_to_repo"`
			Visibility string `json:"visibility"`
			Name       string `json:"name"`
		}
		url := fmt.Sprintf("%s/users/%s/projects?per_page=100&page=%d", api, owner, page)
		if err := c.getWithFallback(ctx, url, hdr, &batch); err != nil {
			// groups fallback
			var gb []struct {
				PathWithNS string `json:"path_with_namespace"`
				HTTPURL    string `json:"http_url_to_repo"`
				Name       string `json:"name"`
			}
			gurl := fmt.Sprintf("%s/groups/%s/projects?per_page=100&page=%d", api, owner, page)
			if gerr := c.get(ctx, gurl, hdr, &gb); gerr != nil {
				return out, err
			}
			for _, r := range gb {
				out = append(out, Repo{Name: r.Name, FullName: r.PathWithNS, CloneURL: r.HTTPURL, Forge: GitLab})
			}
			continue
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

func (c *Client) listGiteaOwner(ctx context.Context, owner string) ([]Repo, error) {
	api := strings.TrimRight(c.BaseURL, "/") + "/api/v1"
	hdr := map[string]string{}
	if c.Token != "" {
		hdr["Authorization"] = "token " + c.Token
	}
	var out []Repo
	for page := 1; page <= c.max/50; page++ {
		var batch []struct {
			FullName string `json:"full_name"`
			CloneURL string `json:"clone_url"`
			HTMLURL  string `json:"html_url"`
			Private  bool   `json:"private"`
			Name     string `json:"name"`
		}
		url := fmt.Sprintf("%s/users/%s/repos?limit=50&page=%d", api, owner, page)
		if err := c.getWithFallback(ctx, url, hdr, &batch); err != nil {
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

// List enumerates up to max repositories.
func (c *Client) List(ctx context.Context) ([]Repo, error) {
	switch c.Forge {
	case GitHub:
		return c.listGitHub(ctx)
	case GitLab:
		return c.listGitLab(ctx)
	case Bitbucket:
		return c.listBitbucket(ctx)
	case AzureDevOps:
		return c.listAzureDevOps(ctx)
	case Gerrit:
		return c.listGerrit(ctx)
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

func (c *Client) getRaw(ctx context.Context, url string, hdr map[string]string) ([]byte, error) {
	code, body, _, err := c.getRawHeaders(ctx, url, hdr)
	if err != nil {
		return nil, err
	}
	if code >= 400 {
		return body, fmt.Errorf("%s: status %d", url, code)
	}
	return body, nil
}

func (c *Client) getRawHeaders(ctx context.Context, url string, hdr map[string]string) (int, []byte, http.Header, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, nil, nil, err
	}
	req.Header.Set("User-Agent", "git-scanner")
	req.Header.Set("Accept", "application/json")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return 0, nil, nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	return resp.StatusCode, body, resp.Header, nil
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
		if err := c.getWithFallback(ctx, url, hdr, &batch); err != nil {
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
		if err := c.getWithFallback(ctx, url, hdr, &batch); err != nil {
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
		if err := c.getWithFallback(ctx, url, hdr, &batch); err != nil {
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
