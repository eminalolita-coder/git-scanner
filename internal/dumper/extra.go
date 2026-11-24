package dumper

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

// listGerrit enumerates projects via the Gerrit REST API. The token must be
// "user:http-password"; anonymous access works on read-only instances.
func (c *Client) listGerrit(ctx context.Context) ([]Repo, error) {
	base := strings.TrimRight(c.BaseURL, "/")
	if base == "" {
		return nil, fmt.Errorf("gerrit: base url required")
	}
	var out []Repo
	for start := 0; start < c.max; start += 100 {
		api := fmt.Sprintf("%s/a/projects/?n=100&S=%d", base, start)
		hdr := map[string]string{}
		if c.Token != "" {
			user, pass, _ := strings.Cut(c.Token, ":")
			hdr["Authorization"] = basicAuth(user, pass)
		}
		var batch map[string]struct {
			ID    string `json:"id"`
			State string `json:"state"`
		}
		raw, err := c.getRaw(ctx, api, hdr)
		if err != nil {
			// retry without the /a/ prefix (anonymous instance)
			api = fmt.Sprintf("%s/projects/?n=100&S=%d", base, start)
			raw, err = c.getRaw(ctx, api, nil)
			if err != nil {
				return out, err
			}
		}
		if err := json.Unmarshal(stripGerritPrefix(raw), &batch); err != nil {
			return out, err
		}
		if len(batch) == 0 {
			break
		}
		for name, p := range batch {
			out = append(out, Repo{
				Name:     name,
				FullName: name,
				CloneURL: base + "/" + name,
				Forge:    Gerrit,
				Private:  p.State == "READ_ONLY" || p.State == "HIDDEN",
			})
		}
	}
	return out, nil
}

func stripGerritPrefix(b []byte) []byte {
	s := string(b)
	if strings.HasPrefix(s, ")]}'") {
		if i := strings.IndexByte(s, '\n'); i >= 0 {
			return []byte(s[i+1:])
		}
	}
	return b
}

// listAzureDevOps enumerates repositories in an Azure DevOps organisation.
// The token is a PAT; org is taken from Org or the base URL path.
func (c *Client) listAzureDevOps(ctx context.Context) ([]Repo, error) {
	org := c.Org
	base := strings.TrimRight(c.BaseURL, "/")
	if org == "" {
		// accept https://dev.azure.com/ORG or https://ORG.visualstudio.com
		if i := strings.Index(base, "dev.azure.com/"); i >= 0 {
			org = strings.Trim(base[i+len("dev.azure.com/"):], "/")
		} else if u, err := url.Parse(base); err == nil {
			org = strings.Split(u.Hostname(), ".")[0]
		}
	}
	if org == "" {
		return nil, fmt.Errorf("azure devops: organisation required (--org)")
	}
	var out []Repo
	hdr := map[string]string{}
	if c.Token != "" {
		hdr["Authorization"] = basicAuth("", c.Token)
	}
	continuation := ""
	for page := 0; page < 20; page++ {
		api := fmt.Sprintf("https://dev.azure.com/%s/_apis/git/repositories?api-version=7.1", url.PathEscape(org))
		if continuation != "" {
			api += "&continuationToken=" + url.QueryEscape(continuation)
		}
		var batch struct {
			Value []struct {
				Name      string `json:"name"`
				RemoteURL string `json:"remoteUrl"`
				SSHURL    string `json:"sshUrl"`
				WebURL    string `json:"webUrl"`
				Project   struct {
					Name string `json:"name"`
				} `json:"project"`
			} `json:"value"`
		}
		code, raw, headers, err := c.getRawHeaders(ctx, api, hdr)
		if err != nil {
			return out, err
		}
		if code >= 400 {
			return out, fmt.Errorf("azure devops: status %d", code)
		}
		if err := json.Unmarshal(raw, &batch); err != nil {
			return out, err
		}
		if len(batch.Value) == 0 {
			break
		}
		for _, r := range batch.Value {
			clone := r.RemoteURL
			if clone == "" {
				clone = r.SSHURL
			}
			out = append(out, Repo{
				Name:     r.Name,
				FullName: r.Project.Name + "/" + r.Name,
				CloneURL: clone,
				Forge:    AzureDevOps,
			})
		}
		continuation = headers.Get("x-ms-continuationtoken")
		if continuation == "" {
			break
		}
	}
	return out, nil
}
