package checkers

import (
	"context"
	"os"
	"strings"
)

// cloud_extra.go adds verification for Azure DevOps PATs and HashiCorp Vault
// tokens. Vault has no fixed address, so the finding host (and VAULT_ADDR) is
// used as a hint.
func init() {
	// Azure DevOps personal access token (global profile endpoint)
	Register(&httpChecker{
		name: "azuredevops", tags: tagsOf("azure"),
		ruleIDs: tags0("azure-devops-pat"),
		fn: func(ctx context.Context, secret string) Result {
			var out struct {
				DisplayName  string `json:"displayName"`
				EmailAddress string `json:"emailAddress"`
			}
			code, err := getJSON(ctx,
				"https://app.vssps.visualstudio.com/_apis/profile/profiles/me?api-version=7.1",
				map[string]string{"Authorization": "Basic " + base64Encode(":"+secret)}, &out)
			if err != nil {
				return Result{Err: err.Error()}
			}
			if !ok(code) {
				return Result{}
			}
			id := out.EmailAddress
			if id == "" {
				id = out.DisplayName
			}
			return Result{Verified: true, Identity: id}
		},
	})

	Register(&vaultChecker{})
}

type vaultChecker struct{}

func (v *vaultChecker) Name() string { return "vault" }

func (v *vaultChecker) Match(ruleID string, tags []string) bool {
	if ruleID == "vault-token" {
		return true
	}
	for _, t := range tags {
		if t == "vault" {
			return true
		}
	}
	return false
}

func (v *vaultChecker) Check(ctx context.Context, secret string, meta map[string]string) Result {
	for _, base := range vaultCandidates(meta) {
		code, body, err := getBody(ctx, base+"/v1/auth/token/lookup-self",
			map[string]string{"X-Vault-Token": secret})
		if err != nil || code != 200 {
			continue
		}
		id := betweenStr(string(body), `"display_name":"`, `"`)
		if id == "" {
			id = base
		}
		return Result{Verified: true, Identity: id, Meta: map[string]string{"addr": base}}
	}
	return Result{Err: "no reachable vault address"}
}

// vaultCandidates lists plausible Vault addresses from the finding context.
func vaultCandidates(meta map[string]string) []string {
	var out []string
	add := func(s string) {
		s = strings.TrimRight(strings.TrimSpace(s), "/")
		if s == "" {
			return
		}
		for _, e := range out {
			if e == s {
				return
			}
		}
		out = append(out, s)
	}
	if meta != nil {
		add(meta["addr"])
	}
	add(os.Getenv("VAULT_ADDR"))
	host := ""
	if meta != nil {
		host = meta["host"]
	}
	if host != "" {
		add("https://" + host)
		if !strings.HasPrefix(host, "vault.") {
			add("https://vault." + host)
		}
		add("http://" + host + ":8200")
	}
	return out
}

func betweenStr(s, a, b string) string {
	i := strings.Index(s, a)
	if i < 0 {
		return ""
	}
	s = s[i+len(a):]
	j := strings.Index(s, b)
	if j < 0 {
		return s
	}
	return s[:j]
}
