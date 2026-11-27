package checkers

import (
	"context"
	"fmt"
	"strings"
)

// extra.go registers additional provider verifications. Endpoints are chosen to
// be cheap and side-effect free.
func init() {
	def := func(name string, ruleIDs []string, tags []string, fn func(ctx context.Context, secret string) Result) {
		Register(&httpChecker{
			name:    name,
			tags:    tagsOf(tags...),
			ruleIDs: tags0(ruleIDs...),
			fn:      fn,
		})
	}

	bearer := func(url, identityPath string) func(context.Context, string) Result {
		return func(ctx context.Context, secret string) Result {
			var out map[string]any
			code, err := getJSON(ctx, url, map[string]string{"Authorization": "Bearer " + secret}, &out)
			if err != nil {
				return Result{Err: err.Error()}
			}
			return Result{Verified: ok(code), Identity: pick(out, identityPath)}
		}
	}

	def("groq", []string{"groq-key"}, []string{"groq"}, bearer("https://api.groq.com/openai/v1/models", ""))
	def("perplexity", []string{"perplexity-key"}, []string{"perplexity"}, bearer("https://api.perplexity.ai/models", ""))
	def("replicate", []string{"replicate-token"}, []string{"replicate"}, bearer("https://api.replicate.com/v1/account", "username"))
	def("pulumi", []string{"pulumi-token"}, []string{"pulumi"}, bearer("https://api.pulumi.com/api/user", "githubLogin"))
	def("doppler", []string{"doppler-token"}, []string{"doppler"}, bearer("https://api.doppler.com/v3/me", "email"))
	def("cloudflare", []string{"cloudflare-token"}, []string{"cloudflare"}, func(ctx context.Context, secret string) Result {
		code, _, err := getBody(ctx, "https://api.cloudflare.com/client/v4/user/tokens/verify",
			map[string]string{"Authorization": "Bearer " + secret})
		if err != nil {
			return Result{Err: err.Error()}
		}
		return Result{Verified: ok(code)}
	})

	def("huggingface", []string{"huggingface-token"}, []string{"huggingface"}, bearer("https://huggingface.co/api/whoami-v2", "name"))
	def("npm", []string{"npm-token"}, []string{"npm"}, bearer("https://registry.npmjs.org/-/whoami", "username"))
	def("sentry", []string{"sentry-auth-token"}, []string{"sentry"}, bearer("https://sentry.io/api/0/", ""))
	def("terraform-cloud", []string{"terraform-cloud-token"}, []string{"terraform"}, bearer("https://app.terraform.io/api/v2/account/details", "data.attributes.username"))
	def("planetscale", []string{"planetscale-token"}, []string{"planetscale"}, bearer("https://api.planetscale.com/v1/organizations", ""))
	def("neon", []string{"neon-api-key"}, []string{"neon"}, bearer("https://console.neon.tech/api/v2/projects", ""))
	def("render", []string{"render-api-key"}, []string{"render"}, bearer("https://api.render.com/v1/owners", ""))

	def("notion", []string{"notion-token"}, []string{"notion"}, func(ctx context.Context, secret string) Result {
		var out map[string]any
		code, err := getJSON(ctx, "https://api.notion.com/v1/users/me", map[string]string{
			"Authorization": "Bearer " + secret, "Notion-Version": "2022-06-28",
		}, &out)
		if err != nil {
			return Result{Err: err.Error()}
		}
		return Result{Verified: ok(code)}
	})

	def("airtable", []string{"airtable-pat"}, []string{"airtable"}, bearer("https://api.airtable.com/v0/meta/whoami", "email"))

	def("brevo", []string{"brevo-key"}, []string{"brevo"}, func(ctx context.Context, secret string) Result {
		var out map[string]any
		code, err := getJSON(ctx, "https://api.brevo.com/v3/account", map[string]string{"api-key": secret}, &out)
		if err != nil {
			return Result{Err: err.Error()}
		}
		return Result{Verified: ok(code), Identity: pick(out, "email")}
	})

	def("mapbox", []string{"mapbox-token"}, []string{"mapbox"}, func(ctx context.Context, secret string) Result {
		var out map[string]any
		code, err := getJSON(ctx, "https://api.mapbox.com/tokens/v2?access_token="+secret, nil, &out)
		if err != nil {
			return Result{Err: err.Error()}
		}
		return Result{Verified: ok(code)}
	})

	def("pypi", []string{"pypi-token"}, []string{"pypi"}, func(ctx context.Context, secret string) Result {
		code, _, err := getBody(ctx, "https://pypi.org/", map[string]string{
			"Authorization": "Basic " + base64Encode("__token__:"+secret),
		})
		if err != nil {
			return Result{Err: err.Error()}
		}
		return Result{Verified: ok(code)}
	})
}

// pick reads a dotted path from a decoded JSON object.
func pick(m map[string]any, path string) string {
	if m == nil || path == "" {
		return ""
	}
	cur := any(m)
	for _, part := range strings.Split(path, ".") {
		asMap, ok := cur.(map[string]any)
		if !ok {
			return ""
		}
		cur, ok = asMap[part]
		if !ok {
			return ""
		}
	}
	return fmt.Sprintf("%v", cur)
}
