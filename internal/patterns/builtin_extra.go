package patterns

// extraRules are additional high-signal provider rules with distinctive
// prefixes (low false-positive rate).
func extraRules() []Pattern {
	return []Pattern{
		{
			ID: "vault-token", Description: "HashiCorp Vault token",
			Regex:       `\b(hvs\.[A-Za-z0-9_-]{20,})\b`,
			SecretGroup: 1, Keywords: []string{"hvs."}, Tags: []string{"vault"},
		},
		{
			ID: "vault-service-token", Description: "HashiCorp Vault service token (legacy s.)",
			Regex:       `(?:^|[^\w])s\.([A-Za-z0-9]{24})(?:[^\w]|$)`,
			SecretGroup: 1, Keywords: []string{"s."}, Tags: []string{"vault"},
		},
		{
			ID: "doppler-token", Description: "Doppler token",
			Regex:       `\b(dp\.(?:pt|st|sa)\.[A-Za-z0-9]{40,})\b`,
			SecretGroup: 1, Keywords: []string{"dp."}, Tags: []string{"doppler"},
		},
		{
			ID: "npm-token", Description: "npm access token",
			Regex:       `\b(npm_[A-Za-z0-9]{36})\b`,
			SecretGroup: 1, Keywords: []string{"npm_"}, Tags: []string{"npm"},
		},
		{
			ID: "pypi-token", Description: "PyPI upload token",
			Regex:       `\b(pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,})\b`,
			SecretGroup: 1, Keywords: []string{"pypi-agei"}, Tags: []string{"pypi"},
		},
		{
			ID: "docker-pat", Description: "Docker Hub personal access token",
			Regex:       `\b(dckr_pat_[A-Za-z0-9_-]{27,})\b`,
			SecretGroup: 1, Keywords: []string{"dckr_pat_"}, Tags: []string{"docker"},
		},
		{
			ID: "notion-token", Description: "Notion integration token",
			Regex:       `\b(ntn_[A-Za-z0-9]{40,}|secret_[A-Za-z0-9]{43})\b`,
			SecretGroup: 1, Keywords: []string{"ntn_", "secret_"}, Tags: []string{"notion"},
		},
		{
			ID: "airtable-pat", Description: "Airtable personal access token",
			Regex:       `\b(pat[A-Za-z0-9]{14}\.[a-f0-9]{64})\b`,
			SecretGroup: 1, Keywords: []string{"pat"}, Tags: []string{"airtable"},
		},
		{
			ID: "linear-api", Description: "Linear API key",
			Regex:       `\b(lin_api_[A-Za-z0-9]{40})\b`,
			SecretGroup: 1, Keywords: []string{"lin_api_"}, Tags: []string{"linear"},
		},
		{
			ID: "mapbox-token", Description: "Mapbox access token",
			Regex:       `\b((?:pk|sk)\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,})\b`,
			SecretGroup: 1, Keywords: []string{"pk.eyj", "sk.eyj"}, Tags: []string{"mapbox"},
		},
		{
			ID: "brevo-key", Description: "Brevo (Sendinblue) API key",
			Regex:       `\b(xkeysib-[a-f0-9]{64}-[A-Za-z0-9]{16})\b`,
			SecretGroup: 1, Keywords: []string{"xkeysib-"}, Tags: []string{"brevo"},
		},
		{
			// Format + contexte : une cle Mailjet est un 32-hex. Le mot-cle
			// (mailjet / mj_apikey) sert de filtre sur le fichier, puis TOUT
			// 32-hex du fichier est retenu - c'est ce qui permet d'attraper
			// la paire publique + privee (MJ_APIKEY_PUBLIC / _PRIVATE,
			// MAILJET_SECRET_KEY), souvents sur des lignes separees.
			ID: "mailjet-key", Description: "Mailjet API key (contexte)",
			Regex:       `(?:^|[^\w])([a-f0-9]{32})(?:[^\w]|$)`,
			SecretGroup: 1, Keywords: []string{"mailjet", "mj_apikey"}, Tags: []string{"mailjet"},
		},
		{
			ID: "groq-key", Description: "Groq API key",
			Regex:       `\b(gsk_[A-Za-z0-9]{40,})\b`,
			SecretGroup: 1, Keywords: []string{"gsk_"}, Tags: []string{"groq"},
		},
		{
			ID: "perplexity-key", Description: "Perplexity API key",
			Regex:       `\b(pplx-[A-Za-z0-9]{40,})\b`,
			SecretGroup: 1, Keywords: []string{"pplx-"}, Tags: []string{"perplexity"},
		},
		{
			ID: "sentry-auth-token", Description: "Sentry auth token",
			Regex:       `\b(sntrys_[A-Za-z0-9]{40,})\b`,
			SecretGroup: 1, Keywords: []string{"sntrys_"}, Tags: []string{"sentry"},
		},
		{
			ID: "pulumi-token", Description: "Pulumi access token",
			Regex:       `\b(pul-[a-f0-9]{40})\b`,
			SecretGroup: 1, Keywords: []string{"pul-"}, Tags: []string{"pulumi"},
		},
		{
			ID: "terraform-cloud-token", Description: "Terraform Cloud token",
			Regex:       `\b([A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9_-]{60,})\b`,
			SecretGroup: 1, Keywords: []string{"atlasv1."}, Tags: []string{"terraform"},
		},
		{
			ID: "planetscale-token", Description: "PlanetScale service token",
			Regex:       `\b(pscale_tkn_[A-Za-z0-9_\.-]{32,})\b`,
			SecretGroup: 1, Keywords: []string{"pscale_tkn_"}, Tags: []string{"planetscale"},
		},
		{
			ID: "neon-api-key", Description: "Neon API key",
			Regex:       `\b(napi_[A-Za-z0-9]{32,})\b`,
			SecretGroup: 1, Keywords: []string{"napi_"}, Tags: []string{"neon"},
		},
		{
			ID: "render-api-key", Description: "Render API key",
			Regex:       `\b(rnd_[A-Za-z0-9]{20,})\b`,
			SecretGroup: 1, Keywords: []string{"rnd_"}, Tags: []string{"render"},
		},
		{
			ID: "cloudinary-url", Description: "Cloudinary URL with credentials",
			Regex:       `cloudinary://([0-9]{15}):([A-Za-z0-9_-]{40,})@([a-z0-9]+)`,
			SecretGroup: 2, Keywords: []string{"cloudinary://"}, Tags: []string{"cloudinary"},
		},
		{
			ID: "azure-storage-key", Description: "Azure storage account key",
			Regex:       `AccountKey=([A-Za-z0-9+/=]{88})`,
			SecretGroup: 1, Keywords: []string{"accountkey="}, Tags: []string{"azure"},
		},
		{
			ID: "azure-connection-string", Description: "Azure storage connection string",
			Regex:       `DefaultEndpointsProtocol=https;AccountName=([a-z0-9]{3,24});`,
			SecretGroup: 1, Keywords: []string{"defaultendpointsprotocol"}, Tags: []string{"azure"},
		},
		{
			ID: "azure-sas-token", Description: "Azure SAS token",
			Regex:       `[?&]sig=([A-Za-z0-9%+/=]{40,})`,
			SecretGroup: 1, Keywords: []string{"sig="}, Tags: []string{"azure"},
		},
		{
			ID: "aws-cognito-pool", Description: "AWS Cognito user pool id",
			Regex:       `\b([a-z]{2}-[a-z]+-\d:[0-9a-f-]{36})\b`,
			SecretGroup: 1, Keywords: []string{"cognito"}, Tags: []string{"aws"},
		},
		{
			ID: "braintree-token", Description: "Braintree access token",
			Regex:       `\b(access_token\$(?:production|sandbox)\$[a-z0-9]{16}\$[a-f0-9]{32})\b`,
			SecretGroup: 1, Keywords: []string{"access_token$"}, Tags: []string{"braintree"},
		},
		{
			ID: "clerk-secret", Description: "Clerk secret key",
			Regex:       `\b(sk_(?:test|live)_[A-Za-z0-9]{40,})\b`,
			SecretGroup: 1, Keywords: []string{"sk_test_", "sk_live_"}, Tags: []string{"clerk"},
		},
		{
			ID: "auth0-domain", Description: "Auth0 tenant domain",
			Regex:       `\b([a-z0-9-]+\.(?:us|eu|au|jp)\.auth0\.com)\b`,
			SecretGroup: 1, Keywords: []string{".auth0.com"}, Tags: []string{"auth0"},
		},
		{
			ID: "okta-domain", Description: "Okta tenant domain",
			Regex:       `\b([a-z0-9-]+\.okta(?:preview|-emea)?\.com)\b`,
			SecretGroup: 1, Keywords: []string{".okta"}, Tags: []string{"okta"},
		},
		{
			ID: "supabase-url", Description: "Supabase project URL",
			Regex:       `\b(https://[a-z0-9]{20}\.supabase\.co)\b`,
			SecretGroup: 1, Keywords: []string{".supabase.co"}, Tags: []string{"supabase"},
		},
		{
			ID: "firebase-config-key", Description: "Firebase web config apiKey",
			Regex:       `(?i)"?apiKey"?\s*[:=]\s*"?(AIza[A-Za-z0-9_-]{35})`,
			SecretGroup: 1, Keywords: []string{"apikey"}, Tags: []string{"firebase"},
		},
		{
			ID: "sendgrid-inbound", Description: "SendGrid inbound webhook",
			Regex:    `https://[a-z0-9-]+\.sendgrid\.net/[A-Za-z0-9/_-]{10,}`,
			Keywords: []string{"sendgrid.net"}, Tags: []string{"sendgrid"},
		},
		{
			ID: "elastic-cloud", Description: "Elastic Cloud id",
			Regex:       `\b([a-z0-9_-]+:ZXhhbXBsZQ[A-Za-z0-9=]*|[a-z0-9]{32}:ZXhhbXBsZQ)\b`,
			SecretGroup: 1, Keywords: []string{"elastic"}, Tags: []string{"elastic"},
		},
	}
}
