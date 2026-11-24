package patterns

// Builtin returns the full default rule set: hand-written rules plus the
// rules recovered from the original scanner binary. Rules use the
// `(?:^|[^\w]) … (?:[^\w]|$)` boundary form to avoid matching inside larger
// tokens.
func Builtin() []Pattern {
	return append(humanRules(), extractedRules()...)
}

// extractedRules are provider rules recovered from the reference binary.
func extractedRules() []Pattern {
	return []Pattern{
		// ---- Forges ----
		{
			ID: "gitea-token", Description: "Gitea access token",
			Regex:       `(?:^|[^\w])(gt[acops]_[a-zA-Z0-9]{40})(?:[^\w]|$)`,
			SecretGroup: 1, Keywords: []string{"gt"}, Tags: []string{"gitea"},
		},
		{
			ID: "gitea-url-cred", Description: "Gitea remote with credentials",
			Regex:       `(?mi)(?:^|\s)url\s*=\s*https?://([^:@\s]+):([^@\s]+)@([^/\s]*gitea[^/\s]*)`,
			SecretGroup: 2, Keywords: []string{"gitea"}, Tags: []string{"gitea"},
		},
		{
			ID: "gitlab-deploy-token", Description: "GitLab deploy token",
			Regex:       `(?:^|[^\w])(gldt-[0-9a-zA-Z\-_]{20,})(?:[^\w]|$)`,
			SecretGroup: 1, Keywords: []string{"gldt-"}, Tags: []string{"gitlab"},
		},
		{
			ID: "gitlab-runner-token", Description: "GitLab runner token",
			Regex:       `(?:^|[^\w])(glrt-[0-9a-zA-Z\-_]{20,})(?:[^\w]|$)`,
			SecretGroup: 1, Keywords: []string{"glrt-"}, Tags: []string{"gitlab"},
		},
		{
			ID: "gitlab-scim-token", Description: "GitLab SCIM / SOAT token",
			Regex:       `(?:^|[^\w])(glsoat-[0-9a-zA-Z\-_]{20,})(?:[^\w]|$)`,
			SecretGroup: 1, Keywords: []string{"glsoat-"}, Tags: []string{"gitlab"},
		},
		{
			ID: "gitlab-ci-token", Description: "GitLab CI/CD variable token",
			Regex:       `(?:^|[^\w])(glc_[a-zA-Z0-9_\-]{32,})(?:[^\w]|$)`,
			SecretGroup: 1, Keywords: []string{"glc_"}, Tags: []string{"gitlab"},
		},
		{
			ID: "gitlab-oauth", Description: "GitLab OAuth / personal token (gl)",
			Regex:       `(?:^|[^\w])(gl[a-z]{2,5}-[0-9A-Za-z]{20})(?:[^\w]|$)`,
			SecretGroup: 1, Keywords: []string{"gl"}, Tags: []string{"gitlab"},
		},

		// ---- Git exposure ----
		{
			ID: "git-exposed-head", Description: "Exposed .git HEAD",
			Regex:       `(?m)^ref:\s+refs/heads/([A-Za-z0-9._/\-]+)`,
			SecretGroup: 1, Keywords: []string{"ref:"}, Tags: []string{"git"},
		},
		{
			ID: "git-config-remote", Description: "Git remote URL in .git/config",
			Regex:       `(?mi)^\s*url\s*=\s*(https?://(?:[^:@/\s]+(?::[^@/\s]+)?@)?[^\s]+)`,
			SecretGroup: 1, Keywords: []string{"url"}, Tags: []string{"git"},
		},
		{
			ID: "git-credentials", Description: "Plain ~/.git-credentials entry",
			Regex:       `https?://([^:@/\s"',]+):([^@\s"',]+)@[^\s"',]+`,
			SecretGroup: 2, Keywords: []string{"@"}, Tags: []string{"git"},
		},

		// ---- Shopify variants ----
		{
			ID: "shopify-password", Description: "Shopify private app password",
			Regex:       `(?:^|[^\w])(shppa_[a-fA-F0-9]{32}|shpss_[a-fA-F0-9]{32})(?:[^\w]|$)`,
			SecretGroup: 1, Keywords: []string{"shppa_", "shpss_"}, Tags: []string{"shopify"},
		},
		{
			ID: "shopify-store", Description: "Shopify store reference",
			Regex:       `SHOPIFY_(?:STORE|SHOP|DOMAIN)\s*[=:]\s*["']?(\w+)`,
			SecretGroup: 1, Keywords: []string{"shopify_"}, Tags: []string{"shopify"},
		},

		// ---- AWS extras ----
		{
			ID: "aws-access-key-boundary", Description: "AWS Access Key ID (strict)",
			Regex:       `(?:^|[^\w])((?:AKIA|ASIA)[A-Z0-9]{16})(?:[^\w]|$)`,
			SecretGroup: 1, Keywords: []string{"akia", "asia"}, Tags: []string{"aws"},
		},
		{
			ID: "aws-arn-role", Description: "AWS IAM role ARN",
			Regex:    `arn:aws:iam::\d{12}:role/[\w+=,.@/\-]+`,
			Keywords: []string{"arn:aws:iam"}, Tags: []string{"aws"},
		},
		{
			ID: "aws-arn", Description: "AWS ARN",
			Regex:    `arn:aws[a-z-]*:[a-z0-9-]+:[a-z0-9-]*:(?:[0-9]{12})?:[^\s"'<>]+`,
			Keywords: []string{"arn:aws"}, Tags: []string{"aws"},
		},
		{
			ID: "aws-account-id", Description: "AWS account id (in context)",
			Regex:       `(?i)account[\s:=#'"]{0,12}([0-9]{12})`,
			SecretGroup: 1, Keywords: []string{"account"}, Tags: []string{"aws"},
		},
		{
			ID: "aws-presigned-url", Description: "AWS S3 presigned URL (X-Amz-Credential)",
			Regex:       `X-Amz-Credential=([A-Za-z0-9%_\-/+=]+)`,
			SecretGroup: 1, Keywords: []string{"x-amz-credential"}, Tags: []string{"aws", "s3"},
		},
		{
			ID: "s3-bucket-host", Description: "S3 bucket hostname",
			Regex:       `(?:https?://)?([a-z0-9][a-z0-9.\-]{1,61}[a-z0-9])\.s3(?:[.\-][a-z0-9\-]+)*\.amazonaws\.com`,
			SecretGroup: 1, Keywords: []string{".s3", "amazonaws"}, Tags: []string{"s3", "bucket"},
		},
		{
			ID: "s3-path-style", Description: "S3 path-style bucket URL",
			Regex:       `https?://s3(?:[.\-][a-z0-9-]+)*\.amazonaws\.com/([a-z0-9][a-z0-9.\-]{1,61}[a-z0-9])(?:/|["'?]|$)`,
			SecretGroup: 1, Keywords: []string{"s3.", "s3-", "//s3"}, Tags: []string{"s3", "bucket"},
		},

		// ---- Messaging ----
		{
			ID: "telegram-bot-token-strict", Description: "Telegram bot token (strict)",
			Regex:       `(?:^|[^\w])([0-9]{8,12}:[a-zA-Z0-9_-]{35})(?:[^\w]|$)`,
			SecretGroup: 1, Keywords: []string{":"}, Tags: []string{"telegram"},
		},
		{
			ID: "discord-bot-token-strict", Description: "Discord bot token (strict)",
			Regex:       `(?:^|[^\w])([MN][A-Za-z\d]{23,}\.[A-Za-z\d_-]{6}\.[A-Za-z\d_-]{27,})(?:[^\w]|$)`,
			SecretGroup: 1, Keywords: []string{"m", "n"}, Tags: []string{"discord"}, Entropy: 3.0,
		},
		{
			ID: "slack-token-strict", Description: "Slack token (strict)",
			Regex:       `(?:^|[^\w])(xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*|xoxe\.xoxp-[0-9]+-[a-zA-Z0-9-]+|xoxe-[0-9]+-[a-zA-Z0-9-]+)(?:[^\w]|$)`,
			SecretGroup: 1, Keywords: []string{"xox"}, Tags: []string{"slack"},
		},

		// ---- Mail ----
		{
			ID: "mailchimp-token-strict", Description: "Mailchimp API key (strict)",
			Regex:       `(?:^|[^\w])([0-9a-f]{32}-(?:us|eu)[0-9]{1,2})(?:[^\w]|$)`,
			SecretGroup: 1, Keywords: []string{"-us", "-eu"}, Tags: []string{"mailchimp"},
		},
		{
			ID: "sendgrid-token-strict", Description: "SendGrid API key (strict)",
			Regex:       `(?:^|[^\w])(SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43})(?:[^\w]|$)`,
			SecretGroup: 1, Keywords: []string{"sg."}, Tags: []string{"sendgrid"},
		},
		{
			ID: "smtp-port", Description: "SMTP credential with port",
			Regex:       `(?:^|[^\w])(25|465|587|2525)(?:[^\w]|$)`,
			SecretGroup: 1, Keywords: []string{"smtp"}, Tags: []string{"smtp"},
		},

		// ---- Infra / misc ----
		{
			ID: "newrelic-license-strict", Description: "New Relic API key (strict)",
			Regex:       `(?:^|[^\w])(NRAK-[A-Z0-9]{27})(?:[^\w]|$)`,
			SecretGroup: 1, Keywords: []string{"nrak-"}, Tags: []string{"newrelic"},
		},
		{
			ID: "digitalocean-token-strict", Description: "DigitalOcean token (strict)",
			Regex:       `(?:^|[^\w])(dop_v1_[a-f0-9]{64}|doo_v1_[a-f0-9]{64})(?:[^\w]|$)`,
			SecretGroup: 1, Keywords: []string{"do"}, Tags: []string{"digitalocean"},
		},
		{
			ID: "openai-token-strict", Description: "OpenAI key (strict)",
			Regex:       `(?:^|[^\w])(sk-[A-Za-z0-9\-]{32,})(?:[^\w]|$)`,
			SecretGroup: 1, Keywords: []string{"sk-"}, Tags: []string{"openai"},
		},
		{
			ID: "anthropic-token-strict", Description: "Anthropic key (strict)",
			Regex:       `(?:^|[^\w])(sk-ant-[A-Za-z0-9_\-]{24,200})(?:[^\w]|$)`,
			SecretGroup: 1, Keywords: []string{"sk-ant"}, Tags: []string{"anthropic"},
		},
		{
			ID: "xai-token-strict", Description: "xAI key (strict)",
			Regex:       `(?:^|[^\w])(xai-[A-Za-z0-9_\-]{32,})(?:[^\w]|$)`,
			SecretGroup: 1, Keywords: []string{"xai-"}, Tags: []string{"xai"},
		},

		// ---- Source-level idioms ----
		{
			ID: "php-array-secret", Description: "PHP array secret assignment",
			Regex:       `(?i)(?:password|secret|key|token)'\s*=>\s*'([^']{5,})'`,
			SecretGroup: 1, Keywords: []string{"=>"}, Tags: []string{"php"},
			Allowlist: []string{
				`(?i)^(secret|real-secret|wrong-key|anything-at-all|value|test|foo|bar|baz|null|true|false)$`,
				`(?i)synthetic`,
				`^[a-z_\-]+:$`,
			},
		},
		{
			ID: "js-fetch-endpoint", Description: "JavaScript fetch/endpoint",
			Regex:       `(?:fetch|XMLHttpRequest)\s*\(\s*["']([^"']+)["']`,
			SecretGroup: 1, Keywords: []string{"fetch", "xmlhttprequest"}, Tags: []string{"js"},
		},
		{
			ID: "asset-js", Description: "JS asset reference",
			Regex:    `(?:/|https?://)[^"'\s]*\.(?:js|mjs|cjs)(?:["'` + "`" + `]|$)`,
			Keywords: []string{".js"}, Tags: []string{"js"},
		},
		{
			ID: "internal-host", Description: "Internal / cluster hostname",
			Regex:    `[a-zA-Z0-9_-]+(?:\.[a-zA-Z0-9_-]+)*\.(?:svc\.cluster\.local|cluster\.local|internal|local)(?::\d+)?`,
			Keywords: []string{".local", ".internal"}, Tags: []string{"internal"},
		},
		{
			ID: "base64-blob", Description: "Embedded base64 blob",
			Regex:       `(?:base64:)?([a-zA-Z0-9+/=]{32,64})(?:[^\w]|$)`,
			SecretGroup: 1, Keywords: []string{"base64"}, Tags: []string{"blob"}, Entropy: 3.0,
		},
		{
			ID: "hex-blob", Description: "Embedded hex blob",
			Regex:    `(?:[0-9a-fA-F]{2}){20,}`,
			Keywords: []string{"0"}, Tags: []string{"blob"}, Entropy: 2.5,
		},
		{
			ID: "unix-user", Description: "Privileged unix user",
			Regex:    `^(www-data|root|apache|nginx|nobody|daemon)\s*$`,
			Keywords: []string{"root"}, Tags: []string{"system"},
		},
		{
			ID: "gcp-service-account-email", Description: "GCP service account email",
			Regex:    `[\w.\-]+@[\w.\-]+\.iam\.gserviceaccount\.com`,
			Keywords: []string{"gserviceaccount"}, Tags: []string{"gcp"},
		},
		{
			ID: "google-oauth-client", Description: "Google OAuth client id",
			Regex:    `[0-9]{12}-[a-z0-9]{32}\.apps\.googleusercontent\.com`,
			Keywords: []string{"googleusercontent"}, Tags: []string{"gcp"},
		},
		{
			ID: "firebase-host", Description: "Firebase Realtime DB host",
			Regex:    `[a-z0-9-]+\.firebaseio\.com`,
			Keywords: []string{"firebaseio"}, Tags: []string{"firebase"},
		},
		{
			ID: "ssh-url-cred", Description: "SSH URL with user",
			Regex:       `ssh://([^@]+)@([^/:\s]+)(?::(\d+))?(/[^\s]*)?`,
			SecretGroup: 1, Keywords: []string{"ssh://"}, Tags: []string{"ssh"},
		},
		{
			ID: "credit-card", Description: "Credit card number",
			Regex:       `(?:^|[^\d])(4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11})(?:[^\d]|$)`,
			SecretGroup: 1,
			Keywords:    []string{"4", "5", "3", "6"}, Tags: []string{"pci"},
		},
	}
}
