package patterns

// humanRules returns the hand-written subset of the default rule set.
func humanRules() []Pattern {
	return []Pattern{
		// ---- Cloud / infra ----
		{
			ID: "aws-secret-access-key", Description: "AWS Secret Access Key",
			Regex:       `(?i)aws_?(?:secret)?_?(?:access)?_?key["'\s:=]{1,6}([A-Za-z0-9/+=]{40})\b`,
			SecretGroup: 1,
			Keywords:    []string{"aws"}, Tags: []string{"aws"},
		},
		{
			ID: "aws-session-token", Description: "AWS Session Token",
			Regex:    `(?i)(?:aws_session_token|aws_security_token)["'\s:=]{1,6}([A-Za-z0-9/+=]{100,})`,
			Keywords: []string{"aws_session", "aws_security"}, Tags: []string{"aws"},
		},
		{
			ID: "gcp-api-key", Description: "Google API Key",
			Regex:    `\b(AIza[0-9A-Za-z\-_]{30,})\b`,
			Keywords: []string{"aiza"}, Tags: []string{"gcp"}, Entropy: 3.5,
		},
		{
			ID: "gcp-service-account", Description: "GCP Service Account JSON",
			Regex:    `"type":\s*"service_account"`,
			Keywords: []string{"service_account"}, Tags: []string{"gcp"},
		},
		{
			ID: "github-pat", Description: "GitHub Personal Access Token",
			Regex:    `\b(ghp_[A-Za-z0-9]{36})\b`,
			Keywords: []string{"ghp_"}, Tags: []string{"github"},
		},
		{
			ID: "github-oauth", Description: "GitHub OAuth / app / installation token",
			Regex:    `\b(gh[ousr]_[A-Za-z0-9]{20,255})\b`,
			Keywords: []string{"gho_", "ghu_", "ghs_", "ghr_"}, Tags: []string{"github"},
		},
		{
			ID: "github-basic-cred", Description: "Base64 x-access-token credential",
			Regex:       `\b(eC1hY2Nlc3MtdG9rZW46[A-Za-z0-9+/=]{12,})\b`,
			SecretGroup: 1, Keywords: []string{"ec1hy2nlc3mtdg9rzw46"}, Tags: []string{"github"},
		},
		{
			ID: "github-fine-grained-pat", Description: "GitHub Fine-Grained PAT",
			Regex:    `\b(github_pat_[A-Za-z0-9_]{22,})\b`,
			Keywords: []string{"github_pat_"}, Tags: []string{"github"},
		},
		{
			ID: "gitlab-pat", Description: "GitLab Personal Access Token",
			Regex:    `\b(glpat-[A-Za-z0-9_\-]{20})\b`,
			Keywords: []string{"glpat"}, Tags: []string{"gitlab"},
		},
		{
			ID: "gitlab-pipeline-token", Description: "GitLab Pipeline Trigger Token",
			Regex:    `\b(glptt-[A-Za-z0-9_\-]{20})\b`,
			Keywords: []string{"glptt"}, Tags: []string{"gitlab"},
		},
		{
			ID: "bitbucket-app-password", Description: "Bitbucket app password",
			Regex:    `(?i)bitbucket[^A-Za-z0-9]{0,20}([A-Za-z0-9]{20,})`,
			Keywords: []string{"bitbucket"}, Tags: []string{"bitbucket"},
		},
		{
			ID: "azure-devops-pat", Description: "Azure DevOps PAT",
			Regex:    `\b([a-z0-9]{52})\b`,
			Keywords: []string{"devops", "azure"}, Tags: []string{"azure"},
			Entropy: 3.5,
		},
		{
			ID: "vercel-token", Description: "Vercel Token",
			Regex:    `\b(vercel_[A-Za-z0-9]{24,})\b`,
			Keywords: []string{"vercel"}, Tags: []string{"vercel"},
		},
		{
			ID: "netlify-token", Description: "Netlify Access Token",
			Regex:    `\b(nfp_[A-Za-z0-9]{40})\b`,
			Keywords: []string{"nfp_"}, Tags: []string{"netlify"},
		},
		{
			ID: "heroku-api-key", Description: "Heroku API Key",
			Regex:    `(?i)heroku[^A-Za-z0-9]{0,20}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})`,
			Keywords: []string{"heroku"}, Tags: []string{"heroku"},
		},

		// ---- Payments / commerce ----
		{
			ID: "stripe-secret-key", Description: "Stripe Secret Key",
			Regex:    `\b([srp]k_(?:live|test)_[0-9a-zA-Z]{24,})\b`,
			Keywords: []string{"sk_live", "sk_test", "rk_live", "rk_test"}, Tags: []string{"stripe"},
		},
		{
			ID: "square-access-token", Description: "Square Access Token",
			Regex:    `\b(sq0atp-[0-9A-Za-z\-_]{22})\b`,
			Keywords: []string{"sq0atp"}, Tags: []string{"square"},
		},
		{
			ID: "square-oauth-secret", Description: "Square OAuth Secret",
			Regex:    `\b(sq0csp-[0-9A-Za-z\-_]{43})\b`,
			Keywords: []string{"sq0csp"}, Tags: []string{"square"},
		},
		{
			ID: "shopify-access-token", Description: "Shopify Access Token",
			Regex:    `\b(shpat_[a-fA-F0-9]{32})\b`,
			Keywords: []string{"shpat_"}, Tags: []string{"shopify"},
		},
		{
			ID: "shopify-custom-app", Description: "Shopify Custom App Token",
			Regex:    `\b(shpca_[a-fA-F0-9]{32})\b`,
			Keywords: []string{"shpca_"}, Tags: []string{"shopify"},
		},

		// ---- Mail / messaging ----
		{
			ID: "mailgun-api-key", Description: "Mailgun API Key",
			Regex:    `\b(key-[0-9a-zA-Z]{32})\b`,
			Keywords: []string{"key-"}, Tags: []string{"mailgun"},
		},
		{
			ID: "postmark-token", Description: "Postmark Server Token",
			Regex:    `(?i)postmark[^A-Za-z0-9]{0,30}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})`,
			Keywords: []string{"postmark"}, Tags: []string{"postmark"},
		},
		{
			ID: "sparkpost-api-key", Description: "SparkPost API Key",
			Regex:    `\b([0-9a-fA-F]{40})\b`,
			Keywords: []string{"sparkpost"}, Tags: []string{"sparkpost"}, Entropy: 3.5,
		},
		{
			ID: "slack-webhook", Description: "Slack Incoming Webhook",
			Regex:    `(https://hooks\.slack\.com/services/[A-Za-z0-9/]{40,})`,
			Keywords: []string{"hooks.slack.com"}, Tags: []string{"slack"},
		},
		{
			ID: "twilio-api-key", Description: "Twilio API Key SID",
			Regex:    `\b(SK[0-9a-fA-F]{32})\b`,
			Keywords: []string{"sk"}, Tags: []string{"twilio"},
		},
		{
			ID: "twilio-account-sid", Description: "Twilio Account SID",
			Regex:    `\b(AC[0-9a-fA-F]{32})\b`,
			Keywords: []string{"ac0", "ac1", "ac2", "ac3", "ac4", "ac5", "ac6", "ac7", "ac8", "ac9"},
			Tags:     []string{"twilio"},
		},
		// ---- AI providers ----
		{
			ID: "huggingface-token", Description: "HuggingFace Token",
			Regex:    `\b(hf_[A-Za-z0-9]{34,})\b`,
			Keywords: []string{"hf_"}, Tags: []string{"huggingface"},
		},
		{
			ID: "replicate-token", Description: "Replicate API Token",
			Regex:    `\b(r8_[A-Za-z0-9]{37,})\b`,
			Keywords: []string{"r8_"}, Tags: []string{"replicate"},
		},

		// ---- Observability ----
		{
			ID: "newrelic-license", Description: "New Relic License Key",
			Regex:    `(?i)new_relic_license_key["'\s:=]{1,6}([a-f0-9]{40})`,
			Keywords: []string{"new_relic_license", "newrelic"}, Tags: []string{"newrelic"},
		},
		{
			ID: "grafana-service-token", Description: "Grafana Service Account Token",
			Regex:    `\b(glsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8})\b`,
			Keywords: []string{"glsa_"}, Tags: []string{"grafana"},
		},
		{
			ID: "datadog-api-key", Description: "Datadog API Key",
			Regex:    `(?i)(?:datadog|dd)_?api_?key["'\s:=]{1,6}([a-f0-9]{32})\b`,
			Keywords: []string{"datadog", "dd_api"}, Tags: []string{"datadog"},
		},
		{
			ID: "sentry-dsn", Description: "Sentry DSN",
			Regex:    `(https://[0-9a-f]{32}@[a-z0-9.\-]+/[0-9]+)`,
			Keywords: []string{"sentry", "ingest"}, Tags: []string{"sentry"},
		},

		// ---- Crypto / keys ----
		{
			ID: "private-key", Description: "Private Key",
			Regex:    `-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----`,
			Keywords: []string{"private key"}, Tags: []string{"key"},
		},
		{
			ID: "rsa-private-key", Description: "RSA Private Key",
			Regex:    `-----BEGIN RSA PRIVATE KEY-----`,
			Keywords: []string{"rsa private"}, Tags: []string{"key"},
		},
		{
			ID: "openssh-private-key", Description: "OpenSSH Private Key",
			Regex:    `-----BEGIN OPENSSH PRIVATE KEY-----`,
			Keywords: []string{"openssh private"}, Tags: []string{"key"},
		},
		{
			ID: "pgp-private-key", Description: "PGP Private Key Block",
			Regex:    `-----BEGIN PGP PRIVATE KEY BLOCK-----`,
			Keywords: []string{"pgp private"}, Tags: []string{"key"},
		},
		{
			ID: "jwt", Description: "JSON Web Token",
			Regex:    `\b(eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,})\b`,
			Keywords: []string{"eyj"}, Tags: []string{"jwt"},
		},

		// ---- Connection strings ----
		{
			ID: "mongodb-uri", Description: "MongoDB connection string with credentials",
			Regex:    `(mongodb(?:\+srv)?://[^:\s/@]+:[^@\s/]+@[^\s"']+)`,
			Keywords: []string{"mongodb"}, Tags: []string{"db"},
		},
		{
			ID: "postgres-uri", Description: "PostgreSQL connection string with credentials",
			Regex:    `(postgres(?:ql)?://[^:\s/@]+:[^@\s/]+@[^\s"']+)`,
			Keywords: []string{"postgres"}, Tags: []string{"db"},
		},
		{
			ID: "mysql-uri", Description: "MySQL connection string with credentials",
			Regex:    `(mysql://[^:\s/@]+:[^@\s/]+@[^\s"']+)`,
			Keywords: []string{"mysql"}, Tags: []string{"db"},
		},
		{
			ID: "redis-uri", Description: "Redis connection string with credentials",
			Regex:    `(rediss?://[^:\s/@]+:[^@\s/]+@[^\s"']+)`,
			Keywords: []string{"redis"}, Tags: []string{"db"},
		},
		{
			ID: "amqp-uri", Description: "AMQP connection string with credentials",
			Regex:    `(amqps?://[^:\s/@]+:[^@\s/]+@[^\s"']+)`,
			Keywords: []string{"amqp"}, Tags: []string{"db"},
		},
		{
			ID: "http-basic-auth-url", Description: "URL with embedded credentials",
			Regex:    `(?i)\b[a-z][a-z0-9+.\-]*://[^:@/\s"',]+:[^@\s"',]+@[a-z0-9.\-]+\.[a-z]{2,}`,
			Keywords: []string{"://"}, Tags: []string{"url"},
		},

		// ---- Generic env access ----
		{
			ID: "getenv", Description: "Environment variable access",
			Regex:    `(?i)(?:getenv|process\.env\.|os\.environ\[)\(?\s*['"]([A-Z0-9_]{3,})['"]`,
			Keywords: []string{"getenv", "process.env", "environ"}, Tags: []string{"env"},
		},

		// ---- Generic high-entropy assignments ----
		{
			ID: "generic-api-key", Description: "Generic API key / secret assignment",
			Regex:       `(?i)(?:api[_-]?key|apikey|secret|token|passwd|password|pwd|auth)["'\s]{0,4}[:=]\s*["']?([A-Za-z0-9_\-/+=.]{16,64})["']?`,
			SecretGroup: 1,
			Keywords:    []string{"key", "secret", "token", "pass", "pwd", "auth"},
			Tags:        []string{"generic"}, Entropy: 3.3,
			Allowlist: []string{
				`^(?i)(true|false|null|undefined|changeme|password|example|placeholder)$`,
				`^(?i)(localStorage|sessionStorage)\..+$`,
				`^(?i)(getItem|setItem|removeItem|document|window|location|JSON)$`,
			},
		},
		{
			ID: "generic-high-entropy", Description: "High-entropy string",
			Regex: `\b([A-Za-z0-9+/=_\-]{32,})\b`,
			Tags:  []string{"generic"}, Entropy: 4.2,
		},
	}
}
