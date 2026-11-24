package scanners

// This file centralises the path/wordlist data recovered from the reference
// binary. It is used by the .env cracker, the CVE prober and the discovery
// command.

// SensitiveFilenames are basenames that usually hold secrets. When scanning a
// directory, files matching these are prioritised.
var SensitiveFilenames = []string{
	".env", ".env.local", ".env.production", ".env.development", ".env.staging",
	".env.backup", ".env.old", ".env.bak", ".env.save", ".env.swp", ".env.dev",
	".env.test", ".env.prod", ".env.example",
	"config.json", "config.yml", "config.yaml", "config.php",
	"appsettings.json", "appsettings.Development.json", "appsettings.Production.json",
	"application.properties", "application.yml", "application.yaml",
	"database.yml", "database.yaml", "credentials", "credentials.json",
	"google-credentials.json", "terraform.tfstate", "vault.hcl",
	".npmrc", ".yarnrc.yml", ".pypirc", ".netrc", ".htpasswd",
	"secrets.json", "secrets.yaml", "wp-config.php", "docker-compose.yml",
	"docker-compose.yaml", "master.key", "id_rsa", "id_ed25519",
}

// SecretFilePaths are absolute locations on a server that commonly leak
// credentials, used by the CVE/probe helpers.
var SecretFilePaths = []string{
	// AWS
	"/root/.aws/credentials", "/root/.aws/config",
	"/home/*/.aws/credentials", "/var/www/.aws/credentials",
	// SSH / GPG
	"/root/.ssh/id_rsa", "/root/.ssh/id_ed25519", "/root/.ssh/id_ecdsa",
	"/root/.ssh/authorized_keys", "/home/app/.ssh/id_rsa", "/home/deploy/.ssh/id_rsa",
	// VCS
	"/.git/config", "/.git/HEAD", "/.git-credentials", "/.gitconfig",
	"/root/.git-credentials", "/home/node/.git-credentials",
	// Cloud / k8s / docker
	"/.kube/config", "/root/.kube/config", "/etc/kubernetes/admin.conf",
	"/etc/kubernetes/kubelet.conf", "/var/run/secrets/kubernetes.io/serviceaccount/token",
	"/.docker/config.json", "/.dockerenv", "/run/secrets",
	"/.config/gcloud/application_default_credentials.json",
	"/.config/gcloud/credentials.db", "/.azure/accessTokens.json",
	"/.azure/azureProfile.json",
	// Histories / misc
	"/root/.bash_history", "/root/.zsh_history", "/.vault-token",
	"/proc/1/environ", "/etc/passwd", "/etc/shadow", "/etc/hostname", "/etc/hosts",
	"/etc/samba/credentials", "/etc/resolv.conf", "/etc/sudoers",
	// App configs
	"/app/.env", "/var/www/html/.env", "/var/task/.env", "/var/www/.env",
	"/srv/app/.env", "/opt/app/.env", "/app/Dockerfile",
	"/app/.next/required-server-files.json", "/app/config/database.yml",
	"/wp-config.php", "/wp-config.php.bak", "/wp-config.php.old", "/wp-config.php.txt",
	"/composer.json", "/package.json",
}

// WebPaths are URL paths probed against live hosts.
var WebPaths = []string{
	"/.git/HEAD", "/.git/config", "/.git/", "/.git/packed-refs",
	"/.git/logs/HEAD", "/.git/COMMIT_EDITMSG", "/.git/index",
	"/.svn/entries", "/.svn/wc.db", "/.hg/requires", "/.bzr/README",
	"/.env", "/.env.local", "/.env.production", "/.env.backup", "/.env.old",
	"/.env.dev", "/.env.staging", "/.env.test", "/.env.save", "/.env.bak",
	"/config.json", "/config.yml", "/config.yaml", "/config/.env", "/config.js",
	"/actuator/env", "/actuator/health", "/actuator/beans", "/actuator/mappings",
	"/actuator/configprops", "/actuator/heapdump", "/actuator/threaddump",
	"/debug/pprof/", "/debug/pprof/goroutine", "/server-info", "/server-status",
	"/_security_test.json", "/appsettings.json", "/appsettings.Development.json",
	"/application.properties", "/application.yml", "/application.yaml",
	"/web.config", "/phpinfo.php", "/info.php", "/test.php",
	"/_next/static/chunks/pages-manifest.json", "/asset-manifest.json",
	"/.vite/manifest.json", "/api/env", "/env", "/metrics", "/status",
	"/_ignition/health-check", "/wp-config.php", "/wp-config.php.bak",
	"/wp-config.php.old", "/wp-config.php.txt", "/wp-config.php.save",
	"/composer.json", "/composer.lock", "/package.json", "/package-lock.json",
	"/yarn.lock", "/docker-compose.yml", "/docker-compose.yaml",
	"/Dockerfile", "/.dockerignore", "/.docker/config.json",
	"/terraform.tfstate", "/terraform.tfstate.backup", "/.terraform.lock.hcl",
	"/credentials.json", "/service-account.json", "/google-credentials.json",
	"/firebase.json", "/.firebaserc", "/database.yml", "/database.yaml",
	"/dump.sql", "/backup.sql", "/db.sql", "/database.sql", "/backup.zip",
	"/backup.tar.gz", "/site.zip", "/www.zip", "/dist.zip",
	"/jenkins/config.xml", "/.gitlab-ci.yml", "/.travis.yml", "/.circleci/config.yml",
	"/.github/workflows/", "/robots.txt", "/sitemap.xml", "/security.txt",
	"/.well-known/security.txt", "/CHANGELOG.md", "/README.md", "/LICENSE",
	"/.htaccess", "/.htpasswd", "/swagger.json", "/openapi.json", "/api-docs",
	"/graphql", "/health", "/version", "/.DS_Store", "/.vscode/settings.json",
	"/.idea/workspace.xml", "/.npmrc", "/.yarnrc", "/.netrc", "/.pypirc",
	"/id_rsa", "/id_ed25519", "/server.key", "/server.crt", "/cert.pem",
}

// LaravelPaths are Laravel-specific debug endpoints.
var LaravelPaths = []string{
	"/_ignition/health-check", "/_ignition/execute-solution",
	"/telescope/requests", "/laravel.log", "/storage/logs/laravel.log",
	"/.env", "/config/database.php",
}
