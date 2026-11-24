// Package config holds the runtime configuration and helpers to load,
// validate and watch it. The JSON shape mirrors the original tool's
// config.json so existing files remain usable.
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/fsnotify/fsnotify"
)

// Config is the root configuration document.
type Config struct {
	Input       Input       `json:"input"`
	Output      Output      `json:"output"`
	Performance Performance `json:"performance"`
	ScanLimits  ScanLimits  `json:"scan_limits"`

	GitScanner GitScanner `json:"git_scanner"`
	GitDumper  GitDumper  `json:"git_dumper"`
	Dumper     Dumper     `json:"dumper"`
	Checkers   Checkers   `json:"checkers"`
	GitTokens  GitTokens  `json:"git_tokens"`
	Webhooks   Webhooks   `json:"webhooks"`
	Proxy      Proxy      `json:"proxy"`
	AWSEnum    AWSEnum    `json:"aws_enum"`
	CVEScan    CVEScan    `json:"cve_scan"`
	EnvCrack   EnvCrack   `json:"envcrack"`
}

type Input struct {
	URLsFile     string `json:"urls_file"`
	PatternsFile string `json:"patterns_file"`
}

type Output struct {
	Directory string `json:"directory"`
	Format    string `json:"format"` // jsonl|csv|txt
}

type Performance struct {
	Threads             int `json:"threads"`
	HTTPConcurrent      int `json:"http_concurrent"`
	TimeoutSeconds      int `json:"timeout_seconds"`
	SMTPConcurrency     int `json:"smtp_concurrency"`
	AWSConcurrency      int `json:"aws_concurrency"`
	CheckerConcurrency  int `json:"checker_concurrency"`
	GitScanConcurrency  int `json:"git_scan_concurrency"`
	ObjectCacheMaxMB    int `json:"object_cache_max_mb"`
	MaxIdleConnsPerHost int `json:"max_idle_conns_per_host"`
	MaxConnsPerHost     int `json:"max_conns_per_host"`
	ConnIdleTimeoutSec  int `json:"conn_idle_timeout_sec"`
	MaxResponseBodyMB   int `json:"max_response_body_mb"`
}

type ScanLimits struct {
	MaxFileSizeBytes       int64    `json:"max_file_size_bytes"`
	MaxBlobSizeBytes       int64    `json:"max_blob_size_bytes"`
	MaxPatchSizeBytes      int64    `json:"max_patch_size_bytes"`
	MaxZipballSizeBytes    int64    `json:"max_zipball_size_bytes"`
	MaxZipEntrySizeBytes   int64    `json:"max_zip_entry_size_bytes"`
	BinaryProbeBytes       int      `json:"binary_probe_bytes"`
	BinaryPolicy           string   `json:"binary_policy"` // extract_strings|skip|force_text
	MinStringLength        int      `json:"min_string_length"`
	MaxBinaryExtractBytes  int64    `json:"max_binary_extract_bytes"`
	MaxHistoryCommits      int      `json:"max_history_commits"`
	ScanMergeParents       string   `json:"scan_merge_parents"`
	BranchScanMode         string   `json:"branch_scan_mode"` // all|named|head_only
	BranchWhitelist        []string `json:"branch_whitelist"`
	MaxBranches            int      `json:"max_branches"`
	ScanSubmodules         bool     `json:"scan_submodules"`
	ScanGitNotes           bool     `json:"scan_git_notes"`
	ScanStash              bool     `json:"scan_stash"`
	ScanTagMessages        bool     `json:"scan_tag_messages"`
	ScanGitConfig          bool     `json:"scan_git_config"`
	RegexMatchesPerPattern int      `json:"regex_matches_per_pattern"`
	DedupMode              string   `json:"dedup_mode"`
	MaxDedupEntries        int      `json:"max_dedup_entries"`
	MaxBase64Candidates    int      `json:"max_base64_candidates"`
	MaxHexCandidates       int      `json:"max_hex_candidates"`
	MaxBase64DecodeBytes   int64    `json:"max_base64_decode_bytes"`
	MaxArchiveDepth        int      `json:"max_archive_depth"`
	MaxArchiveContentBytes int64    `json:"max_archive_content_bytes"`
	CloneRetries           int      `json:"clone_retries"`
	CloneRetryBackoffMS    int      `json:"clone_retry_backoff_ms"`
	ZipballTimeoutSeconds  int      `json:"zipball_timeout_seconds"`
}

type GitScanner struct {
	Enabled          bool `json:"enabled"`
	ScanHead         bool `json:"scan_head"`
	ScanBasicRefs    bool `json:"scan_basic_refs"`
	ScanConfig       bool `json:"scan_config"`
	ScanDescription  bool `json:"scan_description"`
	ScanExtendedRefs bool `json:"scan_extended_refs"`
	ScanPackFiles    bool `json:"scan_pack_files"`
	ScanIndex        bool `json:"scan_index"`
	ScanHistory      bool `json:"scan_history"`
	ScanArchives     bool `json:"scan_archives"`
	MaxHistoryDepth  int  `json:"max_history_depth"`
	MaxObjectsToScan int  `json:"max_objects_to_scan"`
	MaxFileSizeMB    int  `json:"max_file_size_mb"`
	MaxArchiveSizeMB int  `json:"max_archive_size_mb"`
	SkipBinaryFiles  bool `json:"skip_binary_files"`
	MaxReposPerToken int  `json:"max_repos_per_token"`
	UseNewDumper     bool `json:"use_new_dumper"`
}

type GitDumper struct {
	Enabled             bool `json:"enabled"`
	SimultaneousTokens  int  `json:"simultaneous_tokens"`
	SimultaneousRepos   int  `json:"simultaneous_repos"`
	BackgroundWorkers   int  `json:"background_workers"`
	BackgroundQueueSize int  `json:"background_queue_size"`
	AutoValidateTokens  bool `json:"auto_validate_tokens"`
	RateLimitWait       bool `json:"rate_limit_wait"`
	ArchiveFallback     bool `json:"archive_fallback"`
	ScanCommits         bool `json:"scan_commits"`
	ScanIssues          bool `json:"scan_issues"`
	MaxCommitDepth      int  `json:"max_commit_depth"`
}

type Dumper struct {
	Enabled     bool   `json:"enabled"`
	Mode        string `json:"mode"`   // off|shallow|full|bare|api|hybrid
	Filter      string `json:"filter"` // all|private|recent
	MaxRepos    int    `json:"max_repos"`
	MaxSizeMB   int    `json:"max_size_mb"`
	RecentDays  int    `json:"recent_days"`
	ScanHistory bool   `json:"scan_history"`
	KeepClones  bool   `json:"keep_clones"`
	Parallel    int    `json:"parallel"`
	CloneDir    string `json:"clone_dir"`
}

type Checkers struct {
	Enabled      bool `json:"enabled"`
	GitHub       bool `json:"github"`
	GitLab       bool `json:"gitlab"`
	Bitbucket    bool `json:"bitbucket"`
	Gitea        bool `json:"gitea"`
	Gogs         bool `json:"gogs"`
	Gerrit       bool `json:"gerrit"`
	AzureDev     bool `json:"azure_devops"`
	AWS          bool `json:"aws"`
	AWSEnum      bool `json:"aws_enum"`
	DigitalOcean bool `json:"digitalocean"`
	Sendgrid     bool `json:"sendgrid"`
	Brevo        bool `json:"brevo"`
	Mailgun      bool `json:"mailgun"`
	Mailchimp    bool `json:"mailchimp"`
	Postmark     bool `json:"postmark"`
	Sparkpost    bool `json:"sparkpost"`
	SMTP         bool `json:"smtp"`
	Telegram     bool `json:"telegram_bot"`
	Twilio       bool `json:"twilio"`
	Shopify      bool `json:"shopify"`
	Slack        bool `json:"slack"`
	Discord      bool `json:"discord"`
	Stripe       bool `json:"stripe"`
	Square       bool `json:"square"`
	OpenAI       bool `json:"openai"`
	Claude       bool `json:"claude"`
	Grok         bool `json:"grok"`
	GCP          bool `json:"gcp"`
	Vercel       bool `json:"vercel"`
	NewRelic     bool `json:"newrelic"`
	Datadog      bool `json:"datadog"`
	Grafana      bool `json:"grafana"`
	Shodan       bool `json:"shodan"`
	SSH          bool `json:"ssh"`
}

type GitTokens struct {
	CustomHosts map[string]string `json:"custom_hosts"`
}

type Webhooks struct {
	Enabled         bool     `json:"enabled"`
	MuteGitTelegram bool     `json:"mute_git_telegram"`
	Telegram        Telegram `json:"telegram"`
	Discord         Discord  `json:"discord"`
}

type Telegram struct {
	Enabled  bool   `json:"enabled"`
	BotToken string `json:"bot_token"`
	ChatID   string `json:"chat_id"`
}

type Discord struct {
	Enabled    bool   `json:"enabled"`
	WebhookURL string `json:"webhook_url"`
}

type Proxy struct {
	Enabled  bool   `json:"enabled"`
	URL      string `json:"url"`
	File     string `json:"file"`
	Protocol string `json:"protocol"`
	Checkers string `json:"checkers"`
}

type AWSEnum struct {
	Enabled             bool     `json:"enabled"`
	Threads             int      `json:"threads"`
	Regions             []string `json:"regions"`
	UseIAM              bool     `json:"use_iam"`
	UseS3               bool     `json:"use_s3"`
	UseSecretsMgr       bool     `json:"use_secrets_manager"`
	UseSSM              bool     `json:"use_ssm"`
	UseLambda           bool     `json:"use_lambda"`
	UseEC2              bool     `json:"use_ec2"`
	MaxSecretsPerRegion int      `json:"max_secrets_per_region"`
	MaxSSMPerRegion     int      `json:"max_ssm_per_region"`
}

type CVEScan struct {
	Enabled        bool `json:"enabled"`
	Threads        int  `json:"threads"`
	TimeoutSeconds int  `json:"timeout_seconds"`
	AutoExfil      bool `json:"auto_exfil"`
	CheckCreds     bool `json:"check_creds"`
	Persist        bool `json:"persist"`
	ProbeOnly      bool `json:"probe_only"`
}

type EnvCrack struct {
	Enabled   bool `json:"enabled"`
	Threads   int  `json:"threads"`
	Recursive bool `json:"recursive"`
	MaxSizeMB int  `json:"max_size_mb"`
}

// Default returns a fully populated configuration with sane defaults.
func Default() *Config {
	return &Config{
		Output: Output{Directory: "hits", Format: "jsonl"},
		Performance: Performance{
			Threads: 250, HTTPConcurrent: 100, TimeoutSeconds: 10,
			CheckerConcurrency: 50, GitScanConcurrency: 300,
			MaxIdleConnsPerHost: 150, MaxConnsPerHost: 150,
			ConnIdleTimeoutSec: 60, MaxResponseBodyMB: 50,
		},
		ScanLimits: ScanLimits{
			MaxFileSizeBytes: 10 << 20, MaxBlobSizeBytes: 10 << 20,
			MaxPatchSizeBytes: 5 << 20, MaxZipballSizeBytes: 500 << 20,
			MaxZipEntrySizeBytes: 50 << 20, BinaryProbeBytes: 512,
			BinaryPolicy: "extract_strings", MinStringLength: 10,
			BranchScanMode: "all", ScanMergeParents: "first",
			BranchWhitelist: []string{"dev", "develop", "staging", "test", "qa", "release", "prod", "production", "main", "master"},
			ScanSubmodules:  true, ScanGitNotes: true, ScanStash: true,
			ScanTagMessages: true, ScanGitConfig: true,
			RegexMatchesPerPattern: 10, DedupMode: "global_content",
			MaxDedupEntries: 500000, MaxBase64Candidates: 50, MaxHexCandidates: 20,
			MaxBase64DecodeBytes: 1 << 20, MaxArchiveDepth: 5,
			CloneRetries: 3, CloneRetryBackoffMS: 200, ZipballTimeoutSeconds: 300,
		},
		GitScanner: GitScanner{
			Enabled: true, ScanHead: true, ScanBasicRefs: true, ScanConfig: true,
			ScanHistory: true, ScanArchives: true, MaxHistoryDepth: 50,
			MaxFileSizeMB: 10, MaxReposPerToken: 100, UseNewDumper: true,
		},
		GitDumper: GitDumper{
			Enabled: true, SimultaneousTokens: 15, SimultaneousRepos: 25,
			BackgroundWorkers: 16, BackgroundQueueSize: 512,
			AutoValidateTokens: true, RateLimitWait: true, ArchiveFallback: true,
			MaxCommitDepth: 100,
		},
		Dumper: Dumper{Enabled: true, Mode: "full", Filter: "all", MaxRepos: 100, Parallel: 30, CloneDir: "hits/clones"},
		Checkers: Checkers{
			Enabled: true, GitHub: true, GitLab: true, Bitbucket: true, Gitea: true,
			SMTP: true, Telegram: true, Slack: true, Discord: true, Stripe: true,
			OpenAI: true, Claude: true, Sendgrid: true, AWS: true, SSH: true,
		},
		GitTokens: GitTokens{CustomHosts: map[string]string{}},
		Webhooks:  Webhooks{Enabled: true},
		Proxy:     Proxy{Protocol: "http", Checkers: "all"},
		AWSEnum:   AWSEnum{Enabled: true, Threads: 10, UseIAM: true, UseS3: true, MaxSecretsPerRegion: 25},
		CVEScan:   CVEScan{Enabled: true, Threads: 100, TimeoutSeconds: 10, AutoExfil: true, CheckCreds: true},
		EnvCrack:  EnvCrack{Enabled: true, Threads: 20, Recursive: true, MaxSizeMB: 50},
	}
}

// Load reads a config from path. An empty path returns defaults.
func Load(path string) (*Config, error) {
	cfg := Default()
	if path == "" {
		return cfg, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// Validate checks for incoherent values and normalizes a few fields.
func (c *Config) Validate() error {
	if c.Output.Directory == "" {
		c.Output.Directory = "hits"
	}
	if c.Output.Format == "" {
		c.Output.Format = "jsonl"
	}
	switch c.ScanLimits.BinaryPolicy {
	case "extract_strings", "skip", "force_text":
	default:
		c.ScanLimits.BinaryPolicy = "extract_strings"
	}
	if c.Performance.Threads <= 0 {
		c.Performance.Threads = 100
	}
	if c.Performance.TimeoutSeconds <= 0 {
		c.Performance.TimeoutSeconds = 10
	}
	return nil
}

// Save writes the config as indented JSON.
func (c *Config) Save(path string) error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}

// Watch reloads the config file on change and calls fn with the new value.
// It returns a stop function.
func Watch(path string, fn func(*Config)) (func(), error) {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}
	dir := filepath.Dir(path)
	if err := w.Add(dir); err != nil {
		return nil, err
	}
	var mu sync.Mutex
	stop := make(chan struct{})
	go func() {
		for {
			select {
			case ev, ok := <-w.Events:
				if !ok {
					return
				}
				if filepath.Clean(ev.Name) != filepath.Clean(path) {
					continue
				}
				mu.Lock()
				if cfg, err := Load(path); err == nil {
					fn(cfg)
				}
				mu.Unlock()
			case <-w.Errors:
			case <-stop:
				w.Close()
				return
			}
		}
	}()
	return func() { close(stop) }, nil
}
