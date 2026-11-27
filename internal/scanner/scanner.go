// Package scanner orchestrates the whole pipeline: fetch content, run the
// pattern engine, de-obfuscate, optionally verify, then persist and notify.
package scanner

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/eminalolita-coder/git-scanner/internal/analyzer"
	"github.com/eminalolita-coder/git-scanner/internal/checkers"
	"github.com/eminalolita-coder/git-scanner/internal/config"
	"github.com/eminalolita-coder/git-scanner/internal/gitdump"
	"github.com/eminalolita-coder/git-scanner/internal/logger"
	"github.com/eminalolita-coder/git-scanner/internal/model"
	"github.com/eminalolita-coder/git-scanner/internal/output"
	"github.com/eminalolita-coder/git-scanner/internal/patterns"
	"github.com/eminalolita-coder/git-scanner/internal/proxy"
	"github.com/eminalolita-coder/git-scanner/internal/webhook"
)

// Options configures a Scanner.
type Options struct {
	Config   *config.Config
	Engine   *patterns.Engine
	Verify   bool
	Writer   output.Writer
	Notifier *webhook.Dispatcher
	// TargetTimeout bounds a single target (a hung clone must not block the
	// whole run). Defaults to 300s when zero.
	TargetTimeout time.Duration
}

// Stats holds live counters.
type Stats struct {
	Files    int64
	Findings int64
	Verified int64
}

// Scanner runs the detection pipeline.
type Scanner struct {
	cfg    *config.Config
	engine *patterns.Engine
	verify bool
	writer output.Writer
	notif  *webhook.Dispatcher
	dedup  *output.Dedup
	an     analyzer.Options
	proxy  *proxy.Manager
	client *http.Client

	files    int64
	findings int64
	verified int64

	checkSem chan struct{}

	targetTimeout time.Duration
}

// New builds a Scanner.
func New(o Options) *Scanner {
	an := analyzer.DefaultOptions()
	an.MaxBase64Candidates = o.Config.ScanLimits.MaxBase64Candidates
	an.MaxHexCandidates = o.Config.ScanLimits.MaxHexCandidates
	an.MaxDecodeBytes = int(o.Config.ScanLimits.MaxBase64DecodeBytes)

	client := httpClient
	mgr, err := proxy.New(o.Config.Proxy)
	if err == nil && mgr.Enabled() {
		tr := &http.Transport{
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
			MaxIdleConns:        200,
			MaxIdleConnsPerHost: 20,
			Proxy:               mgr.ProxyFunc(),
		}
		client = &http.Client{Timeout: 30 * time.Second, Transport: tr}
		checkers.SetHTTPClient(client)
		logger.Infof("proxy enabled (%d entrie(s))", 1)
	}

	tt := o.TargetTimeout
	if tt <= 0 {
		tt = 300 * time.Second
	}
	return &Scanner{
		cfg:           o.Config,
		engine:        o.Engine,
		verify:        o.Verify,
		writer:        o.Writer,
		notif:         o.Notifier,
		dedup:         output.NewDedup(o.Config.ScanLimits.MaxDedupEntries),
		an:            an,
		proxy:         mgr,
		client:        client,
		checkSem:      make(chan struct{}, max(1, o.Config.Performance.CheckerConcurrency)),
		targetTimeout: tt,
	}
}

// Stats returns a snapshot of counters.
func (s *Scanner) Stats() Stats {
	return Stats{Files: atomic.LoadInt64(&s.files), Findings: atomic.LoadInt64(&s.findings), Verified: atomic.LoadInt64(&s.verified)}
}

var gitCloner = sync.OnceValue(func() *gitdump.Cloner { return nil })

// Run scans every target.
func (s *Scanner) Run(ctx context.Context, targets []model.Target) {
	sem := make(chan struct{}, max(1, s.cfg.Performance.Threads))
	var wg sync.WaitGroup
	for _, t := range targets {
		select {
		case <-ctx.Done():
			wg.Wait()
			return
		default:
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(t model.Target) {
			defer wg.Done()
			defer func() { <-sem }()
			if err := s.scanTarget(ctx, t); err != nil {
				logger.Debugf("target %s: %v", t.Value, err)
			}
		}(t)
	}
	wg.Wait()
}

func (s *Scanner) scanTarget(ctx context.Context, t model.Target) error {
	if s.targetTimeout > 0 {
		tctx, cancel := context.WithTimeout(ctx, s.targetTimeout)
		defer cancel()
		ctx = tctx
	}
	switch t.Kind {
	case model.KindGitRepo:
		cloner := gitdump.New(s.cfg.GitScanner, s.cfg.ScanLimits)
		if s.proxy != nil {
			cloner.Proxy = s.proxy.GitProxyNext()
		}
		if t.GitHost == "" {
			t.GitHost = gitdump.HostFromURL(t.Value)
		}
		err := cloner.Dump(ctx, t, func(t model.Target, c gitdump.Content) {
			s.scanContent(t, model.Location{
				Source: t.Value, File: c.File, Commit: c.Commit, Branch: c.Branch,
				Author: c.Author, Email: c.Email, Date: c.Date,
			}, c.Bytes)
		})
		if err == nil {
			return nil
		}
		// Servers exposing .git without smart HTTP (dumb protocol) reject the
		// clone ("invalid pkt-len"); read the objects directly instead.
		if base := strings.TrimRight(t.Value, "/"); strings.HasPrefix(base, "http") {
			items := 0
			derr := gitdump.DumbScan(ctx, base, nil, gitdump.DefaultDumbOptions(), t,
				func(_ model.Target, c gitdump.Content) {
					items++
					s.scanContent(t, model.Location{
						Source: t.Value, File: c.File, Commit: c.Commit, Branch: c.Branch,
						Author: c.Author, Email: c.Email, Date: c.Date,
					}, c.Bytes)
				})
			if derr == nil && items > 0 {
				return nil
			}
		}
		return err
	case model.KindDir:
		return filepath.WalkDir(t.Value, func(p string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			data, err := os.ReadFile(p)
			if err != nil || int64(len(data)) > s.cfg.ScanLimits.MaxFileSizeBytes {
				return nil
			}
			rel, _ := filepath.Rel(t.Value, p)
			s.scanContent(t, model.Location{Source: t.Value, File: filepath.ToSlash(rel)}, data)
			return nil
		})
	case model.KindFile:
		data, err := os.ReadFile(t.Value)
		if err != nil {
			return err
		}
		if isArchive(t.Value) {
			return s.scanArchive(t, t.Value, data)
		}
		s.scanContent(t, model.Location{Source: t.Value, File: filepath.Base(t.Value)}, data)
		return nil
	case model.KindURL:
		return s.scanURL(ctx, t)
	}
	return nil
}

func (s *Scanner) scanURL(ctx context.Context, t model.Target) error {
	cctx, cancel := context.WithTimeout(ctx, time.Duration(s.cfg.Performance.TimeoutSeconds)*time.Second)
	defer cancel()
	req, err := newRequest(cctx, t.Value)
	if err != nil {
		return err
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	limit := int64(s.cfg.Performance.MaxResponseBodyMB) << 20
	if limit <= 0 {
		limit = 50 << 20
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit))
	if err != nil {
		return err
	}
	s.scanContent(t, model.Location{Source: t.Value}, body)
	return nil
}

// ScanBytes scans an in-memory blob as if it were the given file of target t.
func (s *Scanner) ScanBytes(t model.Target, file string, content []byte) {
	s.scanContent(t, model.Location{Source: t.Value, File: file}, content)
}

// scanContent runs the engine on content plus its decoded variants.
func (s *Scanner) scanContent(t model.Target, loc model.Location, content []byte) {
	atomic.AddInt64(&s.files, 1)

	blobs := [][]byte{content}
	if analyzer.IsBinary(content) {
		switch s.cfg.ScanLimits.BinaryPolicy {
		case "skip":
			return
		case "extract_strings":
			blobs = [][]byte{analyzer.ExtractStrings(content, s.cfg.ScanLimits.MinStringLength)}
		}
	}
	blobs = append(blobs, analyzer.Deobfuscate(content, s.an)...)

	for _, blob := range blobs {
		for _, m := range s.engine.Scan(blob) {
			f := model.Finding{
				RuleID:      m.Pattern.ID,
				Description: m.Pattern.Description,
				Secret:      m.Secret,
				Match:       m.Match,
				Entropy:     patterns.Shannon(m.Secret),
				Location:    loc,
				Tags:        m.Pattern.Tags,
				Detected:    time.Now().UTC(),
			}
			if loc.Line == 0 {
				f.Location.Line = lineOf(content, m.Index)
			}
			// Paired values are searched in a window CENTRED on the match
			// (100 lines either way), never in the whole file: a file with
			// several credentials would otherwise let a key pair with a
			// neighbour's secret.
			win := lineWindow(content, m.Index, 100)
			if isAWSKey(m.Pattern.ID) {
				if sec := firstAWSSecret(win, m.Secret); sec != "" {
					f.Extra = map[string]string{"secret": sec}
				}
			}
			if m.Pattern.ID == "aws-ses-smtp-username" {
				if pass := patterns.BestSESPassword(win, m.Secret, patterns.DefaultSecretEntropy); pass != "" {
					if f.Extra == nil {
						f.Extra = map[string]string{}
					}
					f.Extra["ses_password"] = pass
				}
			}
			if m.Pattern.ID == "gcp-service-account" && json.Valid(content) {
				if f.Extra == nil {
					f.Extra = map[string]string{}
				}
				f.Extra["json"] = string(content)
			}
			if m.Pattern.ID == "mailjet-key" {
				if p := patterns.BestHex32(win, m.Secret); p != "" {
					if f.Extra == nil {
						f.Extra = map[string]string{}
					}
					f.Extra["partner"] = p
				}
			}
			if m.Pattern.ID == "smtp-credential" {
				if f.Extra == nil {
					f.Extra = map[string]string{}
				}
				if u := smtpUserOf(m.Match); u != "" {
					f.Extra["smtp_user"] = u
				}
				if h, p := patterns.FirstSMTPHost(win); h != "" {
					f.Extra["host"] = h
					if p != "" {
						f.Extra["port"] = p
					}
				}
			}
			s.emit(f)
		}
	}
}

func (s *Scanner) emit(f model.Finding) {
	if !s.dedup.First(f.DedupKey()) {
		return
	}
	if s.verify {
		s.verifyFinding(&f)
	}
	atomic.AddInt64(&s.findings, 1)
	if f.Verified {
		atomic.AddInt64(&s.verified, 1)
	}
	if s.writer != nil {
		if err := s.writer.Write(f); err != nil {
			logger.Debugf("write finding: %v", err)
		}
	}
	if f.Verified && s.notif != nil {
		s.notif.Send(context.Background(), formatNotification(f))
	}
}

func (s *Scanner) verifyFinding(f *model.Finding) {
	cs := checkers.For(f.RuleID, f.Tags)
	if len(cs) == 0 {
		return
	}
	s.checkSem <- struct{}{}
	defer func() { <-s.checkSem }()
	ctx, cancel := context.WithTimeout(context.Background(), checkers.DefaultTimeout)
	defer cancel()
	res := cs[0].Check(ctx, f.Secret, f.Extra)
	f.Verified = res.Verified
	f.Checker = cs[0].Name()
	if res.Err != "" {
		if f.Extra == nil {
			f.Extra = map[string]string{}
		}
		f.Extra["check_error"] = res.Err
	}
	if res.Identity != "" {
		if f.Extra == nil {
			f.Extra = map[string]string{}
		}
		f.Extra["identity"] = res.Identity
	}
}

func lineOf(content []byte, idx int) int {
	if idx > len(content) {
		idx = len(content)
	}
	return bytes.Count(content[:idx], []byte{'\n'}) + 1
}

// lineWindow returns content limited to n lines before and after offset. Used
// to pair a value with its neighbour without letting a whole large file, or
// another credential's entry, interfere.
func lineWindow(content []byte, offset, n int) []byte {
	if offset < 0 || offset > len(content) {
		offset = 0
	}
	start := offset
	for lines := 0; start > 0 && lines < n; {
		start--
		if content[start] == '\n' {
			lines++
		}
	}
	end := offset
	for lines := 0; end < len(content) && lines < n; {
		if content[end] == '\n' {
			lines++
		}
		end++
	}
	if start > end {
		start = end
	}
	return content[start:end]
}

func formatNotification(f model.Finding) string {
	var b strings.Builder
	b.WriteString("🔑 <b>" + f.RuleID + "</b> (verified)")
	b.WriteString("\n" + f.Description)
	b.WriteString("\n<code>" + f.Secret + "</code>")
	if f.Location.Source != "" {
		b.WriteString("\nsource: " + f.Location.Source)
	}
	if f.Location.File != "" {
		b.WriteString("\nfile: " + f.Location.File)
	}
	return b.String()
}

func isArchive(path string) bool {
	lower := strings.ToLower(path)
	return strings.HasSuffix(lower, ".zip") || strings.HasSuffix(lower, ".tar.gz") || strings.HasSuffix(lower, ".tgz") || strings.HasSuffix(lower, ".jar") || strings.HasSuffix(lower, ".war")
}

func (s *Scanner) scanArchive(t model.Target, name string, data []byte) error {
	switch {
	case strings.HasSuffix(strings.ToLower(name), ".zip") || strings.HasSuffix(strings.ToLower(name), ".jar") || strings.HasSuffix(strings.ToLower(name), ".war"):
		zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
		if err != nil {
			return err
		}
		for _, f := range zr.File {
			if f.FileInfo().IsDir() || f.UncompressedSize64 > uint64(s.cfg.ScanLimits.MaxZipEntrySizeBytes) {
				continue
			}
			rc, err := f.Open()
			if err != nil {
				continue
			}
			b, _ := io.ReadAll(io.LimitReader(rc, s.cfg.ScanLimits.MaxZipEntrySizeBytes))
			rc.Close()
			s.scanContent(t, model.Location{Source: name, File: f.Name}, b)
		}
	default:
		gz, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return err
		}
		defer gz.Close()
		tr := tar.NewReader(gz)
		for {
			hdr, err := tr.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				break
			}
			if hdr.Typeflag != tar.TypeReg {
				continue
			}
			b, _ := io.ReadAll(io.LimitReader(tr, s.cfg.ScanLimits.MaxZipEntrySizeBytes))
			s.scanContent(t, model.Location{Source: name, File: hdr.Name}, b)
		}
	}
	return nil
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

var reAWSSession = regexp.MustCompile(`(?i)aws_session_token["'\s:=]{1,6}([A-Za-z0-9/+=]{100,})`)

func isAWSKey(ruleID string) bool {
	return ruleID == "aws-access-key-id" || ruleID == "aws-access-key-boundary"
}

// firstAWSSecret finds a plausible paired AWS secret key near the access key.
func firstAWSSecret(blob []byte, accessKey string) string {
	return patterns.BestSecretCandidate(blob, accessKey, patterns.DefaultSecretEntropy)
}

var reSMTPUser = regexp.MustCompile(`(?i)(?:user|username|login|userid)(?:name)?["'\s:=]{1,6}([A-Za-z0-9._%+@-]{2,64})`)

// smtpUserOf re-extracts the user from a smtp-credential match, so the pair can
// be completed with the host found in the same file.
func smtpUserOf(match string) string {
	if m := reSMTPUser.FindStringSubmatch(match); m != nil {
		return m[1]
	}
	return ""
}
