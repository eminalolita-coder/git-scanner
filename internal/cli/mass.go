package cli

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"runtime"
	"runtime/debug"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/eminalolita-coder/git-scanner/internal/analyzer"
	"github.com/eminalolita-coder/git-scanner/internal/aws"
	"github.com/eminalolita-coder/git-scanner/internal/checkers"
	"github.com/eminalolita-coder/git-scanner/internal/config"
	"github.com/eminalolita-coder/git-scanner/internal/dumper"
	"github.com/eminalolita-coder/git-scanner/internal/fetch"
	"github.com/eminalolita-coder/git-scanner/internal/gitdump"
	"github.com/eminalolita-coder/git-scanner/internal/jscracker"
	"github.com/eminalolita-coder/git-scanner/internal/model"
	"github.com/eminalolita-coder/git-scanner/internal/output"
	"github.com/eminalolita-coder/git-scanner/internal/patterns"
)

type massEntry struct {
	host string
	ip   string
}

func newMassCmd(opts *Options) *cobra.Command {
	var (
		concurrency   int
		timeoutSec    int
		pathsFlag     string
		scheme        string
		resolvers     string
		outputDir     string
		format        string
		maxBodyKB     int
		rate          int
		verify        bool
		resolveOnly   bool
		maxPerPat     int
		progressSec   int
		profile       string
		gogc          int
		memLimitMB    int
		method        string
		keepAlive     bool
		checkBuckets  bool
		crawlJS       bool
		jsMax         int
		decode        bool
		bucketObjects int
		followGit     bool
		followMax     int
		gitDepth      int
		gitToken      string
		followForge   bool
		forgeMax      int
		followRobots  bool
		robotsMax     int
		rangeMode     bool
		rangeSizeKB   int
		checkpoint    string
		stallExit     int
	)

	cmd := &cobra.Command{
		Use:   "mass [files-or-hosts...]",
		Short: "High-throughput mass scan of many hosts (target: thousands/s)",
		Long: `mass scans thousands of hosts per second using pooled DNS, dialing by IP
(SNI/Host preserved), a worker pool and an asynchronous buffered writer.

Input lines may be "domain" or "domain ip" (pre-resolved).`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			entries, err := loadMassEntries(args)
			if err != nil {
				return err
			}
			if len(entries) == 0 {
				return fmt.Errorf("no hosts")
			}

			// resume support
			var cp *ckpt
			if checkpoint != "" {
				c, cerr := openCkpt(checkpoint)
				if cerr != nil {
					fmt.Fprintf(cmd.OutOrStdout(), "checkpoint: %v\n", cerr)
				} else {
					cp = c
					before := len(entries)
					kept := entries[:0]
					for _, e := range entries {
						if !cp.has(e.host) {
							kept = append(kept, e)
						}
					}
					entries = kept
					fmt.Fprintf(cmd.OutOrStdout(), "checkpoint: %d already done, %d remaining\n", before-len(entries), len(entries))
					defer cp.close()
				}
			}
			if len(entries) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "nothing left to scan")
				return nil
			}

			cfg, err := loadConfig(opts)
			if err != nil {
				return err
			}
			if outputDir != "" {
				cfg.Output.Directory = outputDir
			}
			if format != "" {
				cfg.Output.Format = format
			}

			engine := patterns.NewEngine(maxPerPat)
			if err := engine.AddAll(patterns.Builtin()); err != nil {
				return err
			}
			engine.Freeze()

			res := fetch.NewResolver(splitCSV(resolvers), 15*time.Minute)
			for _, e := range entries {
				if e.ip != "" {
					res.Seed(e.host, e.ip)
				}
			}

			applyProfile(cmd, profile, &concurrency, &timeoutSec, &maxBodyKB, &gogc)
			applyRuntime(gogc, memLimitMB)

			if concurrency <= 0 {
				concurrency = autoConcurrency()
			}
			if timeoutSec <= 0 {
				timeoutSec = 5
			}
			if maxBodyKB <= 0 {
				maxBodyKB = 512
			}
			if progressSec <= 0 {
				progressSec = 2
			}

			ctx := cmd.Context()
			runCtx, sigStop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
			defer sigStop()
			ctx, cancelAll := context.WithCancel(runCtx)
			defer cancelAll()
			var stalled atomic.Bool
			out := cmd.OutOrStdout()

			fmt.Fprintf(out, "profile=%s concurrency=%d timeout=%ds body=%dKB method=%s gogc=%d cpu=%d\n",
				profile, concurrency, timeoutSec, maxBodyKB, method, gogc, runtime.NumCPU())

			fmt.Fprintf(out, "resolving/loading %d hosts...\n", len(entries))
			res.PreResolve(ctx, hostList(entries), min(concurrency, 1000))
			hits, lookups, derr := res.Stats()
			fmt.Fprintf(out, "dns: cache=%d lookups=%d errors=%d\n", hits, lookups, derr)

			if resolveOnly {
				for _, e := range entries {
					ip, _ := res.Lookup(ctx, e.host)
					fmt.Fprintf(out, "%s %s\n", e.host, ip)
				}
				return nil
			}

			writer, err := output.New(cfg.Output.Directory, cfg.Output.Format)
			if err != nil {
				return err
			}
			async := output.NewAsync(writer, 65536)
			defer async.Close()
			dedup := output.NewShardedDedup(256)

			client := fetch.New(fetch.Options{
				Timeout:           time.Duration(timeoutSec) * time.Second,
				Resolver:          res,
				MaxBody:           int64(maxBodyKB) << 10,
				DisableKeepAlives: !keepAlive && len(splitCSV(pathsFlag)) <= 1,
				Method:            method,
				NoBody:            strings.EqualFold(method, "head"),
				MaxIdleConns:      100000,
				MaxIdlePerHost:    16,
				MaxConnsPerHost:   32,
			})

			paths := normalizePaths(splitCSV(pathsFlag))
			if len(paths) == 0 {
				paths = []string{"/"}
			}
			if scheme == "" {
				scheme = "auto"
			}

			var limiter *rateLimiter
			if rate > 0 {
				limiter = newRateLimiter(rate)
			}

			var (
				done     atomic.Int64
				requests atomic.Int64
				findings atomic.Int64
			)
			bucketSet := &sync.Map{}
			repoSet := &sync.Map{}
			tokenSet := &sync.Map{}
			emailSet := &sync.Map{}
			verifySem := make(chan struct{}, 256)
			start := time.Now()

			stop := make(chan struct{})
			var wg sync.WaitGroup
			go func() {
				t := time.NewTicker(time.Duration(progressSec) * time.Second)
				defer t.Stop()
				var last int64
				for {
					select {
					case <-stop:
						return
					case <-t.C:
						cur := done.Load()
						el := time.Since(start).Seconds()
						fmt.Fprintf(out, "[%.0fs] %d hosts (%.0f/s avg, %.0f/s now), %d findings, %d reqs\n",
							el, cur, float64(cur)/el, float64(cur-last)/float64(progressSec), findings.Load(), requests.Load())
						last = cur
					}
				}
			}()

			if stallExit > 0 {
				go func() {
					t := time.NewTicker(5 * time.Second)
					defer t.Stop()
					last := int64(-1)
					idle := 0
					for {
						select {
						case <-stop:
							return
						case <-t.C:
							cur := done.Load()
							if cur == last {
								idle += 5
							} else {
								idle = 0
							}
							last = cur
							if idle >= stallExit {
								stalled.Store(true)
								fmt.Fprintf(out, "\n[stall] no progress for %ds - aborting so it can resume\n", stallExit)
								cancelAll()
								return
							}
						}
					}
				}()
			}

			jobs := make(chan massEntry, concurrency)
			for i := 0; i < concurrency; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for e := range jobs {
						if limiter != nil {
							limiter.wait(ctx)
						}
						// per-host watchdog: no host can stall the worker
						budget := time.Duration(timeoutSec*len(paths)*2+10) * time.Second
						hctx, hcancel := context.WithTimeout(ctx, budget)
						var rootBody []byte
						var rootScheme string
						for _, p := range paths {
							requests.Add(1)
							sch, code, body, err := fetchMaybeRange(hctx, client, scheme, e.host, p, rangeMode, rangeSizeKB)
							if err != nil || code == 0 || len(body) == 0 {
								continue
							}
							if p == "/" {
								rootBody, rootScheme = body, sch
							}
							scanMassBody(engine, dedup, async, verify, e.host, p, body, &findings, bucketSet, repoSet, tokenSet, verifySem, decode)
						}
						if crawlJS && len(rootBody) > 0 && jscracker.IsHTML(rootBody) {
							crawlScripts(hctx, client, engine, dedup, async, &findings, verifySem, scheme, rootScheme, e.host, rootBody, jsMax, decode, bucketSet, repoSet, tokenSet)
						}
						if followRobots {
							crawlRobots(hctx, client, engine, dedup, async, &findings, verifySem, scheme, rootScheme, e.host, robotsMax, decode, bucketSet, repoSet, tokenSet)
						}
						hcancel()
						cp.add(e.host)
						done.Add(1)
					}
				}()
			}

			feedCtx, cancel := context.WithCancel(ctx)
			defer cancel()
			go func() {
				defer close(jobs)
				for _, e := range entries {
					select {
					case jobs <- e:
					case <-feedCtx.Done():
						return
					}
				}
			}()

			wg.Wait()
			close(stop)

			if stalled.Load() {
				_ = async.Close()
				cp.close()
				fmt.Fprintf(out, "[stall] exiting for resume (checkpoint keeps progress)\n")
				os.Exit(75)
			}

			if checkBuckets && bucketCount(bucketSet) > 0 {
				triageBuckets(ctx, out, bucketSet, engine, async, dedup, &findings, verifySem, decode, bucketObjects)
			}
			if followGit && mapLen(repoSet) > 0 {
				followGitRepos(ctx, out, repoSet, emailSet, cfg, engine, async, dedup, &findings, verifySem, decode, followMax, gitDepth, gitToken)
			}
			if followForge && mapLen(repoSet) > 0 {
				followForgeAccount(ctx, out, repoSet, tokenSet, emailSet, cfg, engine, async, dedup, &findings, verifySem, decode, forgeMax, gitToken)
			}

			el := time.Since(start).Seconds()
			reqs, ferr := client.Stats()
			_ = ferr
			fmt.Fprintf(out, "\n=== done ===\nhosts: %d in %.1fs (%.0f hosts/s)\nrequests: %d\nfindings: %d\ndropped: %d\noutput: %s\n",
				done.Load(), el, float64(done.Load())/el, reqs, findings.Load(), async.Dropped(), async.Path())
			return nil
		},
	}

	f := cmd.Flags()
	f.IntVarP(&concurrency, "concurrency", "C", 1000, "in-flight hosts")
	f.IntVar(&timeoutSec, "timeout", 5, "per-request timeout (seconds)")
	f.StringVar(&pathsFlag, "paths", "/", "comma-separated paths to fetch per host")
	f.StringVar(&scheme, "scheme", "auto", "https|http|auto")
	f.StringVar(&resolvers, "resolvers", "", "comma-separated DNS servers (default: system)")
	f.StringVarP(&outputDir, "output", "o", "", "output directory")
	f.StringVar(&format, "format", "", "jsonl|csv|txt")
	f.IntVar(&maxBodyKB, "max-body", 512, "max response body KB to scan")
	f.IntVar(&rate, "rate", 0, "max requests/second (0 = unlimited)")
	f.BoolVar(&verify, "verify", false, "verify findings against provider APIs")
	f.BoolVar(&resolveOnly, "resolve-only", false, "only resolve hosts and print ip")
	f.IntVar(&maxPerPat, "matches-per-pattern", 3, "max matches per pattern per body")
	f.IntVar(&progressSec, "progress", 2, "progress interval (seconds)")
	f.StringVar(&profile, "profile", "auto", "tuning profile: auto|small|vps|max")
	f.IntVar(&gogc, "gogc", 0, "set GOGC (0 = untouched); profiles set 400-800")
	f.IntVar(&memLimitMB, "memlimit", 0, "soft memory limit in MB (0 = untouched)")
	f.StringVar(&method, "method", "get", "HTTP method: get|head (head = no body)")
	f.BoolVar(&keepAlive, "keep-alive", false, "reuse connections (useful with multiple --paths)")
	f.BoolVar(&checkBuckets, "check-buckets", false, "triage discovered S3 buckets and scan their objects")
	f.BoolVar(&crawlJS, "crawl-js", false, "fetch page scripts and extract endpoints/keys in depth")
	f.IntVar(&jsMax, "js-max", 5, "max scripts to fetch per page")
	f.BoolVar(&decode, "decode", true, "also scan base64/hex/url-decoded content")
	f.IntVar(&bucketObjects, "bucket-objects", 10, "objects to download per public bucket")
	f.BoolVar(&followGit, "follow-git", false, "clone exposed .git repos and scan their history")
	f.IntVar(&followMax, "follow-max", 20, "max repositories to clone")
	f.IntVar(&gitDepth, "git-depth", 0, "history commits to scan (-1 = worktree only, 0 = unlimited)")
	f.StringVar(&gitToken, "git-token", "", "token used to clone private repositories")
	f.BoolVar(&followForge, "follow-forge", false, "expand the forge account of a found remote (uses a leaked token if any)")
	f.IntVar(&forgeMax, "forge-max", 0, "repositories to clone per forge account (0 = list only)")
	f.BoolVar(&followRobots, "follow-robots", false, "follow robots.txt/sitemap.xml paths")
	f.IntVar(&robotsMax, "robots-max", 15, "max extra URLs per host from robots/sitemap")
	f.BoolVar(&rangeMode, "range", false, "HEAD first, then download only the head of large bodies")
	f.IntVar(&rangeSizeKB, "range-size", 256, "bytes (KB) to fetch for large files with --range")
	f.StringVar(&checkpoint, "checkpoint", "", "append completed hosts to this file and resume from it")
	f.IntVar(&stallExit, "stall-exit", 90, "exit for resume if no host completes for N seconds (0 = off)")
	return cmd
}

// checkpoint persists completed hosts so a run can resume after a network cut.
type ckpt struct {
	mu   sync.Mutex
	f    *os.File
	bw   *bufio.Writer
	done map[string]struct{}
	n    int
}

func openCkpt(path string) (*ckpt, error) {
	c := &ckpt{done: map[string]struct{}{}}
	if f, err := os.Open(path); err == nil {
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 1<<20), 1<<20)
		for sc.Scan() {
			if line := strings.TrimSpace(sc.Text()); line != "" {
				c.done[line] = struct{}{}
			}
		}
		f.Close()
	}
	out, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, err
	}
	c.f = out
	c.bw = bufio.NewWriterSize(out, 1<<20)
	return c, nil
}

func (c *ckpt) has(host string) bool {
	if c == nil {
		return false
	}
	_, ok := c.done[host]
	return ok
}

func (c *ckpt) add(host string) {
	if c == nil {
		return
	}
	c.mu.Lock()
	if _, ok := c.done[host]; !ok {
		_, _ = c.bw.WriteString(host)
		_ = c.bw.WriteByte('\n')
		c.done[host] = struct{}{}
	}
	c.n++
	if c.n%512 == 0 {
		_ = c.bw.Flush()
	}
	c.mu.Unlock()
}

func (c *ckpt) close() {
	if c == nil {
		return
	}
	c.mu.Lock()
	_ = c.bw.Flush()
	_ = c.f.Close()
	c.mu.Unlock()
}

func (c *ckpt) count() int { return len(c.done) }

// fetchMaybeRange issues a HEAD first when --range is enabled and downloads
// only a prefix of large bodies (dumps, archives).
func fetchMaybeRange(ctx context.Context, c *fetch.Client, scheme, host, path string, enabled bool, limitKB int) (string, int, []byte, error) {
	if !enabled {
		return fetchOne(ctx, c, scheme, host, path)
	}
	sch := scheme
	if sch == "auto" {
		sch = "https"
		if c.Head(ctx, "https", host, path) < 0 {
			sch = "http"
		}
	}
	size := c.Head(ctx, sch, host, path)
	limit := int64(limitKB) << 10
	if size > limit {
		code, body, err := c.FetchRange(ctx, sch, host, path, 0, limit)
		return sch, code, body, err
	}
	code, body, err := c.Fetch(ctx, sch, host, path)
	return sch, code, body, err
}

// autoConcurrency picks a safe default from the CPU count.
func autoConcurrency() int {
	return clamp(runtime.NumCPU()*150, 500, 20000)
}

func profileConcurrency(p string) int {
	n := runtime.NumCPU()
	switch p {
	case "small":
		return clamp(n*50, 500, 3000)
	case "vps":
		return clamp(n*250, 2000, 40000)
	case "max":
		return clamp(n*500, 5000, 120000)
	default: // auto
		return autoConcurrency()
	}
}

func profileMaxBodyKB(p string) int {
	switch p {
	case "max":
		return 256
	case "vps":
		return 512
	default:
		return 512
	}
}

func profileGOGC(p string) int {
	switch p {
	case "max":
		return 800
	case "vps":
		return 400
	default:
		return 0
	}
}

// applyProfile fills unset flags from the chosen profile.
func applyProfile(cmd *cobra.Command, profile string, concurrency, timeoutSec, maxBodyKB, gogc *int) {
	if profile == "" {
		profile = "auto"
	}
	if !cmd.Flags().Changed("concurrency") {
		*concurrency = profileConcurrency(profile)
	}
	if !cmd.Flags().Changed("max-body") && profileMaxBodyKB(profile) < *maxBodyKB {
		*maxBodyKB = profileMaxBodyKB(profile)
	}
	if !cmd.Flags().Changed("gogc") && profileGOGC(profile) > 0 {
		*gogc = profileGOGC(profile)
	}
	if !cmd.Flags().Changed("timeout") && (profile == "vps" || profile == "max") {
		*timeoutSec = 3
	}
}

// applyRuntime tunes the Go runtime for throughput.
func applyRuntime(gogc, memLimitMB int) {
	if gogc > 0 {
		debug.SetGCPercent(gogc)
	}
	if memLimitMB > 0 {
		debug.SetMemoryLimit(int64(memLimitMB) << 20)
	}
}

func clamp(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func fetchOne(ctx context.Context, c *fetch.Client, scheme, host, path string) (string, int, []byte, error) {
	if scheme == "auto" {
		return c.FetchAuto(ctx, host, path)
	}
	code, body, err := c.Fetch(ctx, scheme, host, path)
	return scheme, code, body, err
}

func scanMassBody(engine *patterns.Engine, dedup *output.ShardedDedup, w *output.AsyncWriter, verify bool, host, path string, body []byte, findings *atomic.Int64, buckets, repos, tokens *sync.Map, verifySem chan struct{}, decode bool) {
	blobs := [][]byte{body}
	// decoding is CPU heavy on large bodies: bound it generously
	if decode && len(body) < 4<<20 {
		dec := analyzer.Deobfuscate(body, analyzer.DefaultOptions())
		if len(dec) > 64 {
			dec = dec[:64]
		}
		blobs = append(blobs, dec...)
	}
	for _, blob := range blobs {
		for _, m := range engine.Scan(blob) {
			key := m.Pattern.ID + "\x00" + m.Secret + "\x00" + host + path
			if !dedup.First(key) {
				continue
			}
			switch m.Pattern.ID {
			case "s3-bucket-host", "s3-path-style":
				if buckets != nil {
					buckets.Store(m.Secret, struct{}{})
				}
			case "git-exposed-head":
				if repos != nil {
					repos.Store(host, repoRemote(repos, host))
				}
			case "git-config-remote":
				if repos != nil {
					repos.Store(host, m.Secret)
				}
			}
			if tokens != nil && isTokenRule(m.Pattern.ID) {
				if _, ok := tokens.Load(host); !ok {
					tokens.Store(host, m.Secret)
				}
			}
			f := model.Finding{
				RuleID:      m.Pattern.ID,
				Description: m.Pattern.Description,
				Secret:      m.Secret,
				Match:       m.Match,
				Location:    model.Location{Source: host, File: path, Line: 1},
				Tags:        m.Pattern.Tags,
				Detected:    time.Now().UTC(),
			}
			if strings.HasPrefix(f.RuleID, "aws-access-key") {
				if sec := pairedAWSSecret(body, f.Secret); sec != "" {
					f.Extra = map[string]string{"secret": sec, "account_hint": "pair from same body"}
				}
			}
			// vault tokens need a server address: hint with the current host
			for _, t := range m.Pattern.Tags {
				if t == "vault" {
					ensureExtra(&f)["host"] = host
					break
				}
			}
			if verify {
				if cs := checkers.For(f.RuleID, f.Tags); len(cs) > 0 {
					verifySem <- struct{}{}
					rctx, cancel := context.WithTimeout(context.Background(), checkers.DefaultTimeout)
					res := cs[0].Check(rctx, f.Secret, f.Extra)
					cancel()
					<-verifySem
					f.Verified = res.Verified
					f.Checker = cs[0].Name()
					if res.Err != "" {
						ensureExtra(&f)["check_error"] = res.Err
					}
					if res.Identity != "" {
						ensureExtra(&f)["identity"] = res.Identity
					}
				}
			}
			findings.Add(1)
			_ = w.Write(f)
		}
	}
}

// crawlScripts fetches the scripts referenced by an HTML page, scans each
// bundle and emits the endpoints it references.
func crawlScripts(ctx context.Context, client *fetch.Client, engine *patterns.Engine, dedup *output.ShardedDedup, w *output.AsyncWriter, findings *atomic.Int64, verifySem chan struct{}, scheme, rootScheme, host string, html []byte, maxScripts int, decode bool, buckets, repos, tokens *sync.Map) {
	if rootScheme == "" {
		rootScheme = scheme
	}
	if rootScheme == "auto" {
		rootScheme = "https"
	}
	base, err := url.Parse(rootScheme + "://" + host + "/")
	if err != nil {
		return
	}
	scripts := jscracker.ScriptsFromHTML(base, html)
	if len(scripts) > maxScripts {
		scripts = scripts[:maxScripts]
	}
	seen := map[string]bool{}
	for _, s := range scripts {
		u, err := url.Parse(s)
		if err != nil || seen[u.Host+u.Path] {
			continue
		}
		seen[u.Host+u.Path] = true
		requestsAdd(1)
		code, body, err := client.Fetch(ctx, u.Scheme, u.Host, u.Path)
		if err != nil || code == 0 || len(body) == 0 {
			continue
		}
		scanMassBody(engine, dedup, w, false, u.Host, u.Path, body, findings, buckets, repos, tokens, verifySem, decode)
		for _, ep := range jscracker.Endpoints(body) {
			emitSimple(dedup, w, findings, "js-endpoint", "Endpoint referenced in JS", ep, u.Host, u.Path, []string{"js"})
		}
		for _, pm := range jscracker.SourceMaps(body) {
			emitSimple(dedup, w, findings, "js-sourcemap", "JS source map reference", pm, u.Host, u.Path, []string{"js"})
			mURL := pm
			if !strings.HasPrefix(mURL, "http") {
				if ru, err := u.Parse(pm); err == nil {
					mURL = ru.String()
				}
			}
			mu, err := url.Parse(mURL)
			if err != nil {
				continue
			}
			mcode, mbody, err := client.Fetch(ctx, mu.Scheme, mu.Host, mu.Path)
			if err != nil || mcode != 200 || len(mbody) == 0 {
				continue
			}
			// source maps embed the original sources: a rich hit surface
			scanMassBody(engine, dedup, w, false, mu.Host, mu.Path, mbody, findings, buckets, repos, tokens, verifySem, decode)
		}
	}
}

var reLoc = regexp.MustCompile(`<loc>\s*([^<\s]+)\s*</loc>`)

// crawlRobots fetches robots.txt and sitemap.xml, scans them and follows the
// referenced paths/URLs (bounded).
func crawlRobots(ctx context.Context, client *fetch.Client, engine *patterns.Engine, dedup *output.ShardedDedup, w *output.AsyncWriter, findings *atomic.Int64, verifySem chan struct{}, scheme, rootScheme, host string, maxExtra int, decode bool, buckets, repos, tokens *sync.Map) {
	if maxExtra <= 0 {
		maxExtra = 15
	}
	base := rootScheme
	if base == "" || base == "auto" {
		base = scheme
	}
	if base == "" || base == "auto" {
		base = "https"
	}
	var candidates []string
	seen := map[string]bool{}

	_, rbody, err := client.Fetch(ctx, base, host, "/robots.txt")
	if err == nil && len(rbody) > 0 {
		scanMassBody(engine, dedup, w, false, host, "/robots.txt", rbody, findings, buckets, repos, tokens, verifySem, decode)
		for _, line := range strings.Split(string(rbody), "\n") {
			line = strings.TrimSpace(line)
			low := strings.ToLower(line)
			switch {
			case strings.HasPrefix(low, "sitemap:"):
				u := strings.TrimSpace(line[len("sitemap:"):])
				if u != "" {
					candidates = append(candidates, u)
				}
			case strings.HasPrefix(low, "allow:"), strings.HasPrefix(low, "disallow:"):
				p := strings.TrimSpace(line[strings.Index(line, ":")+1:])
				if p == "" || p == "/" || strings.ContainsAny(p, "*$") {
					continue
				}
				candidates = append(candidates, p)
			}
		}
	}
	_, sbody, err := client.Fetch(ctx, base, host, "/sitemap.xml")
	if err == nil && len(sbody) > 0 {
		scanMassBody(engine, dedup, w, false, host, "/sitemap.xml", sbody, findings, buckets, repos, tokens, verifySem, decode)
		for _, m := range reLoc.FindAllStringSubmatch(string(sbody), 40) {
			candidates = append(candidates, m[1])
		}
	}

	count := 0
	for _, cand := range candidates {
		if count >= maxExtra {
			break
		}
		u, err := url.Parse(cand)
		if err != nil {
			continue
		}
		if !u.IsAbs() {
			b, err := url.Parse(base + "://" + host)
			if err != nil {
				continue
			}
			u = b.ResolveReference(u)
		}
		key := u.Host + u.Path
		if seen[key] {
			continue
		}
		if !strings.EqualFold(u.Host, host) {
			continue
		}
		seen[key] = true
		count++
		requestsAdd(1)
		code, body, err := client.Fetch(ctx, u.Scheme, u.Host, u.Path)
		if err != nil || code == 0 || len(body) == 0 {
			continue
		}
		scanMassBody(engine, dedup, w, false, u.Host, u.Path, body, findings, buckets, repos, tokens, verifySem, decode)
	}
	if count > 0 {
		fmt.Fprintf(io.Discard, "")
	}
}

func emitSimple(dedup *output.ShardedDedup, w *output.AsyncWriter, findings *atomic.Int64, ruleID, desc, secret, host, path string, tags []string) {
	key := ruleID + "\x00" + secret + "\x00" + host + path
	if !dedup.First(key) {
		return
	}
	findings.Add(1)
	_ = w.Write(model.Finding{
		RuleID: ruleID, Description: desc, Secret: secret,
		Location: model.Location{Source: host, File: path, Line: 1},
		Tags:     tags, Detected: time.Now().UTC(),
	})
}

var crawlReqCounter atomic.Int64

func requestsAdd(n int64) { crawlReqCounter.Add(n) }

// pairedAWSSecret returns the most plausible 40-char secret key in body that
// is not the access key itself.
func pairedAWSSecret(body []byte, accessKey string) string {
	return patterns.BestSecretCandidate(body, accessKey, patterns.DefaultSecretEntropy)
}

func ensureExtra(f *model.Finding) map[string]string {
	if f.Extra == nil {
		f.Extra = map[string]string{}
	}
	return f.Extra
}

func mapLen(m *sync.Map) int {
	n := 0
	m.Range(func(_, _ any) bool { n++; return true })
	return n
}

// repoRemote returns the stored remote for host, or "".
func repoRemote(m *sync.Map, host string) string {
	if v, ok := m.Load(host); ok {
		if s, _ := v.(string); s != "" {
			return s
		}
	}
	return ""
}

// followGitRepos clones exposed repositories (bounded) and scans their
// worktree, and optionally their history.
func followGitRepos(ctx context.Context, out io.Writer, repos, emails *sync.Map, cfg *config.Config, engine *patterns.Engine, w *output.AsyncWriter, dedup *output.ShardedDedup, findings *atomic.Int64, verifySem chan struct{}, decode bool, maxRepos, depth int, token string) {
	type job struct{ host, remote string }
	var jobs []job
	repos.Range(func(k, v any) bool {
		host, _ := k.(string)
		remote, _ := v.(string)
		jobs = append(jobs, job{host: host, remote: remote})
		return true
	})
	sort.Slice(jobs, func(i, j int) bool { return jobs[i].host < jobs[j].host })
	if len(jobs) > maxRepos {
		jobs = jobs[:maxRepos]
	}
	if len(jobs) == 0 {
		return
	}
	fmt.Fprintf(out, "\n[git] following %d exposed repo(s) (depth=%d)...\n", len(jobs), depth)

	gcfg := cfg.GitScanner
	// depth: <0 worktree only, 0 = unlimited history, >0 = N commits
	if depth < 0 {
		gcfg.ScanHistory = false
		gcfg.MaxHistoryDepth = 0
	} else {
		gcfg.ScanHistory = true
		gcfg.MaxHistoryDepth = depth
	}
	lim := cfg.ScanLimits
	cloner := gitdump.New(gcfg, lim)

	rs := &repoScanner{cloner: cloner, engine: engine, dedup: dedup, w: w, findings: findings, verifySem: verifySem, decode: decode, out: out, emails: emails}

	// parallel: cloning is network bound and was the slowest phase
	var wg sync.WaitGroup
	sem := make(chan struct{}, 6)
	for _, j := range jobs {
		wg.Add(1)
		sem <- struct{}{}
		go func(j job) {
			defer wg.Done()
			defer func() { <-sem }()
			var candidates []string
			if strings.HasPrefix(j.remote, "http") {
				candidates = append(candidates, j.remote)
			}
			candidates = append(candidates, "https://"+j.host+"/.git", "http://"+j.host+"/.git")
			rs.scanURL(ctx, j.host, candidates, "https://"+j.host+"/.git", token)
		}(j)
	}
	wg.Wait()
}

// repoScanner holds the shared state used to clone/scan a repository.
type repoScanner struct {
	cloner    *gitdump.Cloner
	engine    *patterns.Engine
	dedup     *output.ShardedDedup
	w         *output.AsyncWriter
	findings  *atomic.Int64
	verifySem chan struct{}
	decode    bool
	out       io.Writer
	emails    *sync.Map
}

// scanURL tries the candidate clone URLs in order, then the dumb protocol.
// It returns true when the repository was scanned by some means.
func (rs *repoScanner) scanURL(ctx context.Context, host string, candidates []string, dumbBase, token string) bool {
	var lastErr error
	for _, cloneURL := range candidates {
		cctx, cancel := context.WithTimeout(ctx, 90*time.Second)
		files := 0
		target := model.Target{
			Kind:    model.KindGitRepo,
			Value:   cloneURL,
			Token:   token,
			GitHost: gitdump.HostFromURL(cloneURL),
		}
		err := rs.cloner.Dump(cctx, target, func(t model.Target, c gitdump.Content) {
			files++
			rs.scanContent(t, host, cloneURL, c)
		})
		cancel()
		if err == nil {
			rs.emit("git-repo", "Cloned exposed repository", cloneURL, host, "/", []string{"git"})
			fmt.Fprintf(rs.out, "  [git] %s cloned, %d blob(s) scanned\n", cloneURL, files)
			return true
		}
		// an expired token makes public repos fail: retry without it
		if token != "" {
			cctx2, cancel2 := context.WithTimeout(ctx, 90*time.Second)
			target.Token = ""
			files = 0
			err2 := rs.cloner.Dump(cctx2, target, func(t model.Target, c gitdump.Content) {
				files++
				rs.scanContent(t, host, cloneURL, c)
			})
			cancel2()
			if err2 == nil {
				rs.emit("git-repo", "Cloned exposed repository", cloneURL, host, "/", []string{"git"})
				fmt.Fprintf(rs.out, "  [git] %s cloned without token, %d blob(s)\n", cloneURL, files)
				return true
			}
		}
		lastErr = err
	}
	// dumb-protocol fallback
	if dumbBase != "" {
		items := 0
		err := gitdump.DumbScan(ctx, dumbBase, nil, gitdump.DefaultDumbOptions(),
			model.Target{Kind: model.KindGitRepo, Value: dumbBase},
			func(t model.Target, c gitdump.Content) {
				items++
				scanMassBody(rs.engine, rs.dedup, rs.w, false, dumbBase, c.File, c.Bytes, rs.findings, nil, nil, nil, rs.verifySem, rs.decode)
			})
		if err == nil && items > 0 {
			rs.emit("git-dumb-scan", "Scanned exposed .git (dumb protocol)", dumbBase, host, "/", []string{"git"})
			fmt.Fprintf(rs.out, "  [git] %s -> dumb scan, %d item(s)\n", host, items)
			return true
		}
	}
	rs.emit("git-clone-failed", "Repository could not be read", host, host, "/", []string{"git"})
	fmt.Fprintf(rs.out, "  [git] %s -> %v\n", host, lastErr)
	return false
}

// scanContent feeds one git blob to the scanner, keeping provenance.
func (rs *repoScanner) scanContent(t model.Target, host, label string, c gitdump.Content) {
	if rs.emails != nil && c.Email != "" {
		if _, seen := rs.emails.Load(c.Email); !seen {
			rs.emails.Store(c.Email, host)
		}
	}
	if c.Author != "" {
		rs.emit("git-author", "Commit author", c.Author+" <"+c.Email+">", label, c.File, []string{"git", "identity"})
	}
	path := c.File
	if c.Deleted {
		path = c.File + " (deleted)"
	}
	scanMassBody(rs.engine, rs.dedup, rs.w, false, label, path, c.Bytes, rs.findings, nil, nil, nil, rs.verifySem, rs.decode)
}

func (rs *repoScanner) emit(ruleID, desc, secret, host, path string, tags []string) {
	emitSimple(rs.dedup, rs.w, rs.findings, ruleID, desc, secret, host, path, tags)
}

// isTokenRule reports whether a rule yields a forge credential.
func isTokenRule(id string) bool {
	switch id {
	case "github-oauth", "github-pat", "github-fine-grained-pat", "github-basic-cred",
		"gitlab-pat", "gitlab-oauth", "gitlab-deploy-token", "gitlab-runner-token",
		"gitlab-scim-token", "gitlab-ci-token",
		"gitea-token", "bitbucket-app-password":
		return true
	}
	return false
}

// normalizeToken decodes a base64 "x-access-token:<token>" credential.
func normalizeToken(t string) string {
	if strings.HasPrefix(t, "eC1h") {
		if dec, err := base64.StdEncoding.DecodeString(t); err == nil {
			if _, rest, ok := strings.Cut(string(dec), ":"); ok {
				return rest
			}
		}
	}
	return t
}

// followForge expands the account behind a discovered remote, using a leaked
// token when available, and optionally clones what it lists.
func followForgeAccount(ctx context.Context, out io.Writer, repos, tokens, emails *sync.Map, cfg *config.Config, engine *patterns.Engine, w *output.AsyncWriter, dedup *output.ShardedDedup, findings *atomic.Int64, verifySem chan struct{}, decode bool, forgeMax int, fallbackToken string) {
	type lead struct{ host, remote, token string }
	var leads []lead
	repos.Range(func(k, v any) bool {
		host, _ := k.(string)
		remote, _ := v.(string)
		if remote == "" {
			return true
		}
		tok := ""
		if t, ok := tokens.Load(host); ok {
			tok, _ = t.(string)
		}
		leads = append(leads, lead{host: host, remote: remote, token: normalizeToken(tok)})
		return true
	})
	if len(leads) == 0 {
		return
	}
	sort.Slice(leads, func(i, j int) bool { return leads[i].host < leads[j].host })

	gcfg := cfg.GitScanner
	gcfg.ScanHistory = false
	rs := &repoScanner{
		cloner:    gitdump.New(gcfg, cfg.ScanLimits),
		engine:    engine,
		dedup:     dedup,
		w:         w,
		findings:  findings,
		verifySem: verifySem,
		decode:    decode,
		out:       out,
	}

	fmt.Fprintf(out, "\n[forge] expanding %d remote(s)...\n", len(leads))
	var wg sync.WaitGroup
	sem := make(chan struct{}, 6)
	for _, l := range leads {
		forge, base, owner, ok := dumper.ParseRemote(l.remote)
		if !ok {
			continue
		}
		token := l.token
		if token == "" {
			token = fallbackToken
		}
		cl := dumper.New(forge, base, token)
		cl.Org = owner
		listed, err := cl.ListOwner(ctx, owner)
		if err != nil {
			fmt.Fprintf(out, "  [forge] %s/%s -> %v\n", forge, owner, err)
			continue
		}
		src := string(forge) + ":" + owner
		withToken := ""
		if token != "" {
			withToken = " (token)"
		}
		rs.emit("forge-account", "Forge account reachable"+withToken, src, l.host, "/", []string{"forge"})
		fmt.Fprintf(out, "  [forge] %s/%s -> %d repo(s)%s\n", forge, owner, len(listed), withToken)

		for i, r := range listed {
			if r.CloneURL == "" {
				continue
			}
			rs.emit("forge-repo", "Repository of the forge account", r.CloneURL, l.host, "/", []string{"forge"})
			if forgeMax > 0 && i < forgeMax {
				wg.Add(1)
				sem <- struct{}{}
				go func(r dumper.Repo, tok string) {
					defer wg.Done()
					defer func() { <-sem }()
					rs.scanURL(ctx, r.FullName, []string{r.CloneURL}, "", tok)
				}(r, token)
			}
		}

		// identity pivot: author emails found on this host -> forge accounts
		if emails != nil {
			var mails []string
			emails.Range(func(k, v any) bool {
				email, _ := k.(string)
				if h, _ := v.(string); h == l.host {
					mails = append(mails, email)
				}
				return true
			})
			sort.Strings(mails)
			for i, em := range mails {
				if i >= 15 {
					break
				}
				profiles, err := cl.SearchIdentity(ctx, em)
				if err != nil || len(profiles) == 0 {
					continue
				}
				for _, p := range profiles {
					rs.emit("identity-pivot", "Forge account matching a commit email", p, l.host, "/", []string{"identity", "forge"})
				}
				fmt.Fprintf(out, "  [pivot] %s -> %v\n", em, profiles)
			}
		}
	}
	wg.Wait()
}

func bucketNames(m *sync.Map) []string {
	var out []string
	m.Range(func(k, _ any) bool {
		if s, ok := k.(string); ok {
			out = append(out, s)
		}
		return true
	})
	sort.Strings(out)
	return out
}

func bucketCount(m *sync.Map) int {
	n := 0
	m.Range(func(_, _ any) bool { n++; return true })
	return n
}

// triageBuckets probes discovered buckets for anonymous listing, emits a
// finding for each public one and scans a sample of their objects.
func triageBuckets(ctx context.Context, out io.Writer, buckets *sync.Map, engine *patterns.Engine, w *output.AsyncWriter, dedup *output.ShardedDedup, findings *atomic.Int64, verifySem chan struct{}, decode bool, maxObjects int) {
	names := bucketNames(buckets)
	fmt.Fprintf(out, "\n[buckets] triaging %d discovered bucket(s)...\n", len(names))
	res := aws.ScanPublicBuckets(ctx, nil, names, 64)
	public := 0
	for _, r := range res {
		if !r.Public {
			continue
		}
		public++
		fmt.Fprintf(out, "  [PUBLIC] %s region=%s objects=%d+ sample=%v\n", r.Name, r.Region, r.ObjectCount, r.Sample)
		emitSimple(dedup, w, findings, "s3-public-bucket", "Publicly listable S3 bucket",
			r.Name, r.Name, "/", []string{"s3", "aws"})

		if maxObjects <= 0 {
			continue
		}
		var keys []string
		if all, err := aws.ListObjects(ctx, nil, r.Name, r.Region, 1000); err == nil && len(all) > 0 {
			keys = all
		} else {
			keys = r.Sample
		}
		keys = selectObjects(keys, DefaultObjectFilter, maxObjects)
		scanned := 0
		for _, k := range keys {
			u := aws.PublicObjectURL(r.Name, r.Region, k)
			code, body := httpGet(ctx, u, 1<<20)
			if code != 200 || len(body) == 0 {
				continue
			}
			scanned++
			scanMassBody(engine, dedup, w, false, "s3://"+r.Name, "/"+k, body, findings, nil, nil, nil, verifySem, decode)
		}
		fmt.Fprintf(out, "           scanned %d object(s)\n", scanned)
	}
	fmt.Fprintf(out, "[buckets] %d public / %d checked\n", public, len(res))
}

var bucketHTTP = &http.Client{Timeout: 20 * time.Second}

func httpGet(ctx context.Context, url string, limit int64) (int, []byte) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, nil
	}
	req.Header.Set("User-Agent", "git-scanner")
	resp, err := bucketHTTP.Do(req)
	if err != nil {
		return 0, nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, limit))
	return resp.StatusCode, body
}

func loadMassEntries(args []string) ([]massEntry, error) {
	var out []massEntry
	for _, a := range args {
		if fi, err := os.Stat(a); err == nil && !fi.IsDir() {
			f, err := os.Open(a)
			if err != nil {
				return nil, err
			}
			sc := bufio.NewScanner(f)
			sc.Buffer(make([]byte, 1<<20), 1<<20)
			for sc.Scan() {
				line := strings.TrimSpace(sc.Text())
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				fields := strings.Fields(line)
				e := massEntry{host: stripScheme(fields[0])}
				if len(fields) > 1 {
					e.ip = fields[1]
				}
				out = append(out, e)
			}
			f.Close()
			continue
		}
		out = append(out, massEntry{host: stripScheme(a)})
	}
	return out, nil
}

func stripScheme(s string) string {
	s = strings.TrimPrefix(strings.TrimPrefix(s, "https://"), "http://")
	return strings.TrimSuffix(s, "/")
}

func hostList(es []massEntry) []string {
	out := make([]string, len(es))
	for i, e := range es {
		out[i] = e.host
	}
	return out
}

func splitCSV(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// normalizePaths ensures every path starts with "/", so that
// --paths "/,.env,.git/HEAD" builds https://host/.env and not https://host.env.
func normalizePaths(in []string) []string {
	for i, p := range in {
		if !strings.HasPrefix(p, "/") && !strings.Contains(p, "://") {
			in[i] = "/" + p
		}
	}
	return in
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// rateLimiter is a simple token-bucket shared by workers.
type rateLimiter struct {
	tokens chan struct{}
}

func newRateLimiter(perSecond int) *rateLimiter {
	rl := &rateLimiter{tokens: make(chan struct{}, perSecond)}
	go func() {
		t := time.NewTicker(time.Second / time.Duration(perSecond))
		defer t.Stop()
		for range t.C {
			select {
			case rl.tokens <- struct{}{}:
			default:
			}
		}
	}()
	return rl
}

func (rl *rateLimiter) wait(ctx context.Context) {
	select {
	case <-rl.tokens:
	case <-ctx.Done():
	}
}

var _ = io.Discard
