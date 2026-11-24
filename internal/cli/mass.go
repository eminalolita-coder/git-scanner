package cli

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/spf13/cobra"

	"github.com/eminalolita-coder/git-scanner/internal/checkers"
	"github.com/eminalolita-coder/git-scanner/internal/fetch"
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
		concurrency int
		timeoutSec  int
		pathsFlag   string
		scheme      string
		resolvers   string
		outputDir   string
		format      string
		maxBodyKB   int
		rate        int
		verify      bool
		resolveOnly bool
		maxPerPat   int
		progressSec int
		profile     string
		gogc        int
		memLimitMB  int
		method      string
		keepAlive   bool
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

			paths := splitCSV(pathsFlag)
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

			jobs := make(chan massEntry, concurrency)
			for i := 0; i < concurrency; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for e := range jobs {
						if limiter != nil {
							limiter.wait(ctx)
						}
						for _, p := range paths {
							requests.Add(1)
							sch, code, body, err := fetchOne(ctx, client, scheme, e.host, p)
							_ = sch
							if err != nil || code == 0 || len(body) == 0 {
								continue
							}
							scanMassBody(engine, dedup, async, verify, e.host, p, body, &findings)
						}
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
	f.IntVar(&maxPerPat, "matches-per-pattern", 1, "max matches per pattern per body")
	f.IntVar(&progressSec, "progress", 2, "progress interval (seconds)")
	f.StringVar(&profile, "profile", "auto", "tuning profile: auto|small|vps|max")
	f.IntVar(&gogc, "gogc", 0, "set GOGC (0 = untouched); profiles set 400-800")
	f.IntVar(&memLimitMB, "memlimit", 0, "soft memory limit in MB (0 = untouched)")
	f.StringVar(&method, "method", "get", "HTTP method: get|head (head = no body)")
	f.BoolVar(&keepAlive, "keep-alive", false, "reuse connections (useful with multiple --paths)")
	return cmd
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

func scanMassBody(engine *patterns.Engine, dedup *output.ShardedDedup, w *output.AsyncWriter, verify bool, host, path string, body []byte, findings *atomic.Int64) {
	for _, m := range engine.Scan(body) {
		key := m.Pattern.ID + "\x00" + m.Secret + "\x00" + host + path
		if !dedup.First(key) {
			continue
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
		if verify {
			if cs := checkers.For(f.RuleID, f.Tags); len(cs) > 0 {
				rctx, cancel := context.WithTimeout(context.Background(), checkers.DefaultTimeout)
				res := cs[0].Check(rctx, f.Secret, nil)
				cancel()
				f.Verified = res.Verified
				f.Checker = cs[0].Name()
			}
		}
		findings.Add(1)
		_ = w.Write(f)
	}
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
