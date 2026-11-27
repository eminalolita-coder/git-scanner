package cli

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"

	"github.com/eminalolita-coder/git-scanner/internal/config"
	"github.com/eminalolita-coder/git-scanner/internal/cve"
	"github.com/eminalolita-coder/git-scanner/internal/model"
	"github.com/eminalolita-coder/git-scanner/internal/output"
	"github.com/eminalolita-coder/git-scanner/internal/patterns"
	"github.com/eminalolita-coder/git-scanner/internal/scanner"
	"github.com/eminalolita-coder/git-scanner/internal/scanners"
	"github.com/eminalolita-coder/git-scanner/internal/source"
	"github.com/eminalolita-coder/git-scanner/internal/webhook"
)

func newReconClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout:       timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return nil },
	}
}

func probe(ctx context.Context, c *http.Client, url string) (int, []byte) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, nil
	}
	req.Header.Set("User-Agent", "git-scanner")
	resp, err := c.Do(req)
	if err != nil {
		return 0, nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
	return resp.StatusCode, body
}

func hostsOf(targets []model.Target) []string {
	var out []string
	for _, t := range targets {
		h := t.Value
		if t.Kind == model.KindURL {
			h = strings.TrimPrefix(strings.TrimPrefix(h, "https://"), "http://")
		}
		if h != "" {
			out = append(out, h)
		}
	}
	return out
}

func schemesFor(h string) []string {
	h = strings.TrimSpace(strings.TrimSuffix(h, "/"))
	h = strings.TrimPrefix(h, "https://")
	h = strings.TrimPrefix(h, "http://")
	return []string{"https://" + h, "http://" + h}
}

// runScanStream scans targets and streams findings to out.
func runScanStream(ctx context.Context, cfg *config.Config, engine *patterns.Engine, out io.Writer, targets []model.Target) {
	runScanWriter(ctx, cfg, engine, output.NewStream(out), targets, out, 0)
}

// runScanWriter scans targets writing findings through w.
func runScanWriter(ctx context.Context, cfg *config.Config, engine *patterns.Engine, w output.Writer, targets []model.Target, out io.Writer, targetTimeout time.Duration) {
	sc := scanner.New(scanner.Options{
		Config:        cfg,
		Engine:        engine,
		Writer:        w,
		Notifier:      webhook.New(cfg.Webhooks),
		TargetTimeout: targetTimeout,
	})
	sc.Run(ctx, targets)
	st := sc.Stats()
	if out != nil {
		fmt.Fprintf(out, "\n%d file(s), %d finding(s)\n", st.Files, st.Findings)
	}
}

// --- discover ---

func newDiscoverCmd(opts *Options) *cobra.Command {
	var concurrency int
	var scan bool
	var outputDir, format string
	var targetTimeout int

	cmd := &cobra.Command{
		Use:   "discover [hosts...]",
		Short: "Find exposed .git directories on hosts",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			targets, err := source.Expand(args)
			if err != nil {
				return err
			}
			hosts := hostsOf(targets)
			if concurrency <= 0 {
				concurrency = 50
			}
			client := newReconClient(10 * time.Second)
			ctx := cmd.Context()
			out := cmd.OutOrStdout()

			var mu sync.Mutex
			sem := make(chan struct{}, concurrency)
			var wg sync.WaitGroup
			var exposed []string

			for _, h := range hosts {
				wg.Add(1)
				sem <- struct{}{}
				go func(h string) {
					defer wg.Done()
					defer func() { <-sem }()
					for _, base := range schemesFor(h) {
						code, body := probe(ctx, client, base+"/.git/HEAD")
						if code == 200 && strings.Contains(string(body), "ref:") {
							mu.Lock()
							exposed = append(exposed, base)
							fmt.Fprintf(out, "[git] %s (.git exposed)\n", base)
							mu.Unlock()
							return
						}
					}
				}(h)
			}
			wg.Wait()
			fmt.Fprintf(out, "\nexposed .git: %d / %d host(s)\n", len(exposed), len(hosts))

			if scan && len(exposed) > 0 {
				gitTargets := make([]model.Target, 0, len(exposed))
				for _, b := range exposed {
					gitTargets = append(gitTargets, model.Target{
						Kind: model.KindGitRepo, Value: b + "/.git", GitHost: "gitea",
					})
				}
				cfg, err := loadConfig(opts)
				if err != nil {
					return err
				}
				eng, err := buildEngine(cfg, "", "", "")
				if err != nil {
					return err
				}
				tt := time.Duration(targetTimeout) * time.Second
				if outputDir != "" {
					if format != "" {
						cfg.Output.Format = format
					}
					w, err := output.New(outputDir, cfg.Output.Format)
					if err != nil {
						return err
					}
					defer w.Close()
					fmt.Fprintf(out, "findings -> %s\n", w.Path())
					runScanWriter(ctx, cfg, eng, w, gitTargets, out, tt)
				} else {
					runScanWriter(ctx, cfg, eng, output.NewStream(out), gitTargets, out, tt)
				}
			}
			return nil
		},
	}
	cmd.Flags().IntVarP(&concurrency, "concurrency", "C", 50, "concurrency")
	cmd.Flags().BoolVar(&scan, "scan", false, "clone and scan discovered repositories")
	cmd.Flags().StringVarP(&outputDir, "output", "o", "", "write findings of --scan to a directory")
	cmd.Flags().StringVar(&format, "format", "jsonl", "findings format when -o is used")
	cmd.Flags().IntVar(&targetTimeout, "target-timeout", 240, "per-repository timeout in seconds")
	return cmd
}

// --- cve ---

func newCVECmd(opts *Options) *cobra.Command {
	var concurrency int
	cmd := &cobra.Command{
		Use:   "cve [hosts...]",
		Short: "Probe hosts for common misconfigurations and metadata leaks",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			targets, err := source.Expand(args)
			if err != nil {
				return err
			}
			hosts := hostsOf(targets)
			if concurrency <= 0 {
				concurrency = 50
			}
			client := newReconClient(10 * time.Second)
			ctx := cmd.Context()
			out := cmd.OutOrStdout()

			paths := append(append([]string{}, cve.HighValuePaths...), scanners.WebPaths...)
			var mu sync.Mutex
			var wg sync.WaitGroup
			sem := make(chan struct{}, concurrency)
			for _, h := range hosts {
				wg.Add(1)
				sem <- struct{}{}
				go func(h string) {
					defer wg.Done()
					defer func() { <-sem }()
					base := "https://" + strings.TrimPrefix(strings.TrimPrefix(h, "https://"), "http://")
					for _, p := range paths {
						code, body := probe(ctx, client, base+p)
						if code == 200 && len(body) > 0 {
							mu.Lock()
							fmt.Fprintf(out, "[cve] %s%s  %s\n", base, p, firstLine(body))
							mu.Unlock()
						}
					}
				}(h)
			}
			wg.Wait()
			return nil
		},
	}
	cmd.Flags().IntVarP(&concurrency, "concurrency", "C", 50, "concurrency")
	return cmd
}

// --- envcrack ---

func newEnvCrackCmd(opts *Options) *cobra.Command {
	var concurrency int
	cmd := &cobra.Command{
		Use:   "envcrack [hosts...]",
		Short: "Fetch .env and config files from hosts and scan them",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig(opts)
			if err != nil {
				return err
			}
			engine, err := buildEngine(cfg, "", "", "")
			if err != nil {
				return err
			}
			targets, err := source.Expand(args)
			if err != nil {
				return err
			}
			hosts := hostsOf(targets)
			if len(hosts) > 500 {
				hosts = hosts[:500]
			}
			if concurrency <= 0 {
				concurrency = 30
			}
			client := newReconClient(10 * time.Second)
			ctx := cmd.Context()
			out := cmd.OutOrStdout()

			var mu sync.Mutex
			var wg sync.WaitGroup
			sem := make(chan struct{}, concurrency)
			fetched := 0
			for _, h := range hosts {
				wg.Add(1)
				sem <- struct{}{}
				go func(h string) {
					defer wg.Done()
					defer func() { <-sem }()
					base := "https://" + strings.TrimPrefix(strings.TrimPrefix(h, "https://"), "http://")
					for _, p := range scanners.EnvPaths {
						code, body := probe(ctx, client, base+p)
						if code != 200 || len(body) == 0 {
							continue
						}
						matches := engine.Scan(body)
						if len(matches) == 0 {
							continue
						}
						mu.Lock()
						fetched++
						fmt.Fprintf(out, "[env] %s%s (%d bytes) -> %d finding(s)\n", base, p, len(body), len(matches))
						for _, m := range matches {
							fmt.Fprintf(out, "      %-26s %s\n", m.Pattern.ID, truncate(m.Secret, 60))
						}
						mu.Unlock()
					}
				}(h)
			}
			wg.Wait()
			fmt.Fprintf(out, "\nfiles with findings: %d (over %d host(s))\n", fetched, len(hosts))
			return nil
		},
	}
	cmd.Flags().IntVarP(&concurrency, "concurrency", "C", 30, "concurrency")
	return cmd
}

func firstLine(b []byte) string {
	s := strings.TrimSpace(string(b))
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return truncate(s, 90)
}
