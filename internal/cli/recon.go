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
	sc := scanner.New(scanner.Options{
		Config:   cfg,
		Engine:   engine,
		Writer:   output.NewStream(out),
		Notifier: webhook.New(cfg.Webhooks),
	})
	sc.Run(ctx, targets)
	st := sc.Stats()
	fmt.Fprintf(out, "\n%d file(s), %d finding(s)\n", st.Files, st.Findings)
}

// --- discover ---

func newDiscoverCmd(opts *Options) *cobra.Command {
	var concurrency int
	var scan bool

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
			found := 0

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
							found++
							fmt.Fprintf(out, "[git] %s (.git exposed)\n", base)
							mu.Unlock()
							if scan {
								cfg, err := loadConfig(opts)
								if err == nil {
									eng, err := buildEngine(cfg, "")
									if err == nil {
										runScanStream(ctx, cfg, eng, out, []model.Target{{Kind: model.KindGitRepo, Value: base + "/.git", GitHost: "gitea"}})
									}
								}
							}
							return
						}
					}
				}(h)
			}
			wg.Wait()
			fmt.Fprintf(out, "\nexposed .git: %d / %d host(s)\n", found, len(hosts))
			return nil
		},
	}
	cmd.Flags().IntVarP(&concurrency, "concurrency", "C", 50, "concurrency")
	cmd.Flags().BoolVar(&scan, "scan", false, "clone and scan discovered repositories")
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
			engine, err := buildEngine(cfg, "")
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
