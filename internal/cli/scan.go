package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/eminalolita-coder/git-scanner/internal/config"
	"github.com/eminalolita-coder/git-scanner/internal/logger"
	"github.com/eminalolita-coder/git-scanner/internal/output"
	"github.com/eminalolita-coder/git-scanner/internal/patterns"
	"github.com/eminalolita-coder/git-scanner/internal/scanner"
	"github.com/eminalolita-coder/git-scanner/internal/source"
	"github.com/eminalolita-coder/git-scanner/internal/webhook"
)

func newScanCmd(opts *Options) *cobra.Command {
	var (
		verify       bool
		patternsFile string
		outputDir    string
		format       string
		rulesFlag    string
		skipRules    string
	)

	cmd := &cobra.Command{
		Use:   "scan [targets...]",
		Short: "Scan repositories, URLs, files or directories for secrets",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
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

			engine, err := buildEngine(cfg, patternsFile, rulesFlag, skipRules)
			if err != nil {
				return err
			}
			logger.Infof("loaded %d patterns", engine.Count())

			targets, err := source.Expand(args)
			if err != nil {
				return err
			}
			if len(targets) == 0 {
				return errors.New("no targets")
			}

			writer, err := output.New(cfg.Output.Directory, cfg.Output.Format)
			if err != nil {
				return err
			}
			defer writer.Close()

			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()

			sc := scanner.New(scanner.Options{
				Config:   cfg,
				Engine:   engine,
				Verify:   verify,
				Writer:   writer,
				Notifier: webhook.New(cfg.Webhooks),
			})
			logger.Infof("scanning %d target(s) -> %s", len(targets), writer.Path())
			sc.Run(ctx, targets)

			st := sc.Stats()
			logger.Infof("done: %d files, %d findings (%d verified)", st.Files, st.Findings, st.Verified)
			return nil
		},
	}

	f := cmd.Flags()
	f.BoolVar(&verify, "verify", false, "verify findings against provider APIs")
	f.StringVar(&patternsFile, "patterns", "", "extra patterns JSON file")
	f.StringVarP(&outputDir, "output", "o", "", "output directory (default from config)")
	f.StringVar(&format, "format", "", "output format: jsonl|csv|txt")
	f.StringVar(&rulesFlag, "rules", "", "only run these rule IDs (comma-separated; see `rules` command)")
	f.StringVar(&skipRules, "skip-rules", "", "skip these rule IDs (comma-separated)")

	return cmd
}

func loadConfig(opts *Options) (*config.Config, error) {
	cfg, err := config.Load(opts.ConfigPath)
	if err != nil {
		return nil, err
	}
	if opts.Threads > 0 {
		cfg.Performance.Threads = opts.Threads
	}
	if opts.Timeout > 0 {
		cfg.Performance.TimeoutSeconds = opts.Timeout
	}
	if opts.Proxy != "" {
		cfg.Proxy.Enabled = true
		cfg.Proxy.URL = normalizeProxy(opts.Proxy)
		if cfg.Proxy.Protocol == "" {
			cfg.Proxy.Protocol = "http"
		}
	}
	return cfg, nil
}

// normalizeProxy accepts either a proxy URL or the "host:port:user:pass" form
// used by proxy providers, and returns a URL.
func normalizeProxy(raw string) string {
	raw = strings.TrimSpace(raw)
	if strings.Contains(raw, "://") {
		return raw
	}
	parts := strings.SplitN(raw, ":", 4)
	switch len(parts) {
	case 4:
		return fmt.Sprintf("http://%s:%s@%s:%s", parts[2], parts[3], parts[0], parts[1])
	case 2:
		return fmt.Sprintf("http://%s:%s", parts[0], parts[1])
	}
	return raw
}

func buildEngine(cfg *config.Config, extra, keepCSV, skipCSV string) (*patterns.Engine, error) {
	engine := patterns.NewEngine(cfg.ScanLimits.RegexMatchesPerPattern)
	base := patterns.Builtin()
	rules, unknown := patterns.Select(base, splitCSV(keepCSV), splitCSV(skipCSV))
	if len(unknown) > 0 {
		fmt.Fprintf(os.Stdout, "rules: unknown ID(s) ignored: %s\n", strings.Join(unknown, ", "))
	}
	if err := engine.AddAll(rules); err != nil {
		return nil, err
	}
	if extra != "" {
		ps, err := patterns.LoadFile(extra)
		if err != nil {
			return nil, err
		}
		if err := engine.AddAll(ps); err != nil {
			return nil, err
		}
	}
	return engine, nil
}

var _ = context.Background
