package cli

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/eminalolita-coder/git-scanner/internal/dumper"
	"github.com/eminalolita-coder/git-scanner/internal/model"
	"github.com/eminalolita-coder/git-scanner/internal/output"
)

func newDumpCmd(opts *Options) *cobra.Command {
	var (
		token         string
		user          string
		forge         string
		org           string
		owner         string
		limit         int
		scan          bool
		private       bool
		outputDir     string
		format        string
		targetTimeout int
	)

	cmd := &cobra.Command{
		Use:   "dump [host-or-url]",
		Short: "Enumerate repositories reachable with a forge token",
		Long: `dump lists the repositories a token can access on a git forge.

The forge is guessed from the host unless --forge is given. Use --scan to
clone and scan every discovered repository.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			host := "github.com"
			if len(args) == 1 {
				host = args[0]
			}
			frg := dumper.ForgeFromHost(host)
			if forge != "" {
				frg = dumper.Forge(forge)
			}
			base := host
			if len(args) == 0 && forge == "" {
				base = ""
			}

			client := dumper.New(frg, base, token)
			client.Org = org
			if user != "" {
				client.Token = user + ":" + token
			}
			var repos []dumper.Repo
			var err error
			if owner != "" {
				repos, err = client.ListOwner(cmd.Context(), owner)
			} else {
				repos, err = client.List(cmd.Context())
			}
			if err != nil {
				return err
			}

			out := cmd.OutOrStdout()
			var targets []model.Target
			for i, r := range repos {
				if limit > 0 && i >= limit {
					break
				}
				if private && !r.Private {
					continue
				}
				fmt.Fprintf(out, "%-40s %s\n", r.FullName, r.CloneURL)
				targets = append(targets, model.Target{Kind: model.KindGitRepo, Value: r.CloneURL, GitHost: string(r.Forge), Token: token})
			}
			fmt.Fprintf(out, "\n%d repositories\n", len(targets))

			if scan && len(targets) > 0 {
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
				engine, err := buildEngine(cfg, "", "", "")
				if err != nil {
					return err
				}
				if outputDir != "" {
					w, err := output.New(cfg.Output.Directory, cfg.Output.Format)
					if err != nil {
						return err
					}
					defer w.Close()
					fmt.Fprintf(out, "findings -> %s\n", w.Path())
					runScanWriter(cmd.Context(), cfg, engine, w, targets, out, time.Duration(targetTimeout)*time.Second)
				} else {
					runScanStream(cmd.Context(), cfg, engine, out, targets)
				}
			}
			return nil
		},
	}

	f := cmd.Flags()
	f.StringVarP(&token, "token", "T", "", "forge API token")
	f.StringVarP(&user, "user", "u", "", "username (gerrit / bitbucket)")
	f.StringVar(&forge, "forge", "", "force forge: github|gitlab|gitea|gogs|bitbucket|azuredevops|gerrit")
	f.StringVar(&org, "org", "", "organisation (azure devops)")
	f.StringVar(&owner, "owner", "", "list a specific owner's repositories (works without a token)")
	f.StringVarP(&outputDir, "output", "o", "", "write findings of --scan to a directory")
	f.StringVar(&format, "format", "jsonl", "findings format when -o is used")
	f.IntVar(&targetTimeout, "target-timeout", 300, "per-repository timeout in seconds")
	f.IntVarP(&limit, "limit", "n", 100, "max repositories to list")
	f.BoolVar(&scan, "scan", false, "clone and scan each repository")
	f.BoolVar(&private, "private-only", false, "list only private repositories")

	return cmd
}
