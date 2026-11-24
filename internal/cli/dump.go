package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/eminalolita-coder/git-scanner/internal/dumper"
	"github.com/eminalolita-coder/git-scanner/internal/model"
)

func newDumpCmd(opts *Options) *cobra.Command {
	var (
		token   string
		user    string
		forge   string
		org     string
		limit   int
		scan    bool
		private bool
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
			repos, err := client.List(cmd.Context())
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
				engine, err := buildEngine(cfg, "")
				if err != nil {
					return err
				}
				runScanStream(cmd.Context(), cfg, engine, out, targets)
			}
			return nil
		},
	}

	f := cmd.Flags()
	f.StringVarP(&token, "token", "T", "", "forge API token")
	f.StringVarP(&user, "user", "u", "", "username (gerrit / bitbucket)")
	f.StringVar(&forge, "forge", "", "force forge: github|gitlab|gitea|gogs|bitbucket|azuredevops|gerrit")
	f.StringVar(&org, "org", "", "organisation (azure devops)")
	f.IntVarP(&limit, "limit", "n", 100, "max repositories to list")
	f.BoolVar(&scan, "scan", false, "clone and scan each repository")
	f.BoolVar(&private, "private-only", false, "list only private repositories")

	return cmd
}
