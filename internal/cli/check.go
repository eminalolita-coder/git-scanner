package cli

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/eminalolita-coder/git-scanner/internal/checkers"
)

func newCheckCmd(opts *Options) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "check [secret...]",
		Short: "Identify and verify one or more secrets",
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
			out := cmd.OutOrStdout()
			for _, arg := range args {
				matches := engine.ScanString(arg)
				if len(matches) == 0 {
					fmt.Fprintf(out, "%-60s no rule matched\n", truncate(arg, 60))
					continue
				}
				for _, m := range matches {
					cs := checkers.For(m.Pattern.ID, m.Pattern.Tags)
					if len(cs) == 0 {
						fmt.Fprintf(out, "%-28s %-40s unverifiable\n", m.Pattern.ID, truncate(m.Secret, 40))
						continue
					}
					res := cs[0].Check(cmd.Context(), m.Secret, nil)
					status := "INVALID"
					if res.Verified {
						status = "VALID"
					}
					line := fmt.Sprintf("%-28s %-40s %s", m.Pattern.ID, truncate(m.Secret, 40), status)
					if res.Identity != "" {
						line += "  (" + res.Identity + ")"
					}
					fmt.Fprintln(out, line)
				}
			}
			return nil
		},
	}
	return cmd
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

var _ = strings.TrimSpace
