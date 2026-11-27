package cli

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/eminalolita-coder/git-scanner/internal/patterns"
)

// newRulesCmd lists the detection rules so their IDs can be passed to
// --rules / --skip-rules (mass, scan).
func newRulesCmd(_ *Options) *cobra.Command {
	var tag, grep string
	cmd := &cobra.Command{
		Use:   "rules",
		Short: "List detection rules (IDs usable with --rules / --skip-rules)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			out := cmd.OutOrStdout()
			n := 0
			for _, p := range patterns.Builtin() {
				if tag != "" && !hasTag(p.Tags, tag) {
					continue
				}
				if grep != "" && !strings.Contains(p.ID, grep) {
					continue
				}
				fmt.Fprintf(out, "%-36s %s\n", p.ID, p.Description)
				n++
			}
			fmt.Fprintf(out, "\n%d rule(s)\n", n)
			return nil
		},
	}
	cmd.Flags().StringVar(&tag, "tag", "", "only rules carrying this tag")
	cmd.Flags().StringVar(&grep, "grep", "", "only rules whose ID contains this string")
	return cmd
}

func hasTag(tags []string, want string) bool {
	for _, t := range tags {
		if t == want {
			return true
		}
	}
	return false
}
