package cli

import (
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/spf13/cobra"

	"github.com/eminalolita-coder/git-scanner/internal/jscracker"
	"github.com/eminalolita-coder/git-scanner/internal/source"
)

func newJSCmd(opts *Options) *cobra.Command {
	var maxScripts int
	cmd := &cobra.Command{
		Use:   "js [urls...]",
		Short: "Analyse JavaScript bundles for endpoints, secrets and source maps",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			targets, err := source.Expand(args)
			if err != nil {
				return err
			}
			client := &http.Client{Timeout: 15 * time.Second}
			o := jscracker.DefaultOptions()
			if maxScripts > 0 {
				o.MaxScripts = maxScripts
			}
			out := cmd.OutOrStdout()
			for _, t := range targets {
				res, err := jscracker.AnalyzeURL(cmd.Context(), client, t.Value, o)
				if err != nil {
					fmt.Fprintf(out, "[js] %s: %v\n", t.Value, err)
					continue
				}
				fmt.Fprintf(out, "\n=== %s ===\n", t.Value)
				printList(out, "endpoints", res.Endpoints)
				printList(out, "paths", res.Paths)
				printList(out, "subdomains", res.Subdomains)
				printList(out, "source maps", res.SourceMaps)
				if len(res.Leaks) > 0 {
					fmt.Fprintln(out, "config leaks:")
					for k, v := range res.Leaks {
						fmt.Fprintf(out, "  %-30s %s\n", k, v)
					}
				}
			}
			return nil
		},
	}
	cmd.Flags().IntVar(&maxScripts, "max-scripts", 40, "max scripts to fetch per page")
	return cmd
}

func printList(out io.Writer, title string, items []string) {
	if len(items) == 0 {
		return
	}
	fmt.Fprintf(out, "%s (%d):\n", title, len(items))
	for _, it := range items {
		fmt.Fprintf(out, "  %s\n", it)
	}
}
