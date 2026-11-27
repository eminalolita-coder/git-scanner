package cli

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/eminalolita-coder/git-scanner/internal/checkers"
	"github.com/eminalolita-coder/git-scanner/internal/model"
	"github.com/eminalolita-coder/git-scanner/internal/output"
)

func newCheckCmd(opts *Options) *cobra.Command {
	var (
		fromFile string
		outDir   string
		only     string
	)

	cmd := &cobra.Command{
		Use:   "check [secret...]",
		Short: "Identify and verify secrets (or re-verify a findings file)",
		Args:  cobra.MinimumNArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig(opts)
			if err != nil {
				return err
			}
			engine, err := buildEngine(cfg, "", "", "")
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()

			if fromFile != "" {
				return verifyFindingsFile(cmd, out, fromFile, outDir, only)
			}
			if len(args) == 0 {
				return fmt.Errorf("give secrets or --from findings.jsonl")
			}
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

	f := cmd.Flags()
	f.StringVar(&fromFile, "from", "", "re-verify findings from a jsonl file")
	f.StringVarP(&outDir, "output", "o", "", "write re-verified findings to a directory")
	f.StringVar(&only, "only", "", "comma separated rule ids to verify")
	return cmd
}

// truncate shortens s to n bytes with an ellipsis.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

// verifyFindingsFile re-runs the checkers over a findings file. It is much
// cheaper than re-scanning and keeps the original provenance.
func verifyFindingsFile(cmd *cobra.Command, out interface{ Write([]byte) (int, error) }, path, outDir, only string) error {
	fh, err := os.Open(path)
	if err != nil {
		return err
	}
	defer fh.Close()

	filter := map[string]bool{}
	for _, r := range strings.Split(only, ",") {
		if r = strings.TrimSpace(r); r != "" {
			filter[r] = true
		}
	}

	var writer output.Writer
	if outDir != "" {
		if writer, err = output.New(outDir, "jsonl"); err != nil {
			return err
		}
		defer writer.Close()
	}

	checked, verified := 0, 0
	sc := bufio.NewScanner(fh)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var f model.Finding
		if err := json.Unmarshal([]byte(line), &f); err != nil {
			continue
		}
		if len(filter) > 0 && !filter[f.RuleID] {
			continue
		}
		cs := checkers.For(f.RuleID, f.Tags)
		if len(cs) == 0 {
			continue
		}
		checked++
		res := cs[0].Check(cmd.Context(), f.Secret, f.Extra)
		if !res.Verified {
			continue
		}
		verified++
		f.Verified = true
		f.Checker = cs[0].Name()
		if res.Identity != "" {
			if f.Extra == nil {
				f.Extra = map[string]string{}
			}
			f.Extra["identity"] = res.Identity
		}
		loc := f.Location.Source + f.Location.File
		fmt.Fprintf(out, "VALID  %-26s %-40s %s\n", f.RuleID, truncate(f.Secret, 40), truncate(loc, 50))
		if writer != nil {
			_ = writer.Write(f)
		}
	}
	if err := sc.Err(); err != nil {
		return err
	}
	if writer != nil {
		fmt.Fprintf(out, "\n%d checked, %d valid -> %s\n", checked, verified, writer.Path())
	} else {
		fmt.Fprintf(out, "\n%d checked, %d valid\n", checked, verified)
	}
	return nil
}
