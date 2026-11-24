// Package cli wires the command-line interface.
package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/eminalolita-coder/git-scanner/internal/logger"
)

// Options holds values shared by commands.
type Options struct {
	ConfigPath string
	Verbose    bool
	Quiet      bool
	NoColor    bool
	Threads    int
	Timeout    int
}

// Execute runs the root command.
func Execute(version string) error {
	root := newRootCmd(version)
	return root.Execute()
}

func newRootCmd(version string) *cobra.Command {
	opts := &Options{}

	root := &cobra.Command{
		Use:   "git-scanner",
		Short: "Fast secret scanner for git repositories, URLs and files",
		Long: `git-scanner finds leaked secrets in git repositories, local files, archives
and live URLs. Findings can be verified against provider APIs.

Targets can be repository URLs, web URLs, files, directories, or a text file
listing one target per line.`,
		Version:       version,
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			switch {
			case opts.Quiet:
				logger.SetLevel(logger.LevelWarn)
			case opts.Verbose:
				logger.SetLevel(logger.LevelDebug)
			}
			logger.SetColor(!opts.NoColor && isTerminal())
			return nil
		},
	}

	pf := root.PersistentFlags()
	pf.StringVarP(&opts.ConfigPath, "config", "c", "", "path to config file")
	pf.BoolVarP(&opts.Verbose, "verbose", "v", false, "debug logging")
	pf.BoolVarP(&opts.Quiet, "quiet", "q", false, "only warnings and errors")
	pf.BoolVar(&opts.NoColor, "no-color", false, "disable colored output")
	pf.IntVarP(&opts.Threads, "threads", "t", 0, "concurrency (0 = config default)")
	pf.IntVar(&opts.Timeout, "timeout", 0, "per-request timeout in seconds")

	root.AddCommand(
		newScanCmd(opts),
		newMassCmd(opts),
		newCheckCmd(opts),
		newDiscoverCmd(opts),
		newCVECmd(opts),
		newEnvCrackCmd(opts),
		newDumpCmd(opts),
		newAWSCmd(opts),
		newS3Cmd(opts),
		newJSCmd(opts),
		newConfigCmd(opts),
		newVersionCmd(version),
	)

	return root
}

func isTerminal() bool {
	fi, err := os.Stderr.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

func newVersionCmd(version string) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version",
		RunE: func(cmd *cobra.Command, _ []string) error {
			fmt.Fprintln(cmd.OutOrStdout(), "git-scanner", version)
			return nil
		},
	}
}
