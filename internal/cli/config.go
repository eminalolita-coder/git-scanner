package cli

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/eminalolita-coder/git-scanner/internal/config"
)

func newConfigCmd(opts *Options) *cobra.Command {
	cmd := &cobra.Command{Use: "config", Short: "Manage configuration"}

	initCmd := &cobra.Command{
		Use:   "init [path]",
		Short: "Write a default configuration file",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := "config.json"
			if len(args) == 1 {
				path = args[0]
			}
			if _, err := os.Stat(path); err == nil {
				return fmt.Errorf("%s already exists", path)
			}
			return config.Default().Save(path)
		},
	}

	showCmd := &cobra.Command{
		Use:   "show",
		Short: "Print the effective configuration",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := config.Load(opts.ConfigPath)
			if err != nil {
				return err
			}
			data, err := json.MarshalIndent(cfg, "", "  ")
			if err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), string(data))
			return nil
		},
	}

	cmd.AddCommand(initCmd, showCmd)
	return cmd
}
