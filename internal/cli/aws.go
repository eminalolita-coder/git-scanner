package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/eminalolita-coder/git-scanner/internal/aws"
)

func newAWSCmd(opts *Options) *cobra.Command {
	var (
		secretKey    string
		sessionToken string
		region       string
		enumerate    bool
	)

	cmd := &cobra.Command{
		Use:   "aws [access-key-id]",
		Short: "Verify AWS credentials and optionally enumerate the account",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			creds := aws.Credentials{
				AccessKey:    args[0],
				SecretKey:    secretKey,
				SessionToken: sessionToken,
				Region:       region,
			}
			out := cmd.OutOrStdout()

			id, err := aws.GetCallerIdentity(cmd.Context(), nil, creds)
			if err != nil {
				return err
			}
			fmt.Fprintf(out, "identity: %s\naccount : %s\nuser id : %s\n", id.ARN, id.Account, id.UserID)

			if !enumerate {
				return nil
			}
			if buckets, err := aws.ListBuckets(cmd.Context(), nil, creds); err == nil {
				fmt.Fprintf(out, "\nS3 buckets (%d):\n", len(buckets))
				for _, b := range buckets {
					fmt.Fprintf(out, "  %s\n", b.Name)
				}
			} else {
				fmt.Fprintf(out, "\nS3: %v\n", err)
			}
			if users, err := aws.ListIAMUsers(cmd.Context(), nil, creds); err == nil {
				fmt.Fprintf(out, "\nIAM users (%d):\n", len(users))
				for _, u := range users {
					fmt.Fprintf(out, "  %s\n", u.ARN)
				}
			} else {
				fmt.Fprintf(out, "\nIAM: %v\n", err)
			}
			return nil
		},
	}

	f := cmd.Flags()
	f.StringVar(&secretKey, "secret-key", "", "paired secret access key")
	f.StringVar(&sessionToken, "session-token", "", "session token (for temporary credentials)")
	f.StringVar(&region, "region", "us-east-1", "region for signing")
	f.BoolVarP(&enumerate, "enumerate", "e", false, "list S3 buckets and IAM users")

	return cmd
}
