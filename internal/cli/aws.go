package cli

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/eminalolita-coder/git-scanner/internal/aws"
)

func newAWSCmd(opts *Options) *cobra.Command {
	var (
		secretKey    string
		sessionToken string
		region       string
		enumerate    bool
		deep         bool
		chain        bool
		envVars      bool
		ses          bool
		externalID   string
		depth        int
		asJSON       bool
		filter       string
	)

	cmd := &cobra.Command{
		Use:   "aws [access-key-id]",
		Short: "Verify AWS credentials, enumerate the account and walk role chains",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			creds := aws.Credentials{
				AccessKey:    args[0],
				SecretKey:    secretKey,
				SessionToken: sessionToken,
				Region:       region,
			}
			out := cmd.OutOrStdout()
			ctx := cmd.Context()

			id, idErr := aws.GetCallerIdentity(ctx, nil, creds)
			if idErr != nil && !ses {
				return idErr
			}
			if idErr == nil {
				fmt.Fprintf(out, "identity: %s\naccount : %s\nuser id : %s\n", id.ARN, id.Account, id.UserID)
			} else {
				fmt.Fprintf(out, "identity: %v\n", idErr)
			}

			if ses {
				// Independent of STS: a key can be denied sts:GetCallerIdentity
				// (or the call can be blocked) and still reach SES.
				acc, err := aws.SESAccountInfo(ctx, nil, creds, region)
				if err != nil {
					fmt.Fprintf(out, "\nSES: %v\n", err)
				} else {
					fmt.Fprintf(out, "\nSES (%s): sending=%v sandbox=%v quota=%.0f/24h rate=%.1f/s sent=%.0f\n",
						acc.Region, acc.SendingEnabled, acc.Sandbox, acc.Max24HourSend, acc.MaxSendRate, acc.SentLast24Hours)
					if len(acc.Identities) > 0 {
						fmt.Fprintf(out, "verified identities (%d):\n", len(acc.Identities))
						for _, i := range acc.Identities {
							fmt.Fprintf(out, "  %s\n", i)
						}
					}
				}
			}

			if enumerate {
				if buckets, err := aws.ListBuckets(ctx, nil, creds); err == nil {
					fmt.Fprintf(out, "\nS3 buckets (%d):\n", len(buckets))
					for _, b := range buckets {
						fmt.Fprintf(out, "  %s\n", b.Name)
					}
				} else {
					fmt.Fprintf(out, "\nS3: %v\n", err)
				}
				if users, err := aws.ListIAMUsers(ctx, nil, creds); err == nil {
					fmt.Fprintf(out, "\nIAM users (%d):\n", len(users))
					for _, u := range users {
						fmt.Fprintf(out, "  %s\n", u.ARN)
					}
				}
			}

			if deep {
				regions := []string{region}
				res := aws.Enumerate(ctx, nil, creds, regions)
				printEnum(out, res, asJSON)
			}

			if envVars {
				lambdas := aws.ListLambdaEnvironments(ctx, nil, creds, 25)
				ecs := aws.ListECSEnvironments(ctx, nil, creds, 25)
				printEnvs(out, lambdas, ecs, asJSON)
			}

			if chain {
				roles := aws.ListRolesForChain(ctx, nil, creds)
				links := aws.AssumeChains(ctx, nil, creds, roles, aws.ChainOptions{
					MaxDepth: depth, ExternalID: externalID, Duration: 3600, Match: filter,
				})
				ok, ko := 0, 0
				fmt.Fprintf(out, "\nrole chain (%d candidate roles):\n", len(roles))
				for _, l := range links {
					if l.Err != "" {
						ko++
						continue
					}
					ok++
					fmt.Fprintf(out, "  %s -> %s (expires %s)\n", l.From, l.AssumedARN, l.ExpiresAt.Format("15:04:05"))
				}
				fmt.Fprintf(out, "\n%d assumable, %d denied\n", ok, ko)
			}
			return nil
		},
	}

	f := cmd.Flags()
	f.StringVar(&secretKey, "secret-key", "", "paired secret access key")
	f.StringVar(&sessionToken, "session-token", "", "session token")
	f.StringVar(&region, "region", "us-east-1", "region")
	f.BoolVarP(&enumerate, "enumerate", "e", false, "list S3 buckets and IAM users")
	f.BoolVar(&deep, "deep", false, "full multi-service enumeration")
	f.BoolVar(&chain, "chain", false, "walk assume-role chains")
	f.BoolVar(&envVars, "env", false, "extract Lambda and ECS environment variables")
	f.BoolVar(&ses, "ses", false, "check SES access (sending status, quota, identities)")
	f.StringVar(&externalID, "external-id", "", "external id for AssumeRole")
	f.IntVar(&depth, "depth", 2, "max assume-role chain depth")
	f.StringVar(&filter, "filter", "", "regex filter on role name/arn")
	f.BoolVar(&asJSON, "json", false, "JSON output for --deep")
	return cmd
}

func printEnum(out io.Writer, res aws.EnumResult, asJSON bool) {
	if asJSON {
		data, _ := json.MarshalIndent(res, "", "  ")
		fmt.Fprintf(out, "\n%s\n", data)
		return
	}
	section(out, "secrets", namedNames(res.Secrets))
	section(out, "ssm parameters", namedNames(res.SSMParams))
	section(out, "lambda functions", namedNames(res.Functions))
	section(out, "cloudformation stacks", namedNames(res.Stacks))
	section(out, "ecr repositories", namedNames(res.Repos))
	section(out, "rds instances", namedNames(res.Databases))
	section(out, "sqs queues", res.Queues)
	section(out, "sns topics", res.Topics)
	section(out, "dynamodb tables", res.Tables)
	section(out, "kms keys", res.KMSKeys)
	if len(res.Instances) > 0 {
		fmt.Fprintf(out, "\nEC2 instances (%d):\n", len(res.Instances))
		for _, i := range res.Instances {
			fmt.Fprintf(out, "  %s %s %s %s\n", i.Region, i.ID, i.Type, i.PublicIP)
		}
	}
	if len(res.IAMRoles) > 0 {
		fmt.Fprintf(out, "\nIAM roles (%d):\n", len(res.IAMRoles))
		for _, r := range res.IAMRoles {
			fmt.Fprintf(out, "  %s\n", r.ARN)
		}
	}
	section(out, "IAM users", namedNames(res.IAMUsers))
	section(out, "IAM policies", namedNames(res.Policies))
	if len(res.Errors) > 0 {
		fmt.Fprintf(out, "\n%d service error(s)\n", len(res.Errors))
	}
}

func printEnvs(out io.Writer, lambdas []aws.LambdaEnv, ecs []aws.ECSEnv, asJSON bool) {
	if asJSON {
		data, _ := json.MarshalIndent(map[string]any{"lambda": lambdas, "ecs": ecs}, "", "  ")
		fmt.Fprintf(out, "\n%s\n", data)
		return
	}
	if len(lambdas) == 0 && len(ecs) == 0 {
		fmt.Fprintln(out, "\nno Lambda/ECS environment found")
		return
	}
	for _, l := range lambdas {
		fmt.Fprintf(out, "\n[lambda] %s (%s, %s) - %d var(s)\n", l.Name, l.Runtime, l.Region, len(l.Vars))
		if l.Role != "" {
			fmt.Fprintf(out, "  role: %s\n", l.Role)
		}
		for _, v := range l.Vars {
			fmt.Fprintf(out, "  %s=%s\n", v.Key, truncate(v.Value, 90))
		}
	}
	for _, e := range ecs {
		fmt.Fprintf(out, "\n[ecs] %s/%s -> %s\n", e.Cluster, e.Service, e.TaskDefinition)
		for _, c := range e.Containers {
			fmt.Fprintf(out, "  container %s (%s)\n", c.Name, c.Image)
			for _, v := range c.Vars {
				fmt.Fprintf(out, "    %s=%s\n", v.Key, truncate(v.Value, 90))
			}
			for _, s := range c.Secrets {
				fmt.Fprintf(out, "    %s <- %s\n", s.Key, s.SecretRef)
			}
		}
	}
}

func namedNames(ns []aws.Named) []string {
	out := make([]string, 0, len(ns))
	for _, n := range ns {
		out = append(out, n.Name)
	}
	return out
}

func section(out io.Writer, title string, items []string) {
	if len(items) == 0 {
		return
	}
	fmt.Fprintf(out, "\n%s (%d):\n", title, len(items))
	for _, it := range items {
		fmt.Fprintf(out, "  %s\n", it)
	}
}
