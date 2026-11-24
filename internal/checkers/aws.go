package checkers

import (
	"context"
	"strings"

	"github.com/eminalolita-coder/git-scanner/internal/aws"
)

func init() {
	Register(&awsChecker{})
}

// awsChecker verifies an AWS access key via sts:GetCallerIdentity. It needs the
// paired secret (and optional session token) in meta.
type awsChecker struct{}

func (a *awsChecker) Name() string { return "aws" }

func (a *awsChecker) Match(ruleID string, tags []string) bool {
	switch ruleID {
	case "aws-access-key-id", "aws-access-key-boundary":
		return true
	}
	for _, t := range tags {
		if t == "aws" && strings.Contains(ruleID, "access-key") {
			return true
		}
	}
	return false
}

func (a *awsChecker) Check(ctx context.Context, accessKey string, meta map[string]string) Result {
	secret := meta["secret"]
	if secret == "" {
		return Result{Err: "missing paired secret"}
	}
	id, err := aws.GetCallerIdentity(ctx, httpClient, aws.Credentials{
		AccessKey:    accessKey,
		SecretKey:    secret,
		SessionToken: meta["session_token"],
	})
	if err != nil {
		return Result{Err: err.Error()}
	}
	return Result{
		Verified: true,
		Identity: id.ARN,
		Meta:     map[string]string{"account": id.Account, "arn": id.ARN, "user_id": id.UserID},
	}
}
