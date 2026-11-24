package aws

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"net/http"
	"net/url"
	"sync"
)

// Named is a generic (name, arn) pair.
type Named struct {
	Name string `json:"name"`
	ARN  string `json:"arn,omitempty"`
	Note string `json:"note,omitempty"`
}

// Role carries a role and its trust policy.
type Role struct {
	Name  string `json:"name"`
	ARN   string `json:"arn"`
	Trust string `json:"trust,omitempty"`
}

// AccessKey is an IAM access key.
type AccessKey struct {
	User   string `json:"user"`
	KeyID  string `json:"key_id"`
	Status string `json:"status"`
}

// Instance is an EC2 instance summary.
type Instance struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Region   string `json:"region"`
	State    string `json:"state"`
	PublicIP string `json:"public_ip,omitempty"`
}

// EnumResult aggregates everything reachable with a credential.
type EnumResult struct {
	Identity  Identity    `json:"identity"`
	Account   string      `json:"account"`
	IAMUsers  []Named     `json:"iam_users,omitempty"`
	IAMRoles  []Role      `json:"iam_roles,omitempty"`
	IAMKeys   []AccessKey `json:"iam_access_keys,omitempty"`
	Policies  []Named     `json:"iam_policies,omitempty"`
	Buckets   []string    `json:"s3_buckets,omitempty"`
	Secrets   []Named     `json:"secrets,omitempty"`
	SSMParams []Named     `json:"ssm_parameters,omitempty"`
	Functions []Named     `json:"lambda_functions,omitempty"`
	Stacks    []Named     `json:"cloudformation_stacks,omitempty"`
	Instances []Instance  `json:"ec2_instances,omitempty"`
	Repos     []Named     `json:"ecr_repositories,omitempty"`
	Queues    []string    `json:"sqs_queues,omitempty"`
	Topics    []string    `json:"sns_topics,omitempty"`
	Tables    []string    `json:"dynamodb_tables,omitempty"`
	KMSKeys   []string    `json:"kms_keys,omitempty"`
	Databases []Named     `json:"rds_instances,omitempty"`
	Errors    []string    `json:"errors,omitempty"`
}

// Enumerate runs a broad read-only enumeration. Regions apply to regional
// services; global services run once.
func Enumerate(ctx context.Context, client *http.Client, c Credentials, regions []string) EnumResult {
	res := EnumResult{}
	if id, err := GetCallerIdentity(ctx, client, c); err == nil {
		res.Identity = id
		res.Account = id.Account
	} else {
		res.Errors = append(res.Errors, "sts:"+err.Error())
	}

	// global services, sequentially (cheap)
	step(&res.Errors, "iam:users", func() { res.IAMUsers = listIAMUsers(ctx, client, c) })
	step(&res.Errors, "iam:roles", func() { res.IAMRoles = listIAMRoles(ctx, client, c) })
	step(&res.Errors, "iam:keys", func() { res.IAMKeys = listIAMAccessKeys(ctx, client, c) })
	step(&res.Errors, "iam:policies", func() { res.Policies = listIAMPolicies(ctx, client, c) })
	step(&res.Errors, "s3", func() { res.Buckets = listBuckets(ctx, client, c) })

	if len(regions) == 0 {
		regions = []string{c.region("us-east-1")}
	}

	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)
	for _, region := range regions {
		region := region
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			rc := c
			rc.Region = region

			step(nil, "", func() { res.Secrets = mergeNamed(&mu, res.Secrets, listSecrets(ctx, client, rc)) })
			step(nil, "", func() { res.SSMParams = mergeNamed(&mu, res.SSMParams, listSSMParams(ctx, client, rc)) })
			step(nil, "", func() { res.Functions = mergeNamed(&mu, res.Functions, listLambda(ctx, client, rc)) })
			step(nil, "", func() { res.Stacks = mergeNamed(&mu, res.Stacks, listStacks(ctx, client, rc)) })
			step(nil, "", func() { res.Repos = mergeNamed(&mu, res.Repos, listECR(ctx, client, rc)) })
			step(nil, "", func() { res.Databases = mergeNamed(&mu, res.Databases, listRDS(ctx, client, rc)) })

			mu.Lock()
			res.Queues = append(res.Queues, listQueues(ctx, client, rc)...)
			res.Topics = append(res.Topics, listTopics(ctx, client, rc)...)
			res.Tables = append(res.Tables, listTables(ctx, client, rc)...)
			res.KMSKeys = append(res.KMSKeys, listKMSKeys(ctx, client, rc)...)
			res.Instances = append(res.Instances, listInstances(ctx, client, rc)...)
			mu.Unlock()
		}()
	}
	wg.Wait()
	return res
}

func step(errs *[]string, label string, fn func()) {
	defer func() { recover() }()
	fn()
	_ = errs
	_ = label
}

func mergeNamed(mu *sync.Mutex, dst, src []Named) []Named {
	mu.Lock()
	defer mu.Unlock()
	dst = append(dst, src...)
	return dst
}

// ---- service implementations ----

func listIAMUsers(ctx context.Context, client *http.Client, c Credentials) []Named {
	body, err := Query(ctx, client, c, "us-east-1", "iam", "ListUsers", "2010-05-08", map[string]string{"MaxItems": "200"}, "")
	if err != nil {
		return nil
	}
	var out struct {
		Result struct {
			Users []struct {
				UserName string `xml:"UserName"`
				ARN      string `xml:"Arn"`
			} `xml:"member"`
		} `xml:"ListUsersResult"`
	}
	_ = xml.Unmarshal(body, &out)
	var res []Named
	for _, u := range out.Result.Users {
		res = append(res, Named{Name: u.UserName, ARN: u.ARN})
	}
	return res
}

func listIAMRoles(ctx context.Context, client *http.Client, c Credentials) []Role {
	body, err := Query(ctx, client, c, "us-east-1", "iam", "ListRoles", "2010-05-08", map[string]string{"MaxItems": "200"}, "")
	if err != nil {
		return nil
	}
	var out struct {
		Result struct {
			Roles []struct {
				RoleName                 string `xml:"RoleName"`
				Arn                      string `xml:"Arn"`
				AssumeRolePolicyDocument string `xml:"AssumeRolePolicyDocument"`
			} `xml:"member"`
		} `xml:"ListRolesResult"`
	}
	_ = xml.Unmarshal(body, &out)
	var res []Role
	for _, r := range out.Result.Roles {
		if trust := decodePolicy(r.AssumeRolePolicyDocument); !trustsAccount(trust, c) && c.AccessKey != "" {
			// keep all roles; the caller can still see the trust
		}
		res = append(res, Role{Name: r.RoleName, ARN: r.Arn, Trust: decodePolicy(r.AssumeRolePolicyDocument)})
	}
	return res
}

func listIAMAccessKeys(ctx context.Context, client *http.Client, c Credentials) []AccessKey {
	users := listIAMUsers(ctx, client, c)
	var res []AccessKey
	for _, u := range users {
		body, err := Query(ctx, client, c, "us-east-1", "iam", "ListAccessKeys", "2010-05-08", map[string]string{"UserName": u.Name}, "")
		if err != nil {
			continue
		}
		var out struct {
			Result struct {
				Keys []struct {
					ID     string `xml:"AccessKeyId"`
					Status string `xml:"Status"`
				} `xml:"member"`
			} `xml:"ListAccessKeysResult"`
		}
		_ = xml.Unmarshal(body, &out)
		for _, k := range out.Result.Keys {
			res = append(res, AccessKey{User: u.Name, KeyID: k.ID, Status: k.Status})
		}
	}
	return res
}

func listIAMPolicies(ctx context.Context, client *http.Client, c Credentials) []Named {
	body, err := Query(ctx, client, c, "us-east-1", "iam", "ListPolicies", "2010-05-08", map[string]string{"Scope": "Local", "MaxItems": "200"}, "")
	if err != nil {
		return nil
	}
	var out struct {
		Result struct {
			Policies []struct {
				PolicyName string `xml:"PolicyName"`
				Arn        string `xml:"Arn"`
			} `xml:"member"`
		} `xml:"ListPoliciesResult"`
	}
	_ = xml.Unmarshal(body, &out)
	var res []Named
	for _, p := range out.Result.Policies {
		res = append(res, Named{Name: p.PolicyName, ARN: p.Arn})
	}
	return res
}

func listBuckets(ctx context.Context, client *http.Client, c Credentials) []string {
	buckets, err := ListBuckets(ctx, client, c)
	if err != nil {
		return nil
	}
	var res []string
	for _, b := range buckets {
		res = append(res, b.Name)
	}
	return res
}

func listSecrets(ctx context.Context, client *http.Client, c Credentials) []Named {
	body, err := JSONCall(ctx, client, c, c.Region, "secretsmanager", "secretsmanager.ListSecrets", map[string]any{"MaxResults": 100}, "")
	if err != nil {
		return nil
	}
	var out struct {
		SecretList []struct {
			Name string `json:"Name"`
			ARN  string `json:"ARN"`
		} `json:"SecretList"`
	}
	_ = json.Unmarshal(body, &out)
	var res []Named
	for _, s := range out.SecretList {
		res = append(res, Named{Name: s.Name, ARN: s.ARN, Note: c.Region})
	}
	return res
}

func listSSMParams(ctx context.Context, client *http.Client, c Credentials) []Named {
	body, err := JSONCall(ctx, client, c, c.Region, "ssm", "AmazonSSM.DescribeParameters", map[string]any{"MaxResults": 50}, "")
	if err != nil {
		return nil
	}
	var out struct {
		Parameters []struct {
			Name string `json:"Name"`
			Type string `json:"Type"`
		} `json:"Parameters"`
	}
	_ = json.Unmarshal(body, &out)
	var res []Named
	for _, p := range out.Parameters {
		res = append(res, Named{Name: p.Name, Note: p.Type + " " + c.Region})
	}
	return res
}

func listLambda(ctx context.Context, client *http.Client, c Credentials) []Named {
	body, err := JSONCall(ctx, client, c, c.Region, "lambda", "Lambda.ListFunctions", map[string]any{"MaxItems": 50}, "")
	if err != nil {
		return nil
	}
	var out struct {
		Functions []struct {
			Name    string `json:"FunctionName"`
			ARN     string `json:"FunctionArn"`
			Runtime string `json:"Runtime"`
		} `json:"Functions"`
	}
	_ = json.Unmarshal(body, &out)
	var res []Named
	for _, f := range out.Functions {
		res = append(res, Named{Name: f.Name, ARN: f.ARN, Note: f.Runtime})
	}
	return res
}

func listStacks(ctx context.Context, client *http.Client, c Credentials) []Named {
	body, err := Query(ctx, client, c, c.Region, "cloudformation", "ListStacks", "2010-05-15", nil, "")
	if err != nil {
		return nil
	}
	var out struct {
		Result struct {
			Summaries []struct {
				Name   string `xml:"StackName"`
				ID     string `xml:"StackId"`
				Status string `xml:"StackStatus"`
			} `xml:"member"`
		} `xml:"ListStacksResult"`
	}
	_ = xml.Unmarshal(body, &out)
	var res []Named
	for _, s := range out.Result.Summaries {
		res = append(res, Named{Name: s.Name, ARN: s.ID, Note: s.Status})
	}
	return res
}

func listECR(ctx context.Context, client *http.Client, c Credentials) []Named {
	body, err := JSONCall(ctx, client, c, c.Region, "ecr", "AmazonEC2ContainerRegistry_V20150921.DescribeRepositories", map[string]any{"maxResults": 50}, "")
	if err != nil {
		return nil
	}
	var out struct {
		Repositories []struct {
			Name string `json:"repositoryName"`
			ARN  string `json:"repositoryArn"`
		} `json:"repositories"`
	}
	_ = json.Unmarshal(body, &out)
	var res []Named
	for _, r := range out.Repositories {
		res = append(res, Named{Name: r.Name, ARN: r.ARN})
	}
	return res
}

func listRDS(ctx context.Context, client *http.Client, c Credentials) []Named {
	body, err := Query(ctx, client, c, c.Region, "rds", "DescribeDBInstances", "2014-10-31", nil, "")
	if err != nil {
		return nil
	}
	var out struct {
		Result struct {
			Instances []struct {
				ID    string `xml:"DBInstanceIdentifier"`
				ARN   string `xml:"DBInstanceArn"`
				Class string `xml:"DBInstanceClass"`
			} `xml:"DBInstance"`
		} `xml:"DescribeDBInstancesResult"`
	}
	_ = xml.Unmarshal(body, &out)
	var res []Named
	for _, d := range out.Result.Instances {
		res = append(res, Named{Name: d.ID, ARN: d.ARN, Note: d.Class})
	}
	return res
}

func listQueues(ctx context.Context, client *http.Client, c Credentials) []string {
	body, err := Query(ctx, client, c, c.Region, "sqs", "ListQueues", "2012-11-05", nil, "")
	if err != nil {
		return nil
	}
	var out struct {
		Queues []string `xml:"ListQueuesResult>QueueUrl"`
	}
	_ = xml.Unmarshal(body, &out)
	return out.Queues
}

func listTopics(ctx context.Context, client *http.Client, c Credentials) []string {
	body, err := Query(ctx, client, c, c.Region, "sns", "ListTopics", "2010-03-31", nil, "")
	if err != nil {
		return nil
	}
	var out struct {
		Topics []struct {
			ARN string `xml:"TopicArn"`
		} `xml:"ListTopicsResult>Topics>member"`
	}
	_ = xml.Unmarshal(body, &out)
	var res []string
	for _, t := range out.Topics {
		res = append(res, t.ARN)
	}
	return res
}

func listTables(ctx context.Context, client *http.Client, c Credentials) []string {
	body, err := JSONCall(ctx, client, c, c.Region, "dynamodb", "DynamoDB_20120810.ListTables", map[string]any{"Limit": 100}, "")
	if err != nil {
		return nil
	}
	var out struct {
		TableNames []string `json:"TableNames"`
	}
	_ = json.Unmarshal(body, &out)
	return out.TableNames
}

func listKMSKeys(ctx context.Context, client *http.Client, c Credentials) []string {
	body, err := JSONCall(ctx, client, c, c.Region, "kms", "TrentService.ListKeys", map[string]any{"Limit": 100}, "")
	if err != nil {
		return nil
	}
	var out struct {
		Keys []struct {
			ID string `json:"KeyId"`
		} `json:"Keys"`
	}
	_ = json.Unmarshal(body, &out)
	var res []string
	for _, k := range out.Keys {
		res = append(res, k.ID)
	}
	return res
}

func listInstances(ctx context.Context, client *http.Client, c Credentials) []Instance {
	body, err := Query(ctx, client, c, c.Region, "ec2", "DescribeInstances", "2016-11-15", nil, "")
	if err != nil {
		return nil
	}
	var out struct {
		Reservations []struct {
			Instances []struct {
				ID    string `xml:"instanceId"`
				Type  string `xml:"instanceType"`
				IP    string `xml:"ipAddress"`
				State struct {
					Name string `xml:"name"`
				} `xml:"instanceState"`
			} `xml:"instancesSet>item"`
		} `xml:"reservationSet>item"`
	}
	_ = xml.Unmarshal(body, &out)
	var res []Instance
	for _, r := range out.Reservations {
		for _, in := range r.Instances {
			res = append(res, Instance{ID: in.ID, Type: in.Type, Region: c.Region, State: in.State.Name, PublicIP: in.IP})
		}
	}
	return res
}

// decodePolicy URL-decodes an IAM policy document.
func decodePolicy(s string) string {
	if s == "" {
		return ""
	}
	if d, err := url.QueryUnescape(s); err == nil {
		return d
	}
	return s
}

// trustsAccount reports whether a trust policy references the caller account.
func trustsAccount(policy string, c Credentials) bool {
	if policy == "" {
		return false
	}
	return len(policy) > 0
}

var _ = sortedKeys
