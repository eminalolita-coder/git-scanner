package aws

import (
	"context"
	"encoding/json"
	"net/http"
	"sort"
)

// EnvPair is a single environment variable (or a secret reference).
type EnvPair struct {
	Key       string `json:"key"`
	Value     string `json:"value,omitempty"`
	SecretRef string `json:"secret_ref,omitempty"`
}

// LambdaEnv is the environment of a Lambda function.
type LambdaEnv struct {
	Name    string    `json:"name"`
	Runtime string    `json:"runtime,omitempty"`
	Role    string    `json:"role,omitempty"`
	Vars    []EnvPair `json:"vars,omitempty"`
	Region  string    `json:"region,omitempty"`
}

// ContainerEnv is the environment of a container in a task definition.
type ContainerEnv struct {
	Name    string    `json:"name"`
	Image   string    `json:"image,omitempty"`
	Vars    []EnvPair `json:"vars,omitempty"`
	Secrets []EnvPair `json:"secrets,omitempty"`
}

// ECSEnv is the environment reachable through an ECS service.
type ECSEnv struct {
	Cluster        string         `json:"cluster"`
	Service        string         `json:"service"`
	TaskDefinition string         `json:"task_definition"`
	Containers     []ContainerEnv `json:"containers,omitempty"`
	Region         string         `json:"region,omitempty"`
}

// ListLambdaEnvironments extracts environment variables from up to max Lambda
// functions in the credential's region.
func ListLambdaEnvironments(ctx context.Context, client *http.Client, c Credentials, max int) []LambdaEnv {
	if max <= 0 {
		max = 25
	}
	functions := listLambdaNames(ctx, client, c)
	var out []LambdaEnv
	for i, name := range functions {
		if i >= max {
			break
		}
		body, err := JSONCall(ctx, client, c, c.Region, "lambda",
			"Lambda.GetFunctionConfiguration", map[string]any{"FunctionName": name}, "")
		if err != nil {
			continue
		}
		env, ok := parseLambdaEnv(body)
		if !ok {
			continue
		}
		env.Name = name
		env.Region = c.Region
		out = append(out, env)
	}
	return out
}

func listLambdaNames(ctx context.Context, client *http.Client, c Credentials) []string {
	body, err := JSONCall(ctx, client, c, c.Region, "lambda", "Lambda.ListFunctions", map[string]any{"MaxItems": 50}, "")
	if err != nil {
		return nil
	}
	var out struct {
		Functions []struct {
			Name string `json:"FunctionName"`
		} `json:"Functions"`
	}
	_ = json.Unmarshal(body, &out)
	var names []string
	for _, f := range out.Functions {
		names = append(names, f.Name)
	}
	return names
}

// parseLambdaEnv extracts the environment block of a GetFunctionConfiguration.
func parseLambdaEnv(body []byte) (LambdaEnv, bool) {
	var out struct {
		Runtime     string `json:"Runtime"`
		Role        string `json:"Role"`
		Environment struct {
			Variables map[string]string `json:"Variables"`
		} `json:"Environment"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return LambdaEnv{}, false
	}
	env := LambdaEnv{Runtime: out.Runtime, Role: out.Role}
	for k, v := range out.Environment.Variables {
		env.Vars = append(env.Vars, EnvPair{Key: k, Value: v})
	}
	sort.Slice(env.Vars, func(i, j int) bool { return env.Vars[i].Key < env.Vars[j].Key })
	return env, true
}

// ListECSEnvironments walks ECS clusters/services/task definitions and returns
// the container environments, following task definition revisions.
func ListECSEnvironments(ctx context.Context, client *http.Client, c Credentials, maxServices int) []ECSEnv {
	if maxServices <= 0 {
		maxServices = 25
	}
	clusters := listClusterARNs(ctx, client, c)
	var out []ECSEnv
	seen := 0
	for _, cluster := range clusters {
		if seen >= maxServices {
			break
		}
		services := listServiceARNs(ctx, client, c, cluster)
		for _, svc := range services {
			if seen >= maxServices {
				break
			}
			seen++
			taskDef := describeServiceTaskDef(ctx, client, c, cluster, svc)
			if taskDef == "" {
				continue
			}
			containers := describeTaskDefContainers(ctx, client, c, taskDef)
			if len(containers) == 0 {
				continue
			}
			out = append(out, ECSEnv{Cluster: cluster, Service: svc, TaskDefinition: taskDef, Containers: containers, Region: c.Region})
		}
	}
	return out
}

func listClusterARNs(ctx context.Context, client *http.Client, c Credentials) []string {
	body, err := JSONCall(ctx, client, c, c.Region, "ecs",
		"AmazonEC2ContainerServiceV20141113.ListClusters", map[string]any{}, "")
	if err != nil {
		return nil
	}
	var out struct {
		ClusterArns []string `json:"clusterArns"`
	}
	_ = json.Unmarshal(body, &out)
	return out.ClusterArns
}

func listServiceARNs(ctx context.Context, client *http.Client, c Credentials, cluster string) []string {
	body, err := JSONCall(ctx, client, c, c.Region, "ecs",
		"AmazonEC2ContainerServiceV20141113.ListServices", map[string]any{"cluster": cluster, "maxResults": 50}, "")
	if err != nil {
		return nil
	}
	var out struct {
		ServiceArns []string `json:"serviceArns"`
	}
	_ = json.Unmarshal(body, &out)
	return out.ServiceArns
}

func describeServiceTaskDef(ctx context.Context, client *http.Client, c Credentials, cluster, service string) string {
	body, err := JSONCall(ctx, client, c, c.Region, "ecs",
		"AmazonEC2ContainerServiceV20141113.DescribeServices",
		map[string]any{"cluster": cluster, "services": []string{service}}, "")
	if err != nil {
		return ""
	}
	var out struct {
		Services []struct {
			TaskDefinition string `json:"taskDefinition"`
		} `json:"services"`
	}
	_ = json.Unmarshal(body, &out)
	if len(out.Services) == 0 {
		return ""
	}
	return out.Services[0].TaskDefinition
}

func describeTaskDefContainers(ctx context.Context, client *http.Client, c Credentials, taskDef string) []ContainerEnv {
	body, err := JSONCall(ctx, client, c, c.Region, "ecs",
		"AmazonEC2ContainerServiceV20141113.DescribeTaskDefinition",
		map[string]any{"taskDefinition": taskDef}, "")
	if err != nil {
		return nil
	}
	return parseTaskDefContainers(body)
}

// parseTaskDefContainers extracts container environments from a task definition.
func parseTaskDefContainers(body []byte) []ContainerEnv {
	var out struct {
		TaskDefinition struct {
			ContainerDefinitions []struct {
				Name        string `json:"name"`
				Image       string `json:"image"`
				Environment []struct {
					Name  string `json:"name"`
					Value string `json:"value"`
				} `json:"environment"`
				Secrets []struct {
					Name      string `json:"name"`
					ValueFrom string `json:"valueFrom"`
				} `json:"secrets"`
			} `json:"containerDefinitions"`
		} `json:"taskDefinition"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return nil
	}
	var containers []ContainerEnv
	for _, cd := range out.TaskDefinition.ContainerDefinitions {
		c := ContainerEnv{Name: cd.Name, Image: cd.Image}
		for _, e := range cd.Environment {
			c.Vars = append(c.Vars, EnvPair{Key: e.Name, Value: e.Value})
		}
		for _, s := range cd.Secrets {
			c.Secrets = append(c.Secrets, EnvPair{Key: s.Name, SecretRef: s.ValueFrom})
		}
		containers = append(containers, c)
	}
	return containers
}
