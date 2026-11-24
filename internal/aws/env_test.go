package aws

import "testing"

func TestParseLambdaEnv(t *testing.T) {
	body := []byte(`{"Runtime":"nodejs20.x","Role":"arn:aws:iam::1:role/lambda","Environment":{"Variables":{"DB_URL":"postgres://u:p@h/db","API_KEY":"abc"}}}`)
	env, ok := parseLambdaEnv(body)
	if !ok {
		t.Fatal("parse failed")
	}
	if env.Runtime != "nodejs20.x" {
		t.Errorf("runtime = %q", env.Runtime)
	}
	if len(env.Vars) != 2 {
		t.Fatalf("expected 2 vars, got %d", len(env.Vars))
	}
	// sorted by key
	if env.Vars[0].Key != "API_KEY" || env.Vars[1].Key != "DB_URL" {
		t.Errorf("vars not sorted: %+v", env.Vars)
	}
}

func TestParseTaskDefContainers(t *testing.T) {
	body := []byte(`{"taskDefinition":{"containerDefinitions":[
	  {"name":"web","image":"nginx","environment":[{"name":"ENV","value":"prod"}],
	   "secrets":[{"name":"DB_PASS","valueFrom":"arn:aws:ssm:...:parameter/db"}]}
	]}}`)
	cs := parseTaskDefContainers(body)
	if len(cs) != 1 {
		t.Fatalf("expected 1 container, got %d", len(cs))
	}
	if cs[0].Name != "web" || len(cs[0].Vars) != 1 || len(cs[0].Secrets) != 1 {
		t.Errorf("unexpected container: %+v", cs[0])
	}
	if cs[0].Secrets[0].SecretRef == "" {
		t.Error("secret ref not captured")
	}
}
