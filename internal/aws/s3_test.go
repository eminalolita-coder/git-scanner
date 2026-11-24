package aws

import (
	"strings"
	"testing"
)

func TestObjectURL(t *testing.T) {
	got := ObjectURL("mybucket", "eu-west-1", "path/to/obj", false)
	want := "https://mybucket.s3.eu-west-1.amazonaws.com/path/to/obj"
	if got != want {
		t.Errorf("ObjectURL = %q, want %q", got, want)
	}
	got = ObjectURL("mybucket", "us-east-1", "k", false)
	if !strings.Contains(got, "mybucket.s3.amazonaws.com/k") {
		t.Errorf("us-east-1 url unexpected: %q", got)
	}
}

func TestParseListing(t *testing.T) {
	body := []byte(`<ListBucketResult>
	  <KeyCount>2</KeyCount>
	  <Contents><Key>a.txt</Key></Contents>
	  <Contents><Key>dir/b.env</Key></Contents>
	</ListBucketResult>`)
	keys, count := parseListing(body)
	if count != 2 || len(keys) != 2 {
		t.Fatalf("parseListing = %v, %d", keys, count)
	}
	if keys[1] != "dir/b.env" {
		t.Errorf("unexpected key: %q", keys[1])
	}
}

func TestTrustsCaller(t *testing.T) {
	account := "123456789012"
	policy := `{"Statement":[{"Principal":{"AWS":"arn:aws:iam::123456789012:root"}}]}`
	if !TrustsCaller(policy, account, "") {
		t.Error("expected trust match on account root")
	}
	if TrustsCaller(policy, "999999999999", "") {
		t.Error("did not expect trust match")
	}
	if !TrustsCaller(`{"Principal":{"AWS":"*"}}`, "", "") {
		t.Error("expected wildcard trust")
	}
}

func TestShorten(t *testing.T) {
	if got := shorten("arn:aws:iam::123:role/Admin"); got != "Admin" {
		t.Errorf("shorten = %q", got)
	}
	if got := shorten("arn:aws:iam::123:role/path/Deep"); got != "Deep" {
		t.Errorf("shorten = %q", got)
	}
}

func TestEscalationRoutes(t *testing.T) {
	links := []ChainLink{
		{From: "user/alice", RoleName: "Admin"},
		{From: "user/alice", RoleName: "ReadOnly"},
		{From: "user/bob", RoleName: "Dev", Err: "denied"},
	}
	routes := EscalationRoutes(links)
	if len(routes["user/alice"]) != 2 {
		t.Errorf("routes = %v", routes)
	}
	if _, ok := routes["user/bob"]; ok {
		t.Error("bob's denied link should not be a route")
	}
}
