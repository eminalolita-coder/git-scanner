package aws

import "testing"

// encoding/xml does not match a field whose tag equals the ROOT element name:
// tagging the wrapper with the root name yields a silent zero value. This test
// pins the correct shape.
func TestParseCallerIdentity(t *testing.T) {
	body := []byte(`<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <GetCallerIdentityResult>
    <Arn>arn:aws:iam::123456789012:user/alice</Arn>
    <UserId>AIDAEXAMPLE</UserId>
    <Account>123456789012</Account>
  </GetCallerIdentityResult>
  <ResponseMetadata><RequestId>x</RequestId></ResponseMetadata>
</GetCallerIdentityResponse>`)

	id := parseCallerIdentity(body)
	if id.Account != "123456789012" {
		t.Errorf("Account = %q", id.Account)
	}
	if id.ARN != "arn:aws:iam::123456789012:user/alice" {
		t.Errorf("ARN = %q", id.ARN)
	}
	if id.UserID != "AIDAEXAMPLE" {
		t.Errorf("UserID = %q", id.UserID)
	}
}
