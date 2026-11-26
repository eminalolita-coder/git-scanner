package checkers

import "testing"

func TestSplitSESPair(t *testing.T) {
	const pass = "Bf3xK9mQ2rT7vL1nW8sY4pZ6cH0jD5gA2eR9uI3oX7k="
	cases := []struct {
		name, in, user, password string
	}{
		{"colon", "AKIAIOSFODNN7EXAMPLE:" + pass, "AKIAIOSFODNN7EXAMPLE", pass},
		{"equals", "AKIAIOSFODNN7EXAMPLE=" + pass, "AKIAIOSFODNN7EXAMPLE", pass},
		{"quoted", `"AKIAIOSFODNN7EXAMPLE", "` + pass + `"`, "AKIAIOSFODNN7EXAMPLE", pass},
		{"temporary", "ASIAIOSFODNN7EXAMPLE:" + pass, "ASIAIOSFODNN7EXAMPLE", pass},
		{"username only", "AKIAIOSFODNN7EXAMPLE", "", ""},
		{"not a key", "Bf3xK9mQ2rT7vL1nW8sY4pZ6cH0jD5gA2eR9uI3oX7k=", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			user, pass := SplitSESPair(tc.in)
			if user != tc.user || pass != tc.password {
				t.Errorf("SplitSESPair(%q) = (%q, %q), want (%q, %q)", tc.in, user, pass, tc.user, tc.password)
			}
		})
	}
}

func TestSESCheckerMatch(t *testing.T) {
	c := &sesSMTPChecker{}
	if !c.Match("aws-ses-smtp-credential", nil) {
		t.Error("pair rule must match")
	}
	if !c.Match("aws-ses-smtp-username", nil) {
		t.Error("username rule must match")
	}
	for _, id := range []string{"aws-ses-smtp-endpoint", "aws-ses-smtp-password", "smtp-cred"} {
		if c.Match(id, nil) {
			t.Errorf("%s is an indicator, not a credential", id)
		}
	}
}
