package cli

import "testing"

func TestNormalizeProxy(t *testing.T) {
	cases := []struct{ in, want string }{
		{"http://u:p@host:8080", "http://u:p@host:8080"},
		{"socks5://u:p@host:1080", "socks5://u:p@host:1080"},
		{"dc.flashproxy.io:777:user-country-US:pass", "http://user-country-US:pass@dc.flashproxy.io:777"},
		{"host:3128", "http://host:3128"},
		{"  dc.flashproxy.io:777:u:p  ", "http://u:p@dc.flashproxy.io:777"},
	}
	for _, tc := range cases {
		if got := normalizeProxy(tc.in); got != tc.want {
			t.Errorf("normalizeProxy(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
