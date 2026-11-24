package patterns

import (
	"sync"
	"testing"
)

func TestFreezeParallelScan(t *testing.T) {
	e := NewEngine(10)
	if err := e.AddAll(Builtin()); err != nil {
		t.Fatal(err)
	}
	e.Freeze()
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if len(e.ScanString("GITHUB_TOKEN=ghp_012345678901234567890123456789012345")) == 0 {
				t.Error("no match after freeze")
			}
		}()
	}
	wg.Wait()
}

func TestEngineScan(t *testing.T) {
	e := NewEngine(10)
	if err := e.AddAll(Builtin()); err != nil {
		t.Fatalf("AddAll: %v", err)
	}
	content := []byte(`
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
GITHUB_TOKEN=ghp_012345678901234567890123456789012345
STRIPE=sk_test_0123456789012345678901234
DATABASE_URL=postgres://admin:s3cr3t@db.example.com:5432/prod
`)
	matches := e.Scan(content)
	want := map[string]bool{
		"aws-access-key-boundary": false,
		"github-pat":              false,
		"stripe-secret-key":       false,
		"postgres-uri":            false,
	}
	for _, m := range matches {
		if _, ok := want[m.Pattern.ID]; ok {
			want[m.Pattern.ID] = true
		}
	}
	for id, seen := range want {
		if !seen {
			t.Errorf("rule %q did not match", id)
		}
	}
}

func TestEntropy(t *testing.T) {
	if Shannon("aaaaaaaa") >= 1.0 {
		t.Error("expected low entropy for repeated char")
	}
	if Shannon("aB3$xZ9!") < 2.5 {
		t.Error("expected higher entropy for mixed string")
	}
}

func TestAllowlist(t *testing.T) {
	e := NewEngine(10)
	_ = e.Add(Pattern{
		ID:          "generic",
		Regex:       `pass\s*=\s*(\S+)`,
		SecretGroup: 1,
		Allowlist:   []string{`^false$`},
	})
	if got := e.ScanString("pass=false"); len(got) != 0 {
		t.Errorf("allowlisted value still matched: %+v", got)
	}
	if got := e.ScanString("pass=hunter2"); len(got) != 1 {
		t.Errorf("expected 1 match, got %d", len(got))
	}
}
