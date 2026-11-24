package analyzer

import (
	"strings"
	"testing"
)

func TestDeobfuscateBase64Cred(t *testing.T) {
	in := []byte("url = https://eC1hY2Nlc3MtdG9rZW46Z2hzX3A1YjNUak5YMXJyQWtrdkMwOU5xa3JoMGRVbjU4NDJROW5mQg@github.com/x/y.git\n")
	out := Deobfuscate(in, DefaultOptions())
	t.Logf("blobs=%d", len(out))
	found := false
	for _, b := range out {
		t.Logf("  %q", string(b))
		if strings.Contains(string(b), "ghs_") {
			found = true
		}
	}
	if !found {
		t.Fatal("no decoded blob containing ghs_")
	}
}
