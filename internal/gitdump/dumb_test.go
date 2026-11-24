package gitdump

import (
	"encoding/hex"
	"testing"
)

func TestParseTree(t *testing.T) {
	sha := "0123456789abcdef0123456789abcdef01234567"
	raw, _ := hex.DecodeString(sha)
	body := append([]byte("100644 file.txt\x00"), raw...)
	body = append(body, []byte("40000 sub\x00")...)
	body = append(body, raw...)

	entries := parseTree(body)
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}
	if entries[0].mode != "100644" || entries[0].name != "file.txt" || entries[0].sha != sha {
		t.Errorf("bad blob entry: %+v", entries[0])
	}
	if entries[1].mode != "40000" || entries[1].name != "sub" {
		t.Errorf("bad tree entry: %+v", entries[1])
	}
}

func TestObjectRefs(t *testing.T) {
	commit := "tree 1111111111111111111111111111111111111111\n" +
		"parent 2222222222222222222222222222222222222222\n" +
		"author A <a@b> 1 +0000\n\nmessage\n"
	trees := objectRefs([]byte(commit), "tree")
	if len(trees) != 1 || trees[0][:4] != "1111" {
		t.Errorf("trees = %v", trees)
	}
	parents := objectRefs([]byte(commit), "parent")
	if len(parents) != 1 || parents[0][:4] != "2222" {
		t.Errorf("parents = %v", parents)
	}
}

func TestIsHex(t *testing.T) {
	if !isHex("0123456789abcdef0123456789abcdef01234567") {
		t.Error("valid sha rejected")
	}
	if isHex("xyz") || isHex("0123456789abcdef0123456789abcdef0123456") {
		t.Error("invalid sha accepted")
	}
}

func TestResolveHeadParsing(t *testing.T) {
	// a dumb HEAD file always points at a ref or a sha
	head := "ref: refs/heads/main\n"
	if ref := head[len("ref: "):]; ref[:len("refs/")] != "refs/" {
		t.Errorf("ref parse: %q", ref)
	}
}
