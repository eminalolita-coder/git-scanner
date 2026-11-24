// Package analyzer provides content pre-processing: binary detection, string
// extraction and decoding of common obfuscations (base64, hex, URL-encoding).
package analyzer

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"net/url"
	"regexp"
	"strings"
)

// Options controls the deobfuscation budget.
type Options struct {
	MaxBase64Candidates int
	MaxHexCandidates    int
	MaxDecodeBytes      int
	MinStringLength     int
}

// DefaultOptions returns conservative limits.
func DefaultOptions() Options {
	return Options{MaxBase64Candidates: 50, MaxHexCandidates: 20, MaxDecodeBytes: 1 << 20, MinStringLength: 10}
}

var (
	reBase64Run = regexp.MustCompile(`[A-Za-z0-9+/\-_]{16,}={0,2}`)
	reHex       = regexp.MustCompile(`\b[0-9a-fA-F]{32,}\b`)
	rePctEnc    = regexp.MustCompile(`%[0-9a-fA-F]{2}`)
)

// IsBinary reports whether content looks non-textual.
func IsBinary(content []byte) bool {
	probe := content
	if len(probe) > 512 {
		probe = probe[:512]
	}
	return bytes.IndexByte(probe, 0) >= 0
}

func mostlyText(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	printable := 0
	for _, c := range b {
		if (c >= 32 && c < 127) || c == '\n' || c == '\r' || c == '\t' {
			printable++
		}
	}
	return float64(printable)/float64(len(b)) >= 0.9
}

// tryBase64 attempts to decode a base64 run, trying shifted offsets and both
// standard and URL alphabets. This handles runs polluted by surrounding URL
// characters (e.g. "https://" leaving leading slashes).
func tryBase64(run string) []byte {
	encs := []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding}
	for start := 0; start < 4 && start < len(run)-15; start++ {
		s := run[start:]
		for trim := 0; trim < 4; trim++ {
			n := len(s) - trim
			if n < 16 {
				break
			}
			cand := s[:n]
			if len(cand)%4 != 0 {
				continue
			}
			for _, enc := range encs {
				if dec, err := enc.DecodeString(cand); err == nil && len(dec) >= 8 && mostlyText(dec) {
					return dec
				}
			}
		}
	}
	return nil
}

// ExtractStrings returns printable ASCII runs of at least minLen, joined by
// newlines, for scanning a binary as text.
func ExtractStrings(content []byte, minLen int) []byte {
	if minLen <= 0 {
		minLen = 6
	}
	var out bytes.Buffer
	run := make([]byte, 0, 64)
	flush := func() {
		if len(run) >= minLen {
			out.Write(run)
			out.WriteByte('\n')
		}
		run = run[:0]
	}
	for _, b := range content {
		if b >= 32 && b < 127 {
			run = append(run, b)
		} else {
			flush()
		}
	}
	flush()
	return out.Bytes()
}

// Deobfuscate returns extra byte blobs decoded from content. Each blob is
// itself meant to be scanned.
func Deobfuscate(content []byte, o Options) [][]byte {
	var out [][]byte
	seen := make(map[string]struct{})
	add := func(b []byte) {
		if len(b) == 0 || len(b) > o.MaxDecodeBytes {
			return
		}
		k := string(b)
		if _, ok := seen[k]; ok {
			return
		}
		seen[k] = struct{}{}
		out = append(out, b)
	}

	// base64 candidates
	for i, run := range reBase64Run.FindAll(content, o.MaxBase64Candidates) {
		if i >= o.MaxBase64Candidates {
			break
		}
		if dec := tryBase64(string(run)); dec != nil {
			add(dec)
		}
	}
	// hex candidates
	for i, m := range reHex.FindAll(content, o.MaxHexCandidates) {
		if i >= o.MaxHexCandidates {
			break
		}
		if dec, err := hex.DecodeString(string(m)); err == nil && len(dec) >= 8 {
			add(dec)
		}
	}
	// url-encoded
	if rePctEnc.Match(content) {
		if dec, err := url.QueryUnescape(string(content)); err == nil && dec != string(content) {
			add([]byte(dec))
		}
	}
	// strip escapes / unicode noise
	if bytes.Contains(content, []byte(`\x`)) || bytes.Contains(content, []byte(`\u`)) {
		add([]byte(unescape(content)))
	}
	return out
}

var reHexEsc = regexp.MustCompile(`\\x([0-9a-fA-F]{2})`)
var reUniEsc = regexp.MustCompile(`\\u([0-9a-fA-F]{4})`)

func unescape(b []byte) string {
	s := string(b)
	s = reHexEsc.ReplaceAllStringFunc(s, func(m string) string {
		v, _ := hex.DecodeString(m[2:])
		return string(v)
	})
	s = reUniEsc.ReplaceAllStringFunc(s, func(m string) string {
		var r rune
		for _, c := range m[2:] {
			r <<= 4
			switch {
			case c >= '0' && c <= '9':
				r += c - '0'
			case c >= 'a' && c <= 'f':
				r += c - 'a' + 10
			case c >= 'A' && c <= 'F':
				r += c - 'A' + 10
			}
		}
		return string(r)
	})
	return strings.ReplaceAll(s, `\/`, `/`)
}
