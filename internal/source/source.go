// Package source turns user input (files, dirs, URLs, repos) into targets.
package source

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"

	"github.com/eminalolita-coder/git-scanner/internal/gitdump"
	"github.com/eminalolita-coder/git-scanner/internal/model"
)

// Classify turns a raw string into a Target, guessing its kind.
func Classify(value string) model.Target {
	v := strings.TrimSpace(value)
	t := model.Target{Value: v}
	switch {
	case strings.HasPrefix(v, "git@") || strings.HasSuffix(v, ".git") || strings.Contains(v, "://") && isGitHost(v):
		t.Kind = model.KindGitRepo
		t.GitHost = gitdump.HostFromURL(v)
	case strings.HasPrefix(v, "http://"), strings.HasPrefix(v, "https://"):
		t.Kind = model.KindURL
	default:
		if fi, err := os.Stat(v); err == nil {
			if fi.IsDir() {
				t.Kind = model.KindDir
			} else {
				t.Kind = model.KindFile
			}
		} else {
			t.Kind = model.KindURL
		}
	}
	return t
}

func isGitHost(u string) bool {
	for _, h := range []string{"github.com", "gitlab", "bitbucket", "gitea", "gogs", "dev.azure.com", "codecommit", "gerrit", "git."} {
		if strings.Contains(u, h) {
			return true
		}
	}
	return false
}

// FromListFile reads one target per line, ignoring blanks and '#' comments.
func FromListFile(path string) ([]model.Target, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []model.Target
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// "domain ip" form: keep the domain, remember the ip
		if fields := strings.Fields(line); len(fields) == 2 {
			line = fields[0]
		}
		out = append(out, Classify(line))
	}
	return out, sc.Err()
}

// Expand turns args (files → lines, dirs, urls) into a flat target list.
func Expand(args []string) ([]model.Target, error) {
	var out []model.Target
	for _, a := range args {
		t := Classify(a)
		if t.Kind == model.KindFile && filepath.Ext(a) == ".txt" {
			ts, err := FromListFile(a)
			if err != nil {
				return nil, err
			}
			out = append(out, ts...)
			continue
		}
		out = append(out, t)
	}
	return out, nil
}
