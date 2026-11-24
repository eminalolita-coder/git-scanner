// Package gitdump clones repositories and extracts their content (worktree,
// history, config, refs) for scanning.
package gitdump

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/plumbing/transport"

	"github.com/eminalolita-coder/git-scanner/internal/config"
	"github.com/eminalolita-coder/git-scanner/internal/model"
)

// Content is a blob of scannable text with its provenance.
type Content struct {
	Bytes   []byte
	File    string
	Commit  string
	Branch  string
	Author  string
	Email   string
	Date    string
	Deleted bool // present in the parent commit, removed by this one
}

// Handler consumes extracted content.
type Handler func(model.Target, Content)

// Options configures cloning and history walking.
type Options struct {
	CloneDir     string
	Depth        int
	MaxFileSize  int64
	ScanHistory  bool
	MaxHistory   int
	SkipBinary   bool
	ExcludedExts map[string]bool
	Auth         *git.CloneOptions
}

// Cloner clones repositories and streams their content to a handler.
type Cloner struct {
	cfg   config.GitScanner
	lim   config.ScanLimits
	Proxy *transport.ProxyOptions
}

// New builds a Cloner from configuration.
func New(cfg config.GitScanner, lim config.ScanLimits) *Cloner {
	return &Cloner{cfg: cfg, lim: lim}
}

// Dump clones url and streams every scannable blob to h.
func (c *Cloner) Dump(ctx context.Context, t model.Target, h Handler) error {
	dir, err := os.MkdirTemp("", "git-scanner-clone-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)

	opts := &git.CloneOptions{URL: t.Value, Tags: git.AllTags}
	if c.Proxy != nil {
		opts.ProxyOptions = *c.Proxy
	}
	if t.Token != "" {
		opts.Auth = tokenAuth(t.GitHost, t.Token)
	}
	if c.cfg.MaxHistoryDepth > 0 {
		opts.Depth = c.cfg.MaxHistoryDepth
	}

	repo, err := git.PlainCloneContext(ctx, dir, false, opts)
	if err != nil && !errors.Is(err, git.ErrRepositoryAlreadyExists) {
		return fmt.Errorf("clone %s: %w", t.Value, err)
	}

	if err := c.scanWorktree(t, dir, h); err != nil {
		return err
	}
	if c.cfg.ScanHistory {
		c.scanHistory(t, repo, h)
	}
	return nil
}

func (c *Cloner) scanWorktree(t model.Target, dir string, h Handler) error {
	return filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if d.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if excluded(path) {
			return nil
		}
		info, err := d.Info()
		if err != nil || info.Size() > c.lim.MaxFileSizeBytes {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		if IsBinary(data) && c.cfg.SkipBinaryFiles {
			return nil
		}
		rel, _ := filepath.Rel(dir, path)
		h(t, Content{Bytes: data, File: filepath.ToSlash(rel)})
		return nil
	})
}

func (c *Cloner) scanHistory(t model.Target, repo *git.Repository, h Handler) {
	// walk every ref (all branches and tags), oldest first
	iter, err := repo.Log(&git.LogOptions{Order: git.LogOrderCommitterTime, All: true})
	if err != nil {
		return
	}
	count := 0
	_ = iter.ForEach(func(commit *object.Commit) error {
		if c.cfg.MaxHistoryDepth > 0 && count >= c.cfg.MaxHistoryDepth {
			return io.EOF
		}
		count++
		files, err := commit.Files()
		if err != nil {
			return nil
		}
		_ = files.ForEach(func(f *object.File) error {
			if excluded(f.Name) {
				return nil
			}
			prov := Content{
				Commit: commit.Hash.String(),
				Author: commit.Author.Name,
				Email:  commit.Author.Email,
				Date:   commit.Author.When.Format(time.RFC3339),
			}
			content, err := f.Contents()
			if err == nil {
				if int64(len(content)) > c.lim.MaxBlobSizeBytes {
					return nil
				}
				prov.Bytes = []byte(content)
				prov.File = f.Name
				h(t, prov)
				return nil
			}
			// the file was deleted by this commit: recover it from the parent
			if c.lim.ScanGitNotes || true {
				if pc, perr := c.fileFromParent(commit, f.Name); perr == nil && pc != nil {
					prov.Bytes = pc
					prov.File = f.Name
					prov.Deleted = true
					h(t, prov)
				}
			}
			return nil
		})
		return nil
	})

	// stash entries are not reachable from any branch
	if c.lim.ScanStash {
		c.scanStash(t, repo, h)
	}
}

// fileFromParent returns the content of name in the first parent commit.
func (c *Cloner) fileFromParent(commit *object.Commit, name string) ([]byte, error) {
	if commit.NumParents() == 0 {
		return nil, nil
	}
	parent, err := commit.Parent(0)
	if err != nil {
		return nil, err
	}
	f, err := parent.File(name)
	if err != nil {
		return nil, err
	}
	if f.Size > c.lim.MaxBlobSizeBytes {
		return nil, nil
	}
	content, err := f.Contents()
	if err != nil {
		return nil, err
	}
	return []byte(content), nil
}

// scanStash walks refs/stash commits and scans their content.
func (c *Cloner) scanStash(t model.Target, repo *git.Repository, h Handler) {
	ref, err := repo.Reference("refs/stash", true)
	if err != nil || ref == nil {
		return
	}
	commit, err := repo.CommitObject(ref.Hash())
	if err != nil {
		return
	}
	files, err := commit.Files()
	if err != nil {
		return
	}
	_ = files.ForEach(func(f *object.File) error {
		if excluded(f.Name) {
			return nil
		}
		content, err := f.Contents()
		if err != nil || int64(len(content)) > c.lim.MaxBlobSizeBytes {
			return nil
		}
		h(t, Content{
			Bytes:  []byte(content),
			File:   "stash:" + f.Name,
			Commit: commit.Hash.String(),
			Author: commit.Author.Name,
			Email:  commit.Author.Email,
			Date:   commit.Author.When.Format(time.RFC3339),
		})
		return nil
	})
}

var excludedExt = map[string]bool{
	".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".webp": true,
	".ico": true, ".woff": true, ".woff2": true, ".ttf": true, ".eot": true,
	".mp3": true, ".mp4": true, ".pdf": true, ".zip": true, ".gz": true,
	".exe": true, ".dll": true, ".so": true, ".dylib": true, ".class": true,
	".min.js": false,
}

func excluded(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	return excludedExt[ext]
}

// IsBinary is a local copy to avoid an import cycle.
func IsBinary(b []byte) bool {
	probe := b
	if len(probe) > 512 {
		probe = probe[:512]
	}
	for _, c := range probe {
		if c == 0 {
			return true
		}
	}
	return false
}

// BranchRefs returns all branch references of a repo.
func BranchRefs(repo *git.Repository) ([]string, error) {
	iter, err := repo.Branches()
	if err != nil {
		return nil, err
	}
	var out []string
	_ = iter.ForEach(func(r *plumbing.Reference) error {
		out = append(out, r.Name().Short())
		return nil
	})
	return out, nil
}
