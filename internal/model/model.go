// Package model defines the core data types shared across git-scanner.
package model

import "time"

// Kind describes what a target is.
type Kind string

const (
	KindURL     Kind = "url"
	KindFile    Kind = "file"
	KindDir     Kind = "dir"
	KindGitRepo Kind = "git"
	KindArchive Kind = "archive"
)

// Target is a single unit of work: something that can be fetched and scanned.
type Target struct {
	Kind    Kind   `json:"kind"`
	Value   string `json:"value"`
	GitHost string `json:"git_host,omitempty"`
	Token   string `json:"token,omitempty"`
}

// Location describes where a finding was found.
type Location struct {
	Source string `json:"source,omitempty"` // repo URL / file / url
	File   string `json:"file,omitempty"`
	Line   int    `json:"line,omitempty"`
	Commit string `json:"commit,omitempty"`
	Branch string `json:"branch,omitempty"`
	Author string `json:"author,omitempty"`
	Email  string `json:"email,omitempty"`
	Date   string `json:"date,omitempty"`
}

// Finding is a single detected (and optionally verified) secret.
type Finding struct {
	RuleID      string            `json:"rule_id"`
	Description string            `json:"description"`
	Secret      string            `json:"secret"`
	Match       string            `json:"match,omitempty"`
	Entropy     float64           `json:"entropy,omitempty"`
	Location    Location          `json:"location"`
	Verified    bool              `json:"verified"`
	Checker     string            `json:"checker,omitempty"`
	Tags        []string          `json:"tags,omitempty"`
	Extra       map[string]string `json:"extra,omitempty"`

	Detected time.Time `json:"detected"`
}

// DedupKey returns a stable identity for de-duplication.
func (f Finding) DedupKey() string {
	return f.RuleID + "\x00" + f.Secret + "\x00" + f.Location.Source + "\x00" + f.Location.File
}
