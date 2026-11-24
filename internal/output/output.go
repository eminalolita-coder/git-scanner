// Package output persists findings to disk in jsonl, csv or txt format.
package output

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/eminalolita-coder/git-scanner/internal/model"
)

// Writer persists findings.
type Writer interface {
	Write(model.Finding) error
	Close() error
	Path() string
}

// New creates a writer for the given format in dir.
func New(dir, format string) (Writer, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	ts := time.Now().Format("20060102-150405")
	switch format {
	case "csv":
		return newCSV(filepath.Join(dir, "hits-"+ts+".csv"))
	case "txt", "text":
		return newTXT(filepath.Join(dir, "hits-"+ts+".txt"))
	default:
		return newJSONL(filepath.Join(dir, "hits-"+ts+".jsonl"))
	}
}

// NewStream returns a writer that prints findings to w in text form.
func NewStream(w io.Writer) Writer { return &streamWriter{w: w} }

type streamWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (s *streamWriter) Write(f model.Finding) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	loc := f.Location.File
	if f.Location.Line > 0 {
		loc += ":" + strconv.Itoa(f.Location.Line)
	}
	_, err := fmt.Fprintf(s.w, "%-26s %s  [%s]\n", f.RuleID, loc, f.Secret)
	return err
}
func (s *streamWriter) Close() error { return nil }
func (s *streamWriter) Path() string { return "<stdout>" }

type jsonlWriter struct {
	mu  sync.Mutex
	f   *os.File
	bw  *bufio.Writer
	enc *json.Encoder
}

func newJSONL(path string) (*jsonlWriter, error) {
	f, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	bw := bufio.NewWriterSize(f, 1<<20)
	return &jsonlWriter{f: f, bw: bw, enc: json.NewEncoder(bw)}, nil
}

func (w *jsonlWriter) Write(f model.Finding) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.enc.Encode(f)
}
func (w *jsonlWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.bw.Flush(); err != nil {
		_ = w.f.Close()
		return err
	}
	return w.f.Close()
}
func (w *jsonlWriter) Path() string { return w.f.Name() }

type csvWriter struct {
	mu sync.Mutex
	f  *os.File
	bw *bufio.Writer
	w  *csv.Writer
}

func newCSV(path string) (*csvWriter, error) {
	f, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	bw := bufio.NewWriterSize(f, 1<<20)
	cw := csv.NewWriter(bw)
	_ = cw.Write([]string{"rule_id", "description", "secret", "source", "file", "line", "commit", "verified", "checker", "tags", "detected"})
	return &csvWriter{f: f, bw: bw, w: cw}, nil
}

func (w *csvWriter) Write(f model.Finding) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.w.Write([]string{
		f.RuleID, f.Description, f.Secret, f.Location.Source, f.Location.File,
		strconv.Itoa(f.Location.Line), f.Location.Commit,
		strconv.FormatBool(f.Verified), f.Checker, join(f.Tags),
		f.Detected.Format(time.RFC3339),
	})
}
func (w *csvWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.w.Flush()
	if err := w.bw.Flush(); err != nil {
		_ = w.f.Close()
		return err
	}
	return w.f.Close()
}
func (w *csvWriter) Path() string { return w.f.Name() }

type txtWriter struct {
	mu sync.Mutex
	f  *os.File
	bw *bufio.Writer
}

func newTXT(path string) (*txtWriter, error) {
	f, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	return &txtWriter{f: f, bw: bufio.NewWriterSize(f, 1<<20)}, nil
}

func (w *txtWriter) Write(f model.Finding) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	loc := f.Location.File
	if f.Location.Line > 0 {
		loc += ":" + strconv.Itoa(f.Location.Line)
	}
	mark := " "
	if f.Verified {
		mark = "✓"
	}
	_, err := fmt.Fprintf(w.bw, "%s %-28s %s  [%s] %s\n", mark, f.RuleID, loc, f.Location.Source, f.Secret)
	return err
}
func (w *txtWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.bw.Flush(); err != nil {
		_ = w.f.Close()
		return err
	}
	return w.f.Close()
}
func (w *txtWriter) Path() string { return w.f.Name() }

func join(ss []string) string {
	out := ""
	for i, s := range ss {
		if i > 0 {
			out += ","
		}
		out += s
	}
	return out
}

// Dedup tracks seen finding keys.
type Dedup struct {
	mu   sync.Mutex
	seen map[string]struct{}
	max  int
}

// NewDedup creates an in-memory de-duplicator capped at max entries.
func NewDedup(max int) *Dedup {
	if max <= 0 {
		max = 500000
	}
	return &Dedup{seen: make(map[string]struct{}), max: max}
}

// First reports whether key is new (and records it).
func (d *Dedup) First(key string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, ok := d.seen[key]; ok {
		return false
	}
	if len(d.seen) >= d.max {
		// crude reset to avoid unbounded growth
		d.seen = make(map[string]struct{})
	}
	d.seen[key] = struct{}{}
	return true
}
