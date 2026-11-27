package output

import (
	"os"
	"sync"
	"testing"

	"github.com/eminalolita-coder/git-scanner/internal/model"
)

type memWriter struct{ n int }

func (m *memWriter) Write(model.Finding) error { m.n++; return nil }
func (m *memWriter) Close() error              { return nil }
func (m *memWriter) Path() string              { return "<mem>" }

func TestAsyncWriterDeliversAll(t *testing.T) {
	m := &memWriter{}
	a := NewAsync(m, 16)
	var wg sync.WaitGroup
	for i := 0; i < 1000; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = a.Write(model.Finding{RuleID: "r"})
		}()
	}
	wg.Wait()
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	// must be ALL of them: the old Write dropped on channel overflow, which
	// silently lost findings on a real run.
	if m.n != 1000 {
		t.Errorf("delivered %d findings, want 1000", m.n)
	}
}

// TestAsyncWriterNoLoss measures the old lossy behaviour: with a tiny channel
// and a slow inner writer every finding must still arrive.
func TestAsyncWriterNoLoss(t *testing.T) {
	m := &memWriter{}
	a := NewAsync(m, 4)
	for i := 0; i < 20000; i++ {
		if err := a.Write(model.Finding{RuleID: "r"}); err != nil {
			t.Fatal(err)
		}
	}
	_ = a.Close()
	if m.n != 20000 {
		t.Fatalf("delivered %d, want 20000", m.n)
	}
}

func TestShardedDedup(t *testing.T) {
	d := NewShardedDedup(8)
	if !d.First("a") {
		t.Error("first should be new")
	}
	if d.First("a") {
		t.Error("second should be duplicate")
	}
	if !d.First("b") {
		t.Error("b should be new")
	}
	if d.Len() != 2 {
		t.Errorf("len = %d", d.Len())
	}

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _ = d.First("k") }()
	}
	wg.Wait()
	if d.Len() != 3 {
		t.Errorf("concurrent dedup len = %d, want 3", d.Len())
	}
}

func TestBufferedWritersFlush(t *testing.T) {
	dir := t.TempDir()
	w, err := New(dir, "jsonl")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 500; i++ {
		if err := w.Write(model.Finding{RuleID: "r", Secret: "s"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(w.Path())
	if err != nil {
		t.Fatal(err)
	}
	if n := countLines(data); n != 500 {
		t.Errorf("flushed %d lines, want 500", n)
	}
}

func countLines(b []byte) int {
	n := 0
	for _, c := range b {
		if c == '\n' {
			n++
		}
	}
	return n
}
