// Package logger provides a tiny leveled logger with optional color.
package logger

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

type Level int

const (
	LevelDebug Level = iota
	LevelInfo
	LevelWarn
	LevelError
)

var (
	mu    sync.Mutex
	out   io.Writer = os.Stderr
	level           = LevelInfo
	color           = true
)

// SetLevel adjusts the global verbosity.
func SetLevel(l Level) { mu.Lock(); level = l; mu.Unlock() }

// SetOutput redirects log output (useful for tests / UI).
func SetOutput(w io.Writer) { mu.Lock(); out = w; mu.Unlock() }

// SetColor toggles ANSI colors.
func SetColor(v bool) { mu.Lock(); color = v; mu.Unlock() }

func tag(l Level) string {
	switch l {
	case LevelDebug:
		return "DEBUG"
	case LevelInfo:
		return "INFO "
	case LevelWarn:
		return "WARN "
	default:
		return "ERROR"
	}
}

func colorize(l Level, s string) string {
	if !color {
		return s
	}
	var c string
	switch l {
	case LevelDebug:
		c = "\033[36m"
	case LevelInfo:
		c = "\033[32m"
	case LevelWarn:
		c = "\033[33m"
	default:
		c = "\033[31m"
	}
	return c + s + "\033[0m"
}

func logf(l Level, format string, args ...any) {
	mu.Lock()
	defer mu.Unlock()
	if l < level {
		return
	}
	ts := time.Now().Format("15:04:05")
	msg := fmt.Sprintf(format, args...)
	fmt.Fprintf(out, "%s %s %s\n", ts, colorize(l, tag(l)), msg)
}

func Debugf(f string, a ...any) { logf(LevelDebug, f, a...) }
func Infof(f string, a ...any)  { logf(LevelInfo, f, a...) }
func Warnf(f string, a ...any)  { logf(LevelWarn, f, a...) }
func Errorf(f string, a ...any) { logf(LevelError, f, a...) }

// ParseLevel maps a string to a Level, defaulting to Info.
func ParseLevel(s string) Level {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return LevelDebug
	case "warn", "warning":
		return LevelWarn
	case "error":
		return LevelError
	default:
		return LevelInfo
	}
}
