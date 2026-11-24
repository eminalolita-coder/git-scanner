// Package webhook delivers notifications to Telegram and Discord.
package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/eminalolita-coder/git-scanner/internal/config"
	"github.com/eminalolita-coder/git-scanner/internal/logger"
)

// Notifier sends messages.
type Notifier interface {
	Send(ctx context.Context, msg string) error
	Name() string
}

// Telegram posts to a bot chat.
type Telegram struct {
	Token  string
	ChatID string
}

func (t Telegram) Name() string { return "telegram" }

func (t Telegram) Send(ctx context.Context, msg string) error {
	body, _ := json.Marshal(map[string]string{"chat_id": t.ChatID, "text": msg, "parse_mode": "HTML"})
	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", t.Token)
	return post(ctx, url, body)
}

// Discord posts to a webhook URL.
type Discord struct{ URL string }

func (d Discord) Name() string { return "discord" }

func (d Discord) Send(ctx context.Context, msg string) error {
	if len(msg) > 1900 {
		msg = msg[:1900] + "…"
	}
	body, _ := json.Marshal(map[string]string{"content": msg})
	return post(ctx, d.URL, body)
}

func post(ctx context.Context, url string, body []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("%s: status %d", url, resp.StatusCode)
	}
	return nil
}

// Dispatcher fans a message out to every configured notifier concurrently.
type Dispatcher struct {
	notifiers []Notifier
	mu        sync.Mutex
	minDelay  time.Duration
	last      time.Time
}

// New builds a dispatcher from config. Returns nil if nothing is enabled.
func New(cfg config.Webhooks) *Dispatcher {
	d := &Dispatcher{minDelay: 1200 * time.Millisecond}
	if cfg.Telegram.Enabled && cfg.Telegram.BotToken != "" && cfg.Telegram.ChatID != "" {
		d.notifiers = append(d.notifiers, Telegram{Token: cfg.Telegram.BotToken, ChatID: cfg.Telegram.ChatID})
	}
	if cfg.Discord.Enabled && cfg.Discord.WebhookURL != "" {
		d.notifiers = append(d.notifiers, Discord{URL: cfg.Discord.WebhookURL})
	}
	if !cfg.Enabled || len(d.notifiers) == 0 {
		return d
	}
	return d
}

// Enabled reports whether there is at least one notifier.
func (d *Dispatcher) Enabled() bool { return d != nil && len(d.notifiers) > 0 }

// Send delivers msg to all notifiers, throttled.
func (d *Dispatcher) Send(ctx context.Context, msg string) {
	if !d.Enabled() {
		return
	}
	d.mu.Lock()
	wait := d.minDelay - time.Since(d.last)
	d.last = time.Now()
	d.mu.Unlock()
	if wait > 0 {
		select {
		case <-time.After(wait):
		case <-ctx.Done():
			return
		}
	}
	for _, n := range d.notifiers {
		if err := n.Send(ctx, msg); err != nil {
			logger.Debugf("webhook %s: %v", n.Name(), err)
		}
	}
}
