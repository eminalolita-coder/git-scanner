// Command git-scanner is a fast secret scanner for git repositories, URLs,
// files and archives.
package main

import (
	"fmt"
	"os"

	"github.com/eminalolita-coder/git-scanner/internal/cli"
)

// version is injected at build time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	if err := cli.Execute(version); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
