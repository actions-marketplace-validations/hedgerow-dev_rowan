// Package shell centralizes process execution for internal/tools handlers
// that need to shell out, mirroring geropl/git-mcp-go's shell/operations.go
// split (BACKLOG.md JG-09 survey: Go MCP handlers are 0 to 1 hop deep).
package shell

import (
	"context"
	"os/exec"
)

// Run is the sink for G-11: it executes args with no validation. Its only
// caller today is internal/tools/git.go:GitStatus, one hop away.
func Run(ctx context.Context, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", args...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}
