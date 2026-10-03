package tools

import (
	"context"
	"os/exec"

	"github.com/mark3labs/mcp-go/mcp"
)

// G-01 (tnt-go-ai-mcptool-exec-001): the MCP tool argument "command" is
// handed straight to a shell with no allowlist or validation.
func RunCommand(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	command, err := request.RequireString("command")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	cmd := exec.CommandContext(ctx, "bash", "-c", command)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	return mcp.NewToolResultText(string(out)), nil
}
