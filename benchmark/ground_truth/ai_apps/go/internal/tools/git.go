package tools

import (
	"context"

	"github.com/mark3labs/mcp-go/mcp"

	"github.com/hedgerow/oracle-go/internal/shell"
)

// G-11 (1-hop cross-file, JG-13 acceptance target): the MCP tool argument
// "repo_path" is passed to shell.Run in a sibling package, which builds the
// exec.Command. Expected MISS until JG-13 cross-file lands for Go.
func GitStatus(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	repoPath := request.GetString("repo_path", ".")
	out, err := shell.Run(ctx, "-C", repoPath, "status")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	return mcp.NewToolResultText(out), nil
}
