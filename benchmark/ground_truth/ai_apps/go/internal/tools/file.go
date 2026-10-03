package tools

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
)

const notesRoot = "/var/lib/oracle-go/notes"

// G-02 (tnt-go-ai-mcptool-path-001): the MCP tool argument "path" is joined
// onto the notes root with no containment check.
func ReadFile(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	p := request.GetString("path", "")
	data, err := os.ReadFile(filepath.Join(notesRoot, p))
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	return mcp.NewToolResultText(string(data)), nil
}

// GD-01: mirrors the mcp-filesystem-server validatePath idiom -- resolves
// to an absolute path and rejects anything that escapes notesRoot.
func ReadFileSafe(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	p := request.GetString("path", "")
	candidate := filepath.Join(notesRoot, p)
	abs, err := filepath.Abs(candidate)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	allowedRoot, err := filepath.Abs(notesRoot)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	if !strings.HasPrefix(abs, allowedRoot) {
		return mcp.NewToolResultError("path escapes notes root"), nil
	}
	data, err := os.ReadFile(abs)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	return mcp.NewToolResultText(string(data)), nil
}
