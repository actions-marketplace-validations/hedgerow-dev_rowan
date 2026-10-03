// mcp-go tool argument used as a filesystem path with no allowlist check (tnt-go-ai-mcptool-path-001, CWE-22).
package main

import (
	"context"
	"os"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func readHandler(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	path, err := req.RequireString("path")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	return mcp.NewToolResultText(string(data)), nil
}

func main() {
	s := server.NewMCPServer("files", "1.0.0")
	s.AddTool(mcp.NewTool("read_file", mcp.WithString("path", mcp.Required())), readHandler)
	server.ServeStdio(s)
}
