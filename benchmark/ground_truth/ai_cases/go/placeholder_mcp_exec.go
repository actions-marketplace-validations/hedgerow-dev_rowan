// mcp-go tool argument executed through a shell (tnt-go-ai-mcptool-exec-001, CWE-78).
package main

import (
	"context"
	"os/exec"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func runHandler(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	cmd := req.GetString("cmd", "")
	out, err := exec.Command("sh", "-c", cmd).CombinedOutput()
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	return mcp.NewToolResultText(string(out)), nil
}

func main() {
	s := server.NewMCPServer("shell", "1.0.0")
	s.AddTool(mcp.NewTool("run", mcp.WithString("cmd", mcp.Required())), runHandler)
	server.ServeStdio(s)
}
