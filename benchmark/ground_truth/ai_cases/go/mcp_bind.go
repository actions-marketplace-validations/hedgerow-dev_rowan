// mcp-go SSE server bound on all interfaces with no auth middleware (tnt-go-ai-mcpbind-001, CWE-306).
package main

import (
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func main() {
	s := server.NewMCPServer("tools", "1.0.0")
	s.AddTool(mcp.NewTool("ping"), nil)
	sse := server.NewSSEServer(s)
	if err := sse.Start("0.0.0.0:8080"); err != nil {
		panic(err)
	}
}
