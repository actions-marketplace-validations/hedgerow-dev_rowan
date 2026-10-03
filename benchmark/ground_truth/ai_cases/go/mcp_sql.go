// mcp-go tool argument concatenated into SQL text (tnt-go-ai-mcptool-sql-001, CWE-89).
package main

import (
	"context"
	"database/sql"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

var db *sql.DB

func lookupHandler(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	name, err := req.RequireString("name")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	rows, err := db.QueryContext(ctx, "SELECT id, email FROM users WHERE name = '"+name+"'")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	defer rows.Close()
	return mcp.NewToolResultText("ok"), nil
}

func main() {
	s := server.NewMCPServer("users", "1.0.0")
	s.AddTool(mcp.NewTool("lookup", mcp.WithString("name", mcp.Required())), lookupHandler)
	server.ServeStdio(s)
}
