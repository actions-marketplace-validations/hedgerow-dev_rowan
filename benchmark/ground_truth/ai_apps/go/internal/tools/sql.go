package tools

import (
	"context"
	"database/sql"

	"github.com/mark3labs/mcp-go/mcp"
)

type sqlTools struct {
	db *sql.DB
}

// G-03 (tnt-go-ai-mcptool-sql-001): the MCP tool argument "query" is
// string-concatenated straight into a SELECT.
func (t *sqlTools) SearchTickets(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	q := request.GetString("query", "")
	rows, err := t.db.QueryContext(ctx, "SELECT id, subject FROM tickets WHERE subject LIKE '%"+q+"%'")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	defer rows.Close()
	return mcp.NewToolResultText("ok"), nil
}

// GD-02: same shape as SearchTickets but the argument is bound as a
// parameter, never concatenated into the query text.
func (t *sqlTools) SearchTicketsSafe(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	id := request.GetString("id", "")
	rows, err := t.db.QueryContext(ctx, "SELECT id, subject FROM tickets WHERE id = $1", id)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	defer rows.Close()
	return mcp.NewToolResultText("ok"), nil
}
