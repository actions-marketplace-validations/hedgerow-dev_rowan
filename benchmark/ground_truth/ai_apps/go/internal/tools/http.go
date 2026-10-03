package tools

import (
	"context"
	"io"
	"net/http"

	"github.com/mark3labs/mcp-go/mcp"
)

// G-04 (tnt-go-ai-mcptool-ssrf-001): the MCP tool argument "url" is fetched
// server-side with no allowlist or scheme check.
func FetchURL(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	u := request.GetString("url", "")
	resp, err := http.Get(u)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	return mcp.NewToolResultText(string(body)), nil
}
