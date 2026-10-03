// Official go-sdk typed tool argument used as an outbound request URL (tnt-go-ai-mcptool-ssrf-001, CWE-918).
package main

import (
	"context"
	"io"
	"net/http"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type FetchArgs struct {
	URL string `json:"url"`
}

func fetch(ctx context.Context, req *mcp.CallToolRequest, args FetchArgs) (*mcp.CallToolResult, any, error) {
	resp, err := http.Get(args.URL)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return &mcp.CallToolResult{}, string(body), nil
}

func main() {
	s := mcp.NewServer(&mcp.Implementation{Name: "fetch"}, nil)
	mcp.AddTool(s, &mcp.Tool{Name: "fetch"}, fetch)
}
