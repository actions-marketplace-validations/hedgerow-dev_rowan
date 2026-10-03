package tools

import (
	"database/sql"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	openai "github.com/sashabaranov/go-openai"
)

// RegisterAll wires every handler in this package onto the MCP server. Kept
// as one function, in one file, so the tool inventory for the ground truth
// is easy to audit against ground_truth.yaml.
func RegisterAll(s *server.MCPServer, db *sql.DB) {
	client := openai.NewClient("sk-oracle-go-placeholder")
	sqlT := &sqlTools{db: db}
	llmT := &llmTools{client: client, db: db}
	assistantT := &assistantTools{client: client}

	s.AddTool(mcp.NewTool("run_command"), RunCommand)
	s.AddTool(mcp.NewTool("read_file"), ReadFile)
	s.AddTool(mcp.NewTool("read_file_safe"), ReadFileSafe)
	s.AddTool(mcp.NewTool("search_tickets"), sqlT.SearchTickets)
	s.AddTool(mcp.NewTool("search_tickets_safe"), sqlT.SearchTicketsSafe)
	s.AddTool(mcp.NewTool("fetch_url"), FetchURL)
	s.AddTool(mcp.NewTool("summarize"), llmT.Summarize)
	s.AddTool(mcp.NewTool("smart_search"), llmT.SmartSearch)
	s.AddTool(mcp.NewTool("fact_check"), assistantT.FactCheck)
	s.AddTool(mcp.NewTool("find_log"), assistantT.FindLog)
	s.AddTool(mcp.NewTool("assist"), assistantT.Assist)
	s.AddTool(mcp.NewTool("git_status"), GitStatus)
}
