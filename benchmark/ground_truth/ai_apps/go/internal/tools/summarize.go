package tools

import (
	"context"
	"database/sql"
	"os/exec"

	"github.com/mark3labs/mcp-go/mcp"
	openai "github.com/sashabaranov/go-openai"
)

type llmTools struct {
	client *openai.Client
	db     *sql.DB
}

// G-05 (tnt-go-ai-llmout-exec-001): the model's own completion text is
// executed verbatim as a shell command.
func (t *llmTools) Summarize(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	text := request.GetString("text", "")
	resp, err := t.client.CreateChatCompletion(ctx, openai.ChatCompletionRequest{
		Model: openai.GPT4,
		Messages: []openai.ChatCompletionMessage{
			{Role: openai.ChatMessageRoleUser, Content: "Summarize this and suggest one shell command to archive it: " + text},
		},
	})
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	command := resp.Choices[0].Message.Content
	cmd := exec.CommandContext(ctx, "sh", "-c", command)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	return mcp.NewToolResultText(string(out)), nil
}

// G-06 (tnt-go-ai-llmout-sql-001): the model is asked for a SQL filter and
// the completion text is concatenated straight into a query.
func (t *llmTools) SmartSearch(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	question := request.GetString("question", "")
	resp, err := t.client.CreateChatCompletion(ctx, openai.ChatCompletionRequest{
		Model: openai.GPT4,
		Messages: []openai.ChatCompletionMessage{
			{Role: openai.ChatMessageRoleUser, Content: "Write a SQL WHERE clause answering: " + question},
		},
	})
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	filter := resp.Choices[0].Message.Content
	rows, err := t.db.QueryContext(ctx, "SELECT id, subject FROM tickets WHERE "+filter)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	defer rows.Close()
	return mcp.NewToolResultText("ok"), nil
}
