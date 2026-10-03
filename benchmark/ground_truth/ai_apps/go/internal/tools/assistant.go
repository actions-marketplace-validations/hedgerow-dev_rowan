package tools

import (
	"context"
	"io"
	"net/http"
	"os"

	"github.com/mark3labs/mcp-go/mcp"
	openai "github.com/sashabaranov/go-openai"
)

type assistantTools struct {
	client *openai.Client
}

// G-07 (tnt-go-ai-llmout-ssrf-001): the model proposes a citation URL and
// the app fetches it server-side with no allowlist.
func (t *assistantTools) FactCheck(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	claim := request.GetString("claim", "")
	resp, err := t.client.CreateChatCompletion(ctx, openai.ChatCompletionRequest{
		Model: openai.GPT4,
		Messages: []openai.ChatCompletionMessage{
			{Role: openai.ChatMessageRoleUser, Content: "Give me one URL that supports this claim: " + claim},
		},
	})
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	citationURL := resp.Choices[0].Message.Content
	page, err := http.Get(citationURL)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	defer page.Body.Close()
	body, err := io.ReadAll(page.Body)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	return mcp.NewToolResultText(string(body)), nil
}

// G-08 (tnt-go-ai-llmout-path-001): the model names a "relevant log file"
// and the app reads it from disk with no containment check.
func (t *assistantTools) FindLog(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	question := request.GetString("question", "")
	resp, err := t.client.CreateChatCompletion(ctx, openai.ChatCompletionRequest{
		Model: openai.GPT4,
		Messages: []openai.ChatCompletionMessage{
			{Role: openai.ChatMessageRoleUser, Content: "Which log file under /var/log/oracle-go is relevant to: " + question},
		},
	})
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	logPath := resp.Choices[0].Message.Content
	data, err := os.ReadFile(logPath)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	return mcp.NewToolResultText(string(data)), nil
}

// G-10 (tnt-go-ai-sysprompt-001): the caller's own "persona" argument is
// placed directly into the system message rather than only the user turn.
func (t *assistantTools) Assist(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	persona := request.GetString("persona", "")
	question := request.GetString("question", "")
	resp, err := t.client.CreateChatCompletion(ctx, openai.ChatCompletionRequest{
		Model: openai.GPT4,
		Messages: []openai.ChatCompletionMessage{
			{Role: openai.ChatMessageRoleSystem, Content: persona},
			{Role: openai.ChatMessageRoleUser, Content: question},
		},
	})
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	return mcp.NewToolResultText(resp.Choices[0].Message.Content), nil
}
