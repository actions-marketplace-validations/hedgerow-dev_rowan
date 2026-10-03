// go-openai completion text used as a file path (tnt-go-ai-llmout-path-001, CWE-22).
package main

import (
	"context"
	"os"

	openai "github.com/sashabaranov/go-openai"
)

func readSuggested(ctx context.Context, client *openai.Client) ([]byte, error) {
	resp, err := client.CreateChatCompletion(ctx, openai.ChatCompletionRequest{
		Model:    openai.GPT4o,
		Messages: []openai.ChatCompletionMessage{{Role: openai.ChatMessageRoleUser, Content: "Which config file should I open?"}},
	})
	if err != nil {
		return nil, err
	}
	path := resp.Choices[0].Message.Content
	return os.ReadFile(path)
}
