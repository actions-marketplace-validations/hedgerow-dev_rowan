// anthropic-sdk-go message text used as an outbound request URL (tnt-go-ai-llmout-ssrf-001, CWE-918).
package main

import (
	"context"
	"net/http"

	"github.com/anthropics/anthropic-sdk-go"
)

func fetchSuggested(ctx context.Context, client *anthropic.Client) (*http.Response, error) {
	msg, err := client.Messages.New(ctx, anthropic.MessageNewParams{
		Model:     anthropic.ModelClaude3_7SonnetLatest,
		MaxTokens: 256,
		Messages:  []anthropic.MessageParam{anthropic.NewUserMessage(anthropic.NewTextBlock("Which URL should I fetch?"))},
	})
	if err != nil {
		return nil, err
	}
	target := msg.Content[0].Text
	return http.Get(target)
}
