// openai-go completion text executed as SQL (tnt-go-ai-llmout-sql-001, CWE-89).
package main

import (
	"context"
	"database/sql"

	"github.com/openai/openai-go"
)

func textToSQL(ctx context.Context, client *openai.Client, db *sql.DB, question string) error {
	resp, err := client.Chat.Completions.New(ctx, openai.ChatCompletionNewParams{
		Messages: []openai.ChatCompletionMessageParamUnion{openai.UserMessage("Write SQL for: " + question)},
		Model:    openai.ChatModelGPT4o,
	})
	if err != nil {
		return err
	}
	query := resp.Choices[0].Message.Content
	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		return err
	}
	return rows.Close()
}
