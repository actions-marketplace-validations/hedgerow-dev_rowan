// langchaingo completion text run through a shell (tnt-go-ai-llmout-exec-001, CWE-78).
package main

import (
	"context"
	"os/exec"

	"github.com/tmc/langchaingo/llms"
)

func runSuggested(ctx context.Context, llm llms.Model, task string) ([]byte, error) {
	cmd, err := llms.GenerateFromSinglePrompt(ctx, llm, "Give me one shell command to "+task)
	if err != nil {
		return nil, err
	}
	return exec.CommandContext(ctx, "sh", "-c", cmd).CombinedOutput()
}
