package dev.hedgerow.oracle.llm;

import org.springframework.ai.chat.client.ChatClient;
import org.springframework.expression.Expression;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.stereotype.Service;

/**
 * V-JA-09 (tnt-ja-ai-llmout-spel-001): the LLM's answer is parsed and
 * evaluated as a Spring Expression Language expression.
 */
@Service
public class LlmSpelService {

    private final ChatClient chatClient;
    private final SpelExpressionParser parser = new SpelExpressionParser();

    public LlmSpelService(ChatClient chatClient) {
        this.chatClient = chatClient;
    }

    public Object askAndEvaluate(String question) {
        String spelAnswer = chatClient.prompt()
                .user("Write a SpEL expression that computes: " + question)
                .call()
                .content();
        Expression expression = parser.parseExpression(spelAnswer);
        return expression.getValue();
    }
}
