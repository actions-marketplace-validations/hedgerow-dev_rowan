import org.springframework.ai.chat.client.ChatClient;
import org.springframework.expression.spel.standard.SpelExpressionParser;

// Spring AI completion text evaluated as a SpEL expression (tnt-ja-ai-llmout-spel-001, CWE-917).
public class LlmoutSpel {
    private final ChatClient chatClient;
    private final SpelExpressionParser parser;

    public LlmoutSpel(ChatClient.Builder builder, SpelExpressionParser parser) {
        this.chatClient = builder.build();
        this.parser = parser;
    }

    public void run(String q) throws Exception {
        String expr = chatClient.prompt().user(q).call().content();
        parser.parseExpression(expr);
    }
}
