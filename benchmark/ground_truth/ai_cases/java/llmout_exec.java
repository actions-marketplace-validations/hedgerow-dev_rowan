import org.springframework.ai.chat.client.ChatClient;

// Spring AI completion text executed as an OS command (tnt-ja-ai-llmout-exec-001, CWE-78).
public class LlmoutExec {
    private final ChatClient chatClient;

    public LlmoutExec(ChatClient.Builder builder) {
        this.chatClient = builder.build();
    }

    public void run(String q) throws Exception {
        String cmd = chatClient.prompt().user(q).call().content();
        new ProcessBuilder("sh", "-c", cmd).start();
    }
}
