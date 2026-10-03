import org.springframework.ai.chat.client.ChatClient;
import java.io.File;

// Spring AI completion text used as a filesystem path (tnt-ja-ai-llmout-path-001, CWE-22).
public class LlmoutPath {
    private final ChatClient chatClient;

    public LlmoutPath(ChatClient.Builder builder) {
        this.chatClient = builder.build();
    }

    public void read(String q) throws Exception {
        String name = chatClient.prompt().user(q).call().content();
        new File(name);
    }
}
