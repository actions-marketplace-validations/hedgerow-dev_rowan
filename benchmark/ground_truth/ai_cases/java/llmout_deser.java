import org.springframework.ai.chat.client.ChatClient;
import org.yaml.snakeyaml.Yaml;

// Spring AI completion text loaded as YAML (tnt-ja-ai-llmout-deser-001, CWE-502).
public class LlmoutDeser {
    private final ChatClient chatClient;

    public LlmoutDeser(ChatClient.Builder builder) {
        this.chatClient = builder.build();
    }

    public void run(String q) throws Exception {
        String body = chatClient.prompt().user(q).call().content();
        new Yaml().load(body);
    }
}
