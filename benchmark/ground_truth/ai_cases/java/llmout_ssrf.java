import org.springframework.ai.chat.client.ChatClient;
import org.springframework.web.client.RestTemplate;

// Spring AI completion text used as an outbound request URL (tnt-ja-ai-llmout-ssrf-001, CWE-918).
public class LlmoutSsrf {
    private final ChatClient chatClient;
    private final RestTemplate restTemplate;

    public LlmoutSsrf(ChatClient.Builder builder, RestTemplate restTemplate) {
        this.chatClient = builder.build();
        this.restTemplate = restTemplate;
    }

    public String fetch(String q) throws Exception {
        String url = chatClient.prompt().user(q).call().content();
        return restTemplate.getForObject(url, String.class);
    }
}
