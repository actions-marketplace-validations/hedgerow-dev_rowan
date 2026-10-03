import org.springframework.ai.chat.client.ChatClient;
import javax.servlet.http.HttpServletResponse;

// Spring AI completion text written into an HTTP response (tnt-ja-ai-llmout-xss-001, CWE-79).
public class LlmoutXss {
    private final ChatClient chatClient;

    public LlmoutXss(ChatClient.Builder builder) {
        this.chatClient = builder.build();
    }

    public void render(String q, HttpServletResponse resp) throws Exception {
        String html = chatClient.prompt().user(q).call().content();
        resp.getWriter().println(html);
    }
}
