import org.springframework.ai.chat.client.ChatClient;
import java.sql.Connection;
import java.sql.Statement;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

// Spring AI completion text executed as SQL (tnt-ja-ai-llmout-sql-001, CWE-89).
@RestController
public class PlaceholderLlmSql {
    private final ChatClient chatClient;
    private final Connection conn;

    public PlaceholderLlmSql(ChatClient.Builder builder, Connection conn) {
        this.chatClient = builder.build();
        this.conn = conn;
    }

    @GetMapping("/ask")
    public void ask(@RequestParam String q) throws Exception {
        String sql = chatClient.prompt().user(q).call().content();
        Statement st = conn.createStatement();
        st.executeQuery(sql);
    }
}
