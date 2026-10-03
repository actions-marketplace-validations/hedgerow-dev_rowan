package dev.hedgerow.oracle.llm;

import org.springframework.ai.chat.client.ChatClient;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;

/**
 * V-JA-05 (tnt-ja-ai-llmout-sql-001): the LLM's own free-text answer is
 * treated as a SQL fragment and queried directly.
 */
@Service
public class LlmSqlService {

    private final ChatClient chatClient;
    private final JdbcTemplate jdbcTemplate;

    public LlmSqlService(ChatClient chatClient, JdbcTemplate jdbcTemplate) {
        this.chatClient = chatClient;
        this.jdbcTemplate = jdbcTemplate;
    }

    public List<Map<String, Object>> askAndQuery(String question) {
        String generatedFilter = chatClient.prompt()
                .user("Write a SQL WHERE clause answering: " + question)
                .call()
                .content();
        return jdbcTemplate.queryForList("SELECT * FROM tickets WHERE " + generatedFilter);
    }
}
