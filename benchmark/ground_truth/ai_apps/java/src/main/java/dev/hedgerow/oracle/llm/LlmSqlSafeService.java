package dev.hedgerow.oracle.llm;

import org.springframework.ai.chat.client.ChatClient;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * D-JA-03: looks like LlmSqlService but the LLM output is only ever bound as
 * a parameter of a PreparedStatement, never concatenated into SQL text.
 */
@Service
public class LlmSqlSafeService {

    private final ChatClient chatClient;
    private final JdbcTemplate jdbcTemplate;

    public LlmSqlSafeService(ChatClient chatClient, JdbcTemplate jdbcTemplate) {
        this.chatClient = chatClient;
        this.jdbcTemplate = jdbcTemplate;
    }

    public List<Map<String, Object>> askAndQuery(String question) {
        String subjectGuess = chatClient.prompt()
                .user("In one sentence, guess the ticket subject for: " + question)
                .call()
                .content();
        return jdbcTemplate.query(
                "SELECT * FROM tickets WHERE subject LIKE ?",
                (PreparedStatement ps) -> ps.setString(1, "%" + subjectGuess + "%"),
                this::mapRow
        );
    }

    private Map<String, Object> mapRow(ResultSet rs, int rowNum) throws java.sql.SQLException {
        Map<String, Object> row = new java.util.HashMap<>();
        row.put("id", rs.getInt("id"));
        row.put("subject", rs.getString("subject"));
        return row;
    }
}
