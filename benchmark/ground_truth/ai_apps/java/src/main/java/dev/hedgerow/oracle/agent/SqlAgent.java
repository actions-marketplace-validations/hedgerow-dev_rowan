package dev.hedgerow.oracle.agent;

import org.springframework.ai.chat.client.ChatClient;
import org.springframework.stereotype.Component;

/**
 * V-JA-13 (tnt-ja-ai-llmout-sql-001, cross-file / JG-13 acceptance target):
 * third hop. Asks the LLM for a SQL statement, then hands the raw answer to
 * QueryRunner (a fourth file) rather than executing it here -- the shape
 * DataAgent's SqlExecuteNode -> SqlExecutor takes in the wild (survey note,
 * BACKLOG.md JG-09/JG-11).
 */
@Component
public class SqlAgent {

    private final ChatClient chatClient;
    private final QueryRunner queryRunner;

    public SqlAgent(ChatClient chatClient, QueryRunner queryRunner) {
        this.chatClient = chatClient;
        this.queryRunner = queryRunner;
    }

    public Object run(String naturalLanguageQuery) {
        String sql = chatClient.prompt()
                .user("Write a single SQL SELECT statement for: " + naturalLanguageQuery)
                .call()
                .content();
        return queryRunner.execute(sql);
    }
}
