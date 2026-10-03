package dev.hedgerow.oracle.tool;

import org.springframework.ai.tool.annotation.Tool;
import org.springframework.ai.tool.annotation.ToolParam;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;

/**
 * V-JA-03 (tnt-ja-ai-toolsql-001): the model-chosen `filter` clause is
 * string-concatenated straight into a SELECT.
 */
@Component
public class SqlTool {

    private final JdbcTemplate jdbcTemplate;

    public SqlTool(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    @Tool(description = "Look up ticket rows matching a filter expression")
    public List<Map<String, Object>> lookupTickets(@ToolParam(description = "SQL WHERE clause") String filter) {
        return jdbcTemplate.queryForList("SELECT id, subject, status FROM tickets WHERE " + filter);
    }
}
